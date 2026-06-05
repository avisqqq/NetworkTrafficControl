package analytics

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"ntc/source/application/inspection"
	"ntc/source/domain/packet"
)

type Service struct {
	repo          Repository
	localNets     []netip.Prefix
	mu            sync.Mutex
	pending       map[string]PacketStat
	flushInterval time.Duration
	now           func() time.Time
}

func NewService(repo Repository, localCIDRs []string) *Service {
	return &Service{
		repo:          repo,
		localNets:     parsePrefixes(localCIDRs),
		pending:       make(map[string]PacketStat),
		flushInterval: time.Second,
		now:           func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.flush()
				return
			case <-ticker.C:
				s.flush()
			}
		}
	}()
}

func (s *Service) Consume(p packet.Packet) {
	srcKey := packet.IPKey{Version: p.IPVersion, Address: p.Src}
	dstKey := packet.IPKey{Version: p.IPVersion, Address: p.Dst}
	src := srcKey.ToString()
	dst := dstKey.ToString()

	srcLocal := s.isLocal(src)
	dstLocal := s.isLocal(dst)
	if !srcLocal && !dstLocal {
		return
	}

	hostIP := src
	peerIP := dst
	direction := "EGRESS"
	if !srcLocal && dstLocal {
		hostIP = dst
		peerIP = src
		direction = "INGRESS"
	}

	servicePort := p.DstPort
	if direction == "INGRESS" {
		servicePort = p.SrcPort
	}

	stat := PacketStat{
		HostIP:    hostIP,
		PeerIP:    peerIP,
		HostScope: inspection.IPScope(hostIP),
		PeerScope: inspection.IPScope(peerIP),
		Proto:     packet.ProtoString(p.Proto),
		Port:      servicePort,
		Service:   inspection.ServiceName(servicePort),
		Direction: direction,
		Action:    packet.ParseAction(p.Action).String(),
		Packets:   1,
		Bytes:     uint64(p.PktSize),
		SeenAt:    s.now(),
	}

	s.addPending(stat)
}

func (s *Service) Summary(limit int) (Summary, error) {
	s.flush()
	return s.repo.Summary(limit)
}

func (s *Service) HostSummary(ip string, limit int) (Summary, error) {
	s.flush()
	return s.repo.HostSummary(ip, limit)
}

func (s *Service) addPending(stat PacketStat) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := stat.key()
	existing, ok := s.pending[key]
	if !ok {
		s.pending[key] = stat
		return
	}

	existing.Packets += stat.Packets
	existing.Bytes += stat.Bytes
	existing.SeenAt = stat.SeenAt
	s.pending[key] = existing
}

func (s *Service) flush() {
	batch := s.drain()
	for _, stat := range batch {
		_ = s.repo.RecordPacket(stat)
	}
}

func (s *Service) drain() []PacketStat {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pending) == 0 {
		return nil
	}

	batch := make([]PacketStat, 0, len(s.pending))
	for _, stat := range s.pending {
		batch = append(batch, stat)
	}
	s.pending = make(map[string]PacketStat)
	return batch
}

func (p PacketStat) key() string {
	return strings.Join([]string{
		p.HostIP,
		p.PeerIP,
		p.Proto,
		strconv.Itoa(int(p.Port)),
		p.Direction,
		p.Action,
	}, "|")
}

func (s *Service) isLocal(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	for _, prefix := range s.localNets {
		if prefix.Contains(addr) {
			return true
		}
	}

	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

func parsePrefixes(rawCIDRs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(rawCIDRs))
	for _, raw := range rawCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}
