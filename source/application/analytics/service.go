package analytics

import (
	"context"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"ntc/source/application/inspection"
	"ntc/source/domain/packet"
)

type Service struct {
	repo                     Repository
	localNets                []netip.Prefix
	mu                       sync.Mutex
	pending                  map[string]PacketStat
	flushInterval            time.Duration
	consecutiveWriteFailures int
	writesDisabled           bool
	pendingLimitLogged       bool
	now                      func() time.Time
}

const (
	maxConsecutiveFatalSQLiteWriteFailures = 1
	maxPendingStats                        = 10_000
)

func NewService(repo Repository, localCIDRs []string) *Service {
	return &Service{
		repo:          repo,
		localNets:     parsePrefixes(localCIDRs),
		pending:       make(map[string]PacketStat),
		flushInterval: 30 * time.Second,
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
				// Deliberately no flush here. This goroutine cannot be waited
				// on, so flushing would drain the buffer into a transaction
				// that the process may exit before committing -- and it would
				// leave Close with nothing left to write. Close owns the final
				// flush, synchronously.
				return
			case <-ticker.C:
				s.flush()
			}
		}
	}()
}

// Close writes out whatever is still buffered. Start's goroutine also flushes
// when its context is cancelled, but that happens concurrently with shutdown
// and cannot be waited on, so the caller needs a synchronous way to drain the
// buffer before the database goes away. Flushing twice is harmless: the second
// drain finds nothing pending.
func (s *Service) Close() {
	s.flush()
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
	return s.repo.Summary(limit)
}

func (s *Service) HostSummary(ip string, limit int) (Summary, error) {
	return s.repo.HostSummary(ip, limit)
}

func (s *Service) RecordKnownHosts(hosts []KnownHost) error {
	for _, host := range hosts {
		if host.IP == "" {
			continue
		}
		now := s.now()
		if host.FirstSeen.IsZero() {
			host.FirstSeen = now
		}
		host.LastSeen = now
		if err := s.repo.RecordKnownHost(host); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) KnownHosts() ([]KnownHost, error) {
	hosts, err := s.repo.KnownHosts()
	if err != nil {
		return nil, err
	}

	filtered := make([]KnownHost, 0, len(hosts))
	for _, host := range hosts {
		addr, err := netip.ParseAddr(host.IP)
		if err != nil || !addr.Is4() {
			continue
		}
		for _, prefix := range s.localNets {
			if prefix.Addr().Is4() && prefix.Contains(addr) {
				filtered = append(filtered, host)
				break
			}
		}
	}
	return filtered, nil
}

func (s *Service) addPending(stat PacketStat) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writesDisabled {
		return
	}

	s.addPendingLocked(stat)
}

func (s *Service) addPendingLocked(stat PacketStat) {
	key := stat.key()
	existing, ok := s.pending[key]
	if !ok {
		if len(s.pending) >= maxPendingStats {
			if !s.pendingLimitLogged {
				log.Printf("analytics: dropping new packet stats because pending analytics buffer reached %d keys", maxPendingStats)
				s.pendingLimitLogged = true
			}
			return
		}
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
	if len(batch) == 0 {
		return
	}

	if err := s.repo.RecordPackets(batch); err != nil {
		s.handleFlushError(batch, err)
		return
	}

	s.mu.Lock()
	s.consecutiveWriteFailures = 0
	s.mu.Unlock()
}

func (s *Service) drain() []PacketStat {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writesDisabled {
		s.pending = make(map[string]PacketStat)
		return nil
	}

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

func (s *Service) handleFlushError(batch []PacketStat, err error) {
	log.Printf("analytics: failed to persist %d packet stats: %v", len(batch), err)

	s.mu.Lock()
	defer s.mu.Unlock()

	if isFatalSQLiteWriteFailure(err) {
		s.consecutiveWriteFailures++
		if s.consecutiveWriteFailures >= maxConsecutiveFatalSQLiteWriteFailures {
			s.writesDisabled = true
			s.pending = make(map[string]PacketStat)
			log.Printf("analytics: disabling analytics writes after %d fatal SQLite write failure(s): %v", s.consecutiveWriteFailures, err)
			return
		}
	} else if isTemporarySQLiteWriteFailure(err) {
		s.consecutiveWriteFailures = 0
	}

	for _, stat := range batch {
		s.addPendingLocked(stat)
	}
}

func isFatalSQLiteWriteFailure(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "input/output error") ||
		strings.Contains(msg, "disk i/o error")
}

func isTemporarySQLiteWriteFailure(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(strings.ToLower(err.Error()), "database is locked")
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
