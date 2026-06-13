package mock

import (
	"context"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"ntc/source/domain/packet"
)

var ipv4Pool = []string{
	"192.168.1.1", "192.168.1.100", "192.168.1.200",
	"10.0.0.1", "10.0.0.50", "10.0.0.100",
	"172.16.0.1", "172.16.0.50",
	"8.8.8.8", "8.8.4.4", "1.1.1.1",
	"52.0.0.1", "104.0.0.1", "151.101.0.1",
	"185.199.108.1", "140.82.120.1",
	"203.0.113.1", "198.51.100.1",
}

var ipv6Pool = []string{
	"2001:db8::1", "2001:db8::2", "2001:db8::3",
	"fe80::1", "fe80::2",
	"2606:4700:4700::1111", "2001:4860:4860::8888",
}

var protos = []uint8{6, 6, 6, 17, 17, 1}
var tcpPorts = []uint16{22, 80, 443, 3306, 5432, 6379, 8080, 8443}
var udpPorts = []uint16{53, 123, 161, 500, 4500}
var tcpFlagSets = []uint8{0x02, 0x10, 0x12, 0x11, 0x04, 0x18}

type listChecker interface {
	IsBlacklisted(ip string) bool
	IsWhitelisted(ip string) bool
}

type Reader struct {
	ctx context.Context
	mgr listChecker
}

func NewReader(ctx context.Context, mgr listChecker) *Reader {
	return &Reader{ctx: ctx, mgr: mgr}
}

func (r *Reader) ReadPackets() <-chan packet.Packet {
	out := make(chan packet.Packet, 64)
	var seq atomic.Uint64

	go func() {
		defer close(out)

		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		burstTicker := time.NewTicker(15 * time.Second)
		defer burstTicker.Stop()

		inBurst := false
		burstEnd := time.Time{}

		for {
			select {
			case <-r.ctx.Done():
				return
			case <-burstTicker.C:
				inBurst = true
				burstEnd = time.Now().Add(2 * time.Second)
			case t := <-ticker.C:
				if inBurst && t.After(burstEnd) {
					inBurst = false
				}
				count := 1
				if inBurst {
					count = 20
				}
				for i := 0; i < count; i++ {
					p := newPacket(rng, r.mgr, seq.Add(1))
					select {
					case out <- p:
					default:
					}
				}
			}
		}
	}()

	return out
}

func newPacket(rng *rand.Rand, mgr listChecker, seq uint64) packet.Packet {
	useIPv6 := rng.Intn(5) == 0

	var src, dst [16]byte
	var ipVersion uint8
	var srcStr, dstStr string

	if useIPv6 {
		ipVersion = 6
		srcStr = ipv6Pool[rng.Intn(len(ipv6Pool))]
		dstStr = ipv6Pool[rng.Intn(len(ipv6Pool))]
		copy(src[:], net.ParseIP(srcStr).To16())
		copy(dst[:], net.ParseIP(dstStr).To16())
	} else {
		ipVersion = 4
		srcStr = ipv4Pool[rng.Intn(len(ipv4Pool))]
		dstStr = ipv4Pool[rng.Intn(len(ipv4Pool))]
		copy(src[:4], net.ParseIP(srcStr).To4())
		copy(dst[:4], net.ParseIP(dstStr).To4())
	}

	proto := protos[rng.Intn(len(protos))]
	var srcPort, dstPort uint16
	var tcpFlags uint8

	switch proto {
	case 6:
		srcPort = uint16(1024 + rng.Intn(60000))
		dstPort = tcpPorts[rng.Intn(len(tcpPorts))]
		tcpFlags = tcpFlagSets[rng.Intn(len(tcpFlagSets))]
	case 17:
		srcPort = uint16(1024 + rng.Intn(60000))
		dstPort = udpPorts[rng.Intn(len(udpPorts))]
	}

	action := uint8(packet.ActPass)
	switch {
	case mgr.IsBlacklisted(srcStr):
		action = uint8(packet.ActDrop)
	case mgr.IsWhitelisted(srcStr):
		action = uint8(packet.ActSkip)
	case proto == 6 && (srcPort == 22 || dstPort == 22):
		action = uint8(packet.ActSSHBypass)
	}

	return packet.Packet{
		Ts:        uint64(time.Now().UnixNano()),
		Seq:       seq,
		Src:       src,
		Dst:       dst,
		Proto:     proto,
		Action:    action,
		IPVersion: ipVersion,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		PktSize:   uint16(64 + rng.Intn(1436)),
		TCPFlags:  tcpFlags,
		Direction: uint8(rng.Intn(2)),
	}
}
