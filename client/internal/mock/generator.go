package mock

import (
	"context"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"client/internal/model"
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

// protos: TCP=6, UDP=17, ICMP=1
var protos = []uint8{6, 6, 6, 17, 17, 1}

// GenerateEvents produces synthetic packet events for local development.
// Simulates normal traffic (~20 pkt/s) with periodic bursts every 15s.
// Respects blacklist/whitelist from mgr when assigning actions.
func GenerateEvents(ctx context.Context, mgr *Manager) <-chan model.Event {
	out := make(chan model.Event, 64)
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
			case <-ctx.Done():
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
					e := newEvent(rng, mgr, seq.Add(1))
					select {
					case out <- e:
					default:
					}
				}
			}
		}
	}()

	return out
}

func newEvent(rng *rand.Rand, mgr *Manager, seq uint64) model.Event {
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

	var action uint8
	switch {
	case mgr.IsBlacklisted(srcStr):
		action = uint8(model.ActDrop)
	case mgr.IsWhitelisted(srcStr):
		action = uint8(model.ActSkip)
	case proto == 6 && rng.Intn(30) == 0:
		action = uint8(model.ActSSHBypass)
	default:
		action = uint8(model.ActPass)
	}

	return model.Event{
		Ts:         uint64(time.Now().UnixNano()),
		Seq:        seq,
		Src:        src,
		Dst:        dst,
		Proto:      proto,
		Action:     action,
		Ip_Version: ipVersion,
	}
}
