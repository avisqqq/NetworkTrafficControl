package stats

import (
	"sync"
	"time"
)

const buckets = 60 // 60 × 1s = 60s sliding window

type bucket struct {
	pkts  uint32
	bytes uint32
}

// Window is a per-IP sliding window — 60 buckets of 1 second each.
type Window struct {
	mu         sync.Mutex
	b          [buckets]bucket
	cursor     int
	lastRotate time.Time
	lastReset  time.Time // tracks when unique sets were last cleared

	UniqueDstPorts map[uint16]struct{}
	UniqueSrcIPs   map[[16]byte]struct{}
	SynCount       uint32
	AckCount       uint32
}

func newWindow(now time.Time) *Window {
	return &Window{
		lastRotate:     now,
		lastReset:      now,
		UniqueDstPorts: make(map[uint16]struct{}),
		UniqueSrcIPs:   make(map[[16]byte]struct{}),
	}
}

func (w *Window) rotate(now time.Time) {
	elapsed := int(now.Sub(w.lastRotate).Seconds())
	if elapsed <= 0 {
		return
	}
	if elapsed > buckets {
		elapsed = buckets
	}
	for i := 0; i < elapsed; i++ {
		w.cursor = (w.cursor + 1) % buckets
		w.b[w.cursor] = bucket{}
	}
	w.lastRotate = now

	// Reset unique sets every full window cycle (60s) regardless of traffic.
	// Without this, ports from a port scan would linger as long as the IP
	// sends any traffic at all.
	if now.Sub(w.lastReset) >= buckets*time.Second {
		w.UniqueDstPorts = make(map[uint16]struct{})
		w.UniqueSrcIPs = make(map[[16]byte]struct{})
		w.SynCount = 0
		w.AckCount = 0
		w.lastReset = now
	}
}

func (w *Window) Add(pktSize uint16, dstPort uint16, srcIP [16]byte, tcpFlags uint8, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.rotate(now)
	w.b[w.cursor].pkts++
	w.b[w.cursor].bytes += uint32(pktSize)
	w.UniqueDstPorts[dstPort] = struct{}{}
	w.UniqueSrcIPs[srcIP] = struct{}{}
	if tcpFlags&0x02 != 0 { // SYN
		w.SynCount++
	}
	if tcpFlags&0x10 != 0 { // ACK
		w.AckCount++
	}
}

// Snapshot returns aggregate values over the full 60s window.
func (w *Window) Snapshot() WindowSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.rotate(time.Now())

	var totalPkts, totalBytes uint64
	for _, b := range w.b {
		totalPkts += uint64(b.pkts)
		totalBytes += uint64(b.bytes)
	}

	return WindowSnapshot{
		PktsPerSec:      totalPkts / buckets,
		BytesPerSec:     totalBytes / buckets,
		UniqueDstPorts:  len(w.UniqueDstPorts),
		UniqueSrcIPs:    len(w.UniqueSrcIPs),
		SynCount:        w.SynCount,
		AckCount:        w.AckCount,
	}
}

type WindowSnapshot struct {
	PktsPerSec     uint64
	BytesPerSec    uint64
	UniqueDstPorts int
	UniqueSrcIPs   int
	SynCount       uint32
	AckCount       uint32
}