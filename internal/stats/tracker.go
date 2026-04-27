package stats

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"ntc/internal/model"
)

// IPTracker maintains per-IP sliding windows, global counters, and flow count.
type IPTracker struct {
	mu         sync.RWMutex
	windows    map[string]*Window
	Global     Counters
	activeFlows atomic.Int64
}

func NewIPTracker() *IPTracker {
	return &IPTracker{
		windows: make(map[string]*Window),
	}
}

// SetActiveFlows is called by the flow tracker on each flush.
func (t *IPTracker) SetActiveFlows(n int) {
	t.activeFlows.Store(int64(n))
}

// Update registers a packet for its source IP and global counters.
func (t *IPTracker) Update(srcIP string, e model.Event) {
	t.Global.Add(e.Proto, e.Direction, e.Action, e.PktSize)

	now := time.Now()

	t.mu.Lock()
	w, ok := t.windows[srcIP]
	if !ok {
		w = newWindow(now)
		t.windows[srcIP] = w
	}
	t.mu.Unlock()

	w.Add(e.PktSize, e.DstPort, e.Src, e.TCPFlags, now)
}

// TopTalker is a single entry in the top-talkers list.
type TopTalker struct {
	IP             string `json:"ip"`
	PktsPerSec     uint64 `json:"pkts_per_sec"`
	BytesPerSec    uint64 `json:"bytes_per_sec"`
	UniqueDstPorts int    `json:"unique_dst_ports"`
	SynCount       uint32 `json:"syn_count"`
	AckCount       uint32 `json:"ack_count"`
}

// GlobalSnapshot aggregates all per-IP windows into a metrics snapshot.
type GlobalSnapshot struct {
	TotalPktsPerSec  uint64
	TotalBytesPerSec uint64
	ActiveIPs        int
	ActiveFlows      int64
	TopTalkers       []TopTalker
	Windows          map[string]WindowSnapshot
	Counters         CountersSnapshot
}

// Snapshot builds a GlobalSnapshot from all current windows.
func (t *IPTracker) Snapshot() GlobalSnapshot {
	t.mu.RLock()
	keys := make([]string, 0, len(t.windows))
	for k := range t.windows {
		keys = append(keys, k)
	}
	t.mu.RUnlock()

	snap := GlobalSnapshot{
		Windows:     make(map[string]WindowSnapshot, len(keys)),
		ActiveFlows: t.activeFlows.Load(),
		Counters:    t.Global.Snapshot(),
	}

	for _, ip := range keys {
		t.mu.RLock()
		w := t.windows[ip]
		t.mu.RUnlock()

		ws := w.Snapshot()
		snap.Windows[ip] = ws
		snap.TotalPktsPerSec += ws.PktsPerSec
		snap.TotalBytesPerSec += ws.BytesPerSec
	}
	snap.ActiveIPs = len(keys)

	// Build top-10 talkers sorted by pkt/s.
	talkers := make([]TopTalker, 0, len(keys))
	for ip, ws := range snap.Windows {
		if ws.PktsPerSec > 0 || ws.BytesPerSec > 0 {
			talkers = append(talkers, TopTalker{
				IP:             ip,
				PktsPerSec:     ws.PktsPerSec,
				BytesPerSec:    ws.BytesPerSec,
				UniqueDstPorts: ws.UniqueDstPorts,
				SynCount:       ws.SynCount,
				AckCount:       ws.AckCount,
			})
		}
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].BytesPerSec > talkers[j].BytesPerSec
	})
	if len(talkers) > 10 {
		talkers = talkers[:10]
	}
	snap.TopTalkers = talkers

	return snap
}

// Evict removes windows that have been idle for more than 2 minutes.
func (t *IPTracker) Evict() {
	cutoff := time.Now().Add(-2 * time.Minute)

	t.mu.Lock()
	defer t.mu.Unlock()

	for ip, w := range t.windows {
		w.mu.Lock()
		idle := w.lastRotate.Before(cutoff)
		w.mu.Unlock()
		if idle {
			delete(t.windows, ip)
		}
	}
}