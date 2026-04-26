package flow

import (
	"sync"
	"time"

	"ntc/internal/model"
)

const (
	idleTimeout  = 30 * time.Second
	flushTimeout = 60 * time.Second
)

// Key uniquely identifies a network flow (5-tuple).
type Key struct {
	Src     [16]byte
	Dst     [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// Record accumulates state for an active flow.
type Record struct {
	FirstSeen time.Time
	LastSeen  time.Time
	PktCount  uint64
	ByteCount uint64
	TCPFlags  uint8
	Direction uint8
	Action    uint8
	IPVersion uint8
}

// Flow is a closed (expired) flow ready for export.
type Flow struct {
	Key
	Record
}

// Tracker aggregates raw packets into flows.
type Tracker struct {
	mu     sync.Mutex
	table  map[Key]*Record
	closed chan Flow
}

func NewTracker() *Tracker {
	return &Tracker{
		table:  make(map[Key]*Record),
		closed: make(chan Flow, 512),
	}
}

// Update registers a packet into the flow table.
func (t *Tracker) Update(e model.Event) {
	key := Key{
		Src:     e.Src,
		Dst:     e.Dst,
		SrcPort: e.SrcPort,
		DstPort: e.DstPort,
		Proto:   e.Proto,
	}

	now := time.Now()

	t.mu.Lock()
	rec, ok := t.table[key]
	if !ok {
		rec = &Record{
			FirstSeen: now,
			Direction: e.Direction,
			Action:    e.Action,
			IPVersion: e.IPVersion,
		}
		t.table[key] = rec
	}
	rec.LastSeen = now
	rec.PktCount++
	rec.ByteCount += uint64(e.PktSize)
	rec.TCPFlags |= e.TCPFlags
	t.mu.Unlock()
}

// Flush expires idle / long-lived / TCP-closed flows into the Flows channel.
func (t *Tracker) Flush() {
	now := time.Now()

	t.mu.Lock()
	for key, rec := range t.table {
		idle      := now.Sub(rec.LastSeen) > idleTimeout
		long      := now.Sub(rec.FirstSeen) > flushTimeout
		tcpClosed := key.Proto == 6 && rec.TCPFlags&0x05 != 0 // FIN(0x01) | RST(0x04)

		if idle || long || tcpClosed {
			select {
			case t.closed <- Flow{Key: key, Record: *rec}:
			default:
			}
			delete(t.table, key)
		}
	}
	t.mu.Unlock()
}

// Flows returns the channel of closed flows for downstream consumers.
func (t *Tracker) Flows() <-chan Flow {
	return t.closed
}

// ActiveCount returns the number of currently tracked flows.
func (t *Tracker) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.table)
}