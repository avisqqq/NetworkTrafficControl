package stats

import "sync/atomic"

// Counters holds monotonically increasing packet/byte totals broken down by
// protocol, direction and action. All fields are accessed via atomic ops so
// they can be updated from the hot packet path without a mutex.
type Counters struct {
	// by protocol
	PktsTCP  atomic.Uint64
	PktsUDP  atomic.Uint64
	PktsICMP atomic.Uint64
	PktsOther atomic.Uint64

	BytesTCP  atomic.Uint64
	BytesUDP  atomic.Uint64
	BytesICMP atomic.Uint64
	BytesOther atomic.Uint64

	// by direction
	PktsIngress atomic.Uint64
	PktsEgress  atomic.Uint64
	BytesIngress atomic.Uint64
	BytesEgress  atomic.Uint64

	// by action
	PktsPass atomic.Uint64
	PktsDrop atomic.Uint64
	PktsSkip atomic.Uint64
	PktsSSH  atomic.Uint64
	BytesPass atomic.Uint64
	BytesDrop atomic.Uint64
}

func (c *Counters) Add(proto, direction, action uint8, pktSize uint16) {
	sz := uint64(pktSize)

	switch proto {
	case 6:
		c.PktsTCP.Add(1); c.BytesTCP.Add(sz)
	case 17:
		c.PktsUDP.Add(1); c.BytesUDP.Add(sz)
	case 1:
		c.PktsICMP.Add(1); c.BytesICMP.Add(sz)
	default:
		c.PktsOther.Add(1); c.BytesOther.Add(sz)
	}

	if direction == 0 {
		c.PktsIngress.Add(1); c.BytesIngress.Add(sz)
	} else {
		c.PktsEgress.Add(1); c.BytesEgress.Add(sz)
	}

	switch action {
	case 0:
		c.PktsPass.Add(1); c.BytesPass.Add(sz)
	case 1:
		c.PktsDrop.Add(1); c.BytesDrop.Add(sz)
	case 2:
		c.PktsSkip.Add(1)
	case 3:
		c.PktsSSH.Add(1)
	}
}

type CountersSnapshot struct {
	PktsTCP   uint64; BytesTCP   uint64
	PktsUDP   uint64; BytesUDP   uint64
	PktsICMP  uint64; BytesICMP  uint64
	PktsOther uint64; BytesOther uint64

	PktsIngress uint64; BytesIngress uint64
	PktsEgress  uint64; BytesEgress  uint64

	PktsPass uint64; BytesPass uint64
	PktsDrop uint64; BytesDrop uint64
	PktsSkip uint64
	PktsSSH  uint64
}

func (c *Counters) Snapshot() CountersSnapshot {
	return CountersSnapshot{
		PktsTCP:  c.PktsTCP.Load(), BytesTCP:  c.BytesTCP.Load(),
		PktsUDP:  c.PktsUDP.Load(), BytesUDP:  c.BytesUDP.Load(),
		PktsICMP: c.PktsICMP.Load(), BytesICMP: c.BytesICMP.Load(),
		PktsOther: c.PktsOther.Load(), BytesOther: c.BytesOther.Load(),

		PktsIngress: c.PktsIngress.Load(), BytesIngress: c.BytesIngress.Load(),
		PktsEgress:  c.PktsEgress.Load(),  BytesEgress:  c.BytesEgress.Load(),

		PktsPass: c.PktsPass.Load(), BytesPass: c.BytesPass.Load(),
		PktsDrop: c.PktsDrop.Load(), BytesDrop: c.BytesDrop.Load(),
		PktsSkip: c.PktsSkip.Load(),
		PktsSSH:  c.PktsSSH.Load(),
	}
}