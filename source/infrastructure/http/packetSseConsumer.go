package http

import (
	"encoding/json"
	"time"

	"ntc/source/infrastructure/http/dto"
	"ntc/source/domain/packet"
)

type PacketClock interface {
	FromTs(ts uint64) time.Time
}
type PacketSseConsumer struct {
	sse *SSE
	clock PacketClock
}

func NewPacketSseConsumer(sse *SSE, clock PacketClock) *PacketSseConsumer {
	return &PacketSseConsumer{
		sse: sse,
		clock: clock,
	}
}

func (c *PacketSseConsumer) Consume(p packet.Packet) {
	eventTime := c.clock.FromTs(p.Ts)
	src := packet.IPKey{
		Version: p.IPVersion,
		Address: p.Src,
	}
	dst := packet.IPKey{
		Version: p.IPVersion,
		Address: p.Dst,
	}
	event := dto.PacketEvent{
		Time: eventTime.Format("15:04:05.00"),
		Seq: p.Seq,
		Src: src.ToString(),
		Dst: dst.ToString(),
		Proto: packet.ProtoString(p.Proto),
		Action: packet.ParseAction(p.Action).String(),
		Direction: packet.ParseDirection(p.Direction),
	}

	b, err := json.Marshal(event)
	if err != nil {
		return
	}
	c.sse.Broadcast(b)
}
