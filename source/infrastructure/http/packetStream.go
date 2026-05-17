package http

import (
	"context"
	"encoding/json"

	"ntc/source/domain/packet"
	"ntc/source/domain/packet/core"
)

func StreamPackets(ctx context.Context, reader core.Reader, sse *SSE) {
	packets := reader.ReadPackets()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case p, ok := <-packets:
				if !ok {
					return
				}
				src := packet.IPKey{
					Version: p.IPVersion,
					Address: p.Src,
				}

				dst := packet.IPKey{
					Version: p.IPVersion,
					Address: p.Dst,
				}

				event := PacketEvent{
					Seq:       p.Seq,
					Src:       src.ToString(),
					Dst:       dst.ToString(),
					Proto:     p.Proto,
					Action:    p.Action,
					Direction: p.Direction,
				}

				b, err := json.Marshal(event)
				if err != nil {
					continue
				}

				sse.Broadcast(b)
			}
		}
	}()
}
