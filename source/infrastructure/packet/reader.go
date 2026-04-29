package packet

import (
	"bytes"
	"context"
	"encoding/binary"
	"ntc/source/domain/packet"
	"ntc/source/domain/packet/core"

	"github.com/cilium/ebpf/ringbuf"
)

type Reader struct {
	context context.Context
	reader  *ringbuf.Reader
}

func NewReader(ctx context.Context, reader *ringbuf.Reader) core.Reader {
	return &Reader{
		context: ctx,
		reader:  reader,
	}
}

func (r *Reader) ReadPackets() <-chan packet.Packet {
	out := make(chan packet.Packet)

	go func() {
		defer close(out)

		for {
			select {
			case <-r.context.Done():
				return
			default:
			}

			rec, err := r.reader.Read()
			if err != nil {
				return
			}

			var e packet.Packet
			if err := binary.Read(
				bytes.NewReader(rec.RawSample),
				binary.LittleEndian,
				&e,
			); err != nil {
				continue
			}

			out <- e
		}
	}()

	return out
}
