package bpf

import (
	"bytes"
	"context"
	"encoding/binary"

	"client/internal/model"

	"github.com/cilium/ebpf/ringbuf"
)

func ReadEvents(ctx context.Context, rd *ringbuf.Reader) <-chan model.Event {
	out := make(chan model.Event)

	go func() {
		defer close(out)
		defer rd.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			rec, err := rd.Read()
			if err != nil {
				return
			}

			var e model.Event
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
