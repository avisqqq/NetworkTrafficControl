package bpf

import (
	"bytes"
	"context"
	"encoding/binary"

	"ntc/internal/model"

	"github.com/cilium/ebpf/ringbuf"
)

// readEvents reads from rd until ctx is cancelled or rd is closed (e.g. by Manager.Close).
func readEvents(ctx context.Context, rd *ringbuf.Reader) <-chan model.Event {
	out := make(chan model.Event)

	go func() {
		defer close(out)

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