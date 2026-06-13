package packetstream

import (
	"context"
	"ntc/source/domain/packet/core"
)

type Dispatcher struct {
	reader    core.Reader
	consumers []Consumer
}

func NewDispatcher(reader core.Reader, consumers ...Consumer) *Dispatcher {
	return &Dispatcher{
		reader:    reader,
		consumers: consumers,
	}
}

func (d *Dispatcher) Start(ctx context.Context) {
	packets := d.reader.ReadPackets()
	go func(){
		for {
			select {
			case <-ctx.Done():
				return

			case p, ok := <-packets:
				if !ok {
					return
				}
				for _, consumer := range d.consumers {
					consumer.Consume(p)
				}
			}
		}
	}()
}