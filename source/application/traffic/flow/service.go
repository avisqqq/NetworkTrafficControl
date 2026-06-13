package flow

import (
	"context"
	"time"

	"ntc/source/domain/packet"
)

type Service struct {
	tracker *Tracker
}

func NewService() *Service {
	return &Service{
		tracker: NewTracker(),
	}
}

func (s *Service) Consume(packet packet.Packet) {
	s.tracker.Update(packet)
}

func (s *Service) Start(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)

	go func(){
		defer ticker.Stop()

		for{
			select{
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.tracker.Flush()
			}
		}
	}()
}

func (s *Service) ActiveCount() int {
	return s.tracker.ActiveCount()
}

func (s *Service) Flows() <-chan Flow {
	return s.tracker.Flows()
}