package stats

import (
	"context"
	"time"

	"ntc/source/domain/packet"
)

type ActiveFlowsProvider interface {
	ActiveCount() int
}

type Service struct {
	tracker *IPTracker
	flows   ActiveFlowsProvider
}

func NewService(flows ActiveFlowsProvider) *Service {
	return &Service{
		tracker: NewIPTracker(),
		flows:   flows,
	}
}

func (s *Service) Consume(p packet.Packet) {
	src := packet.IPKey{
		Version: p.IPVersion,
		Address: p.Src,
	}
	s.tracker.Update(src.ToString(), p)
}

func (s *Service) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.tracker.Evict()
			}
		}
	}()
}

func (s *Service) Snapshot() GlobalSnapshot {
	snap := s.tracker.Snapshot()

	if s.flows != nil {
		snap.ActiveFlows = int64(s.flows.ActiveCount())
	}
	return snap
}
