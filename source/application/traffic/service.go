package traffic

import (
	"context"
	"ntc/source/domain/packet"
	"ntc/source/application/traffic/flow"
	"ntc/source/application/traffic/stats"
)

type Service struct {
	flow *flow.Service
	stats *stats.Service
}

func NewService() *Service {
	flowService := flow.NewService()
	return &Service{
		flow:  flowService,
		stats: stats.NewService(flowService),
	}
}
func (s *Service) Start(ctx context.Context) {
	s.flow.Start(ctx)
	s.stats.Start(ctx)
}

func (s *Service) Consume(p packet.Packet) {
	s.flow.Consume(p)
	s.stats.Consume(p)
}

func (s *Service) Snapshot() stats.GlobalSnapshot {
	return s.stats.Snapshot()
}

func (s *Service) Flows() <-chan flow.Flow {
	return s.flow.Flows()
}