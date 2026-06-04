package system

import domainsystem "ntc/source/domain/system"

type Collector interface {
	Snapshot() (domainsystem.Snapshot, error)
}

type Service struct {
	collector Collector
}

func NewService(collector Collector) *Service {
	return &Service{collector: collector}
}

func (s *Service) Snapshot() (domainsystem.Snapshot, error) {
	return s.collector.Snapshot()
}
