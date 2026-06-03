package logs

import (
	"context"
	domain "ntc/source/domain/logs"
	"time"
)

type Service struct {
	repo Repository
}

func (s *Service) NewSerice(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Add(ctx context.Context, log domain.AppLog) (domain.AppLog, error) {
	if log.CreateAt.IsZero() {
		log.CreateAt = time.Now().UTC()
	}
	return s.repo.Add(ctx, log)
}

func (s *Service) Info(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{Level: domain.LevelInfo, Category: category, Event: event, Message: message})
}

func (s *Service) Warn(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{Level: domain.LevelWarn, Category: category, Event: event, Message: message})
}
func (s *Service) Error(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{Level: domain.LevelError, Category: category, Event: event, Message: message})
}

func (s *Service) Get(ctx context.Context, filter Filter) ([]domain.AppLog, error) {
	return s.repo.Get(ctx, filter)
}
