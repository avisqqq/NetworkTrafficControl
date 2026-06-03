package logs

import (
	"context"
	domain "ntc/source/domain/logs"
)

type Filter struct {
	Level      domain.Level
	Category   domain.Category
	Event      string
	EntityType string
	EntityId   string
	Search     string
	Limit      int
}

type Repository interface {
	Add(ctx context.Context, log domain.AppLog) (domain.AppLog, error)
	Get(ctx context.Context, filter Filter) ([]domain.AppLog, error)
}
