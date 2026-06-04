package logs

import (
	"context"
	domain "ntc/source/domain/logs"
	"time"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Add(ctx context.Context, log domain.AppLog) (domain.AppLog, error) {
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	return s.repo.Add(ctx, log)
}

func (s *Service) Get(ctx context.Context, filter Filter) ([]domain.AppLog, error) {
	return s.repo.Get(ctx, filter)
}

func (s *Service) Info(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelInfo,
		Category: category,
		Event:    event,
		Message:  message,
	})
}

func (s *Service) Warn(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelWarn,
		Category: category,
		Event:    event,
		Message:  message,
	})
}
func (s *Service) Error(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelError,
		Category: category,
		Event:    event,
		Message:  message,
	})
}

func (s *Service) ServiceStarted(ctx context.Context) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelInfo,
		Category: domain.CategorySystem,
		Event:    domain.EventServiceStarted,
		Message:  "service started",
		Actor:    domain.ActorSystem,
		Source:   domain.SourceStartup,
	})
}

func (s *Service) ConfigLoaded(ctx context.Context) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelInfo,
		Category: domain.CategorySystem,
		Event:    domain.EventConfigLoaded,
		Message:  "config loaded",
		Actor:    domain.ActorSystem,
		Source:   domain.SourceStartup,
	})
}

func (s *Service) ListActionSucceeded(ctx context.Context, list, action, value string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelInfo,
		Category:   domain.CategoryList,
		Event:      listEvent(list, action),
		Message:    action + " " + list + ": " + value,
		EntityType: entityTypeForList(list),
		EntityID:   value,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceListManager,
	})
}

func (s *Service) ListActionFailed(ctx context.Context, list, action, value string, err error) {
	if err == nil {
		return
	}

	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelWarn,
		Category:   domain.CategoryList,
		Event:      listEvent(list, action),
		Message:    action + " " + list + " failed: " + err.Error(),
		EntityType: entityTypeForList(list),
		EntityID:   value,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceListManager,
	})
}

func (s *Service) StorageError(ctx context.Context, operation string, err error) {
	if err == nil {
		return
	}

	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelError,
		Category: domain.CategoryStorage,
		Event:    domain.EventStorageError,
		Message:  operation + ": " + err.Error(),
		Actor:    domain.ActorSystem,
		Source:   domain.SourceStorage,
	})
}

func (s *Service) APIError(ctx context.Context, method, path string, status int, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelWarn,
		Category: domain.CategorySystem,
		Event:    domain.EventAPIError,
		Message:  method + " " + path + ": " + message,
		Actor:    domain.ActorAPI,
		Source:   domain.SourceHTTP,
	})
}

func listEvent(list, action string) domain.Event {
	switch list {
	case "whitelist":
		if action == "add" {
			return domain.EventWhitelistAdded
		}
		return domain.EventWhitelistRemoved
	case "blacklist":
		if action == "add" {
			return domain.EventBlacklistAdded
		}
		return domain.EventBlacklistRemoved
	case "onlylocal":
		if action == "add" {
			return domain.EventOnlyLocalAdded
		}
		return domain.EventOnlyLocalRemoved
	case "localnet_v4", "localnet_v6":
		if action == "add" {
			return domain.EventLocalNetAdded
		}
		return domain.EventLocalNetRemoved
	default:
		return domain.EventAPIError
	}
}

func entityTypeForList(list string) domain.EntityType {
	switch list {
	case "localnet_v4", "localnet_v6":
		return domain.EntityTypeCIDR
	default:
		return domain.EntityTypeIP
	}
}
