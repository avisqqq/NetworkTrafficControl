package repositories

import (
	"context"
	"ntc/source/infrastructure/storage/gorm/models"
	"strings"

	app "ntc/source/application/logs"
	domain "ntc/source/domain/logs"

	"gorm.io/gorm"
)

type AppLogRepository struct {
	db *gorm.DB
}

func NewAppLogRepository(db *gorm.DB) *AppLogRepository {
	return &AppLogRepository{db: db}
}

func (r *AppLogRepository) Add(ctx context.Context, log domain.AppLog) (domain.AppLog, error) {
	row := toModel(log)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return domain.AppLog{}, err
	}
	return toDomain(row), nil
}

func (r *AppLogRepository) Get(ctx context.Context, filter app.Filter) ([]domain.AppLog, error) {
	query := r.db.WithContext(ctx).Model(&models.AppLog{})
	if filter.Level != "" {
		query = query.Where("level = ?", string(filter.Level))
	}
	if filter.Category != "" {
		query = query.Where("category = ?", string(filter.Category))
	}
	if filter.Event != "" {
		query = query.Where("event = ?", filter.Event)
	}
	if filter.EntityType != "" {
		query = query.Where("entity_type = ?", filter.EntityType)
	}
	if filter.EntityID != "" {
		query = query.Where("entity_id = ?", filter.EntityID)
	}

	if strings.TrimSpace(filter.Search) != "" {
		search := "%" + strings.TrimSpace(filter.Search) + "%"
		query = query.Where("message LIKE ? OR metadata_json LIKE ?", search, search)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	var rows []models.AppLog
	if err := query.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}

	logs := make([]domain.AppLog, 0, len(rows))
	for _, row := range rows {
		logs = append(logs, toDomain(row))
	}

	return logs, nil
}

func toModel(log domain.AppLog) models.AppLog {
	return models.AppLog{
		ID:           log.ID,
		CreatedAt:    log.CreatedAt,
		Level:        string(log.Level),
		Category:     string(log.Category),
		Event:        string(log.Event),
		Message:      log.Message,
		EntityType:   string(log.EntityType),
		EntityID:     log.EntityID,
		Actor:        string(log.Actor),
		Source:       string(log.Source),
		MetadataJSON: log.MetadataJSON,
	}
}

func toDomain(row models.AppLog) domain.AppLog {
	return domain.AppLog{
		ID:           row.ID,
		CreatedAt:    row.CreatedAt,
		Level:        domain.Level(row.Level),
		Category:     domain.Category(row.Category),
		Event:        domain.Event(row.Event),
		Message:      row.Message,
		EntityType:   domain.EntityType(row.EntityType),
		EntityID:     row.EntityID,
		Actor:        domain.Actor(row.Actor),
		Source:       domain.Source(row.Source),
		MetadataJSON: row.MetadataJSON,
	}
}
