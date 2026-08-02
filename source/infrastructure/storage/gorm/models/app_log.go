package models

import "time"

type AppLog struct {
	ID           uint64    `gorm:"primaryKey"`
	CreatedAt    time.Time `gorm:"index:idx_app_logs_created_at,sort:desc;index:idx_app_logs_level_created_at,sort:desc;index:idx_app_logs_category_created_at,sort:desc;index:idx_app_logs_event_created_at,sort:desc;index:idx_app_logs_entity_created_at,sort:desc"`
	Level        string    `gorm:"size:16;not null;index:idx_app_logs_level_created_at"`
	Category     string    `gorm:"size:32;not null;index:idx_app_logs_category_created_at"`
	Event        string    `gorm:"size:128;not null;index:idx_app_logs_event_created_at"`
	Message      string    `gorm:"type:text;not null"`
	EntityType   string    `gorm:"size:64;index:idx_app_logs_entity_created_at"`
	EntityID     string    `gorm:"size:255;index:idx_app_logs_entity_created_at"`
	Actor        string    `gorm:"size:64"`
	Source       string    `gorm:"size:64"`
	MetadataJSON string    `gorm:"type:text"`
}

func (AppLog) TableName() string {
	return "app_log"
}
