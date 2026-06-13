package storage

import (
	"os"
	"path/filepath"

	"ntc/source/infrastructure/storage/gorm/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Open(path string) (*gorm.DB, error) {
	return open(path, &models.AppLog{})
}

func OpenAnalytics(path string) (*gorm.DB, error) {
	return open(path,
		&models.AnalyticsHost{},
		&models.AnalyticsIP{},
		&models.AnalyticsIPEnrichment{},
		&models.AnalyticsService{},
		&models.HostPeerCounter{},
		&models.HostCountryCounter{},
		&models.HostServiceCounter{},
		&models.BlockedPeerCounter{},
	)
}

func open(path string, migrate ...any) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(migrate...); err != nil {
		return nil, err
	}

	return db, nil
}
