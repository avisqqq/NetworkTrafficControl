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

// Close releases the underlying connection pool, letting in-flight statements
// finish instead of leaving the handle to the OS at process exit. These
// databases currently run in SQLite's default rollback-journal mode, where
// that is a tidiness win rather than a correctness one -- but it becomes a
// correctness one the moment WAL is enabled, and shutdown is the wrong place
// to discover that.
func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
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
