package storage

import (
	"os"
	"path/filepath"

	"ntc/source/infrastructure/storage/gorm/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Open(path string) (*gorm.DB, error) {
	if err := os.Mkdir(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&models.AppLog{}); err != nil {
		return nil, err
	}

	return db, nil
}
