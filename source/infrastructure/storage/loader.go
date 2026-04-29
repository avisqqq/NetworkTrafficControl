package storage

import (
	"context"
	"database/sql"
	"log"
	"ntc/source/domain/storage"
	"ntc/source/infrastructure/storage/sqlite"
	"ntc/source/infrastructure/storage/tables"
	"os"
	"path/filepath"
	"time"
)

type Loader struct {
	connection *sql.DB
}

func NewLoader() storage.Loader {
	return &Loader{}
}

func (l *Loader) Open(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("loader:OpenConnection mkdir %s -> %w", filepath.Dir(path), err)
		return nil
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		log.Fatalf("loader:OpenConnection %s -> %w", path, err)
		return nil
	}
	l.connection = conn

	return nil
}

func (l *Loader) Load() error {
	if _, err := l.connection.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous  = NORMAL;
		PRAGMA foreign_keys = ON;
	`); err != nil {
		log.Fatalf("loader:LoadConfigure -> %w", err)
		return nil
	}

	l.connection.SetMaxOpenConns(1)
	l.connection.SetMaxIdleConns(1)
	l.connection.SetConnMaxLifetime(0)

	err := l.Migrate()
	if err != nil {
		return err
	}

	return nil
}

func (l *Loader) Migrate() error {
	tablesSQL := []string{
		sqlite.CreateTableSQL(tables.DevicesTable),
		sqlite.CreateTableSQL(tables.FlowsTable),
	}

	for _, query := range tablesSQL {
		if _, err := l.connection.Exec(query); err != nil {
			log.Fatalf("loader:Migrate -> %w", err)
			return nil
		}
	}

	return nil
}

func (l *Loader) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return l.connection.PingContext(ctx)
}

func (l *Loader) Close() error {
	if l.connection != nil {
		return l.connection.Close()
	}
	return nil
}
