package storage

import "context"

type Loader interface {
	Open(path string) error
	Load() error
	HealthCheck(ctx context.Context) error
	Close() error
}
