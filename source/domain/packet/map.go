package packet

type Map[T any] interface {
	Add(entry T) error
	Delete(entry T) error
	Get() ([]T, error)
	Close() error
}
