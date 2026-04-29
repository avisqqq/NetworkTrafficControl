package storage

type Storage[T any] interface {
	Insert(data T) error
	InsertMany(data []T) error
	GetAll() ([]T, error)
	GetOne(id string) (T, error)
	Update(data T) error
	Delete(id string) error
}
