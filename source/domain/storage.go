package domain

type Storage[T any] interface {
	Save(data T) error
	Get() ([]T, error)
	Update(data T) error
	Delete(data T) error
}
