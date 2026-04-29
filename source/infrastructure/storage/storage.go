package storage

import (
	"context"
	"database/sql"
	"log"
	"ntc/source/infrastructure/storage/sqlite"

	"github.com/jmoiron/sqlx"
)

type Storage[T any] struct {
	connection *sqlx.DB
	table      sqlite.TableDef
	context    context.Context
}

func NewStorage[T any](db *sql.DB, table sqlite.TableDef, context context.Context) *Storage[T] {
	return &Storage[T]{
		connection: sqlx.NewDb(db, "sqlite"),
		table:      table,
		context:    context,
	}
}

func (s *Storage[T]) InsertMany(columns []sqlite.ColumnDef, rows [][]sqlite.ColumnValue) error {
	insertion := sqlite.Insert(s.table, columns, rows)
	if err := insertion.Validate(); err != nil {
		log.Fatalf("storage:InsertMany -> %w", err)
		return nil
	}

	query, arguments := insertion.SQL()
	if _, err := s.connection.ExecContext(s.context, query, arguments); err != nil {
		log.Fatalf("storage:InsertMany -> %w", err)
		return nil
	}

	return nil
}

func (s *Storage[T]) Insert(data []sqlite.ColumnValue) error {
	columns := make([]sqlite.ColumnDef, len(data))

	for i, col := range data {
		columns[i] = col.Column
	}

	insertion := sqlite.Insert(s.table, columns, [][]sqlite.ColumnValue{data})
	if err := insertion.Validate(); err != nil {
		log.Fatalf("storage:Insert -> %w", err)
		return nil
	}

	query, arguments := insertion.SQL()
	if _, err := s.connection.ExecContext(s.context, query, arguments); err != nil {
		log.Fatalf("storage:Insert -> %w", err)
		return nil
	}

	return nil
}

func (s *Storage[T]) GetAll() ([]T, error) {
	var results []T
	selection := sqlite.Select(s.table, s.table.Columns)

	if err := selection.Validate(); err != nil {
		log.Fatalf("storage:GetAll -> %w", err)
		return nil, err
	}

	query, arguments := selection.SQL()
	err := s.connection.SelectContext(s.context, &results, query, arguments)

	if err != nil {
		log.Fatalf("storage:GetAll -> %w", err)
		return nil, err
	}

	return nil, nil
}

func (s *Storage[T]) Get(
	columns []sqlite.ColumnDef,
	where []string,
	orderBy []sqlite.OrderByDef,
	limit *int64,
) ([]T, error) {
	var results []T
	selection := sqlite.Select(s.table, columns)

	if err := selection.Validate(); err != nil {
		log.Fatalf("storage:Get -> %w", err)
		return nil, err
	}

	if where != nil && len(where) > 0 {
		selection.Where(where...)
	}

	if orderBy != nil && len(orderBy) > 0 {
		selection.OrderBy(orderBy)
	}

	if limit != nil && *limit > 0 {
		selection.Limit(*limit)
	}

	query, arguments := selection.SQL()
	err := s.connection.SelectContext(s.context, &results, query, arguments)

	if err != nil {
		log.Fatalf("storage:Get -> %w", err)
		return nil, err
	}

	return results, nil
}

func (s *Storage[T]) Update(data any) error {
	return nil
}

func (s *Storage[T]) Delete(id string) error {
	return nil
}
