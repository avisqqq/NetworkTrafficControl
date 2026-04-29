package sqlite

import (
	"fmt"
	"strings"
)

type SelectQuery struct {
	table   TableDef
	columns []ColumnDef
	where   []string
	orderBy *[]OrderByDef
	limit   *int64
}

type OrderByDef struct {
	column    ColumnDef
	Ascending bool
}

func (q *SelectQuery) SQL() (string, []string) {
	arguments := make([]string, 0)
	stringColumns := make([]string, len(q.columns))
	for i, col := range q.columns {
		stringColumns[i] = col.Name
	}

	cols := strings.Join(stringColumns, ", ")
	query := strings.Builder{}

	query.WriteString("SELECT ?")
	arguments = append(arguments, cols)

	query.WriteString(" FROM ")
	query.WriteString(q.table.Name)

	if q.where != nil && len(q.where) > 0 {
		query.WriteString(" WHERE ?")
		arguments = append(arguments, strings.Join(q.where, " AND "))
	}

	if q.orderBy != nil {
		for _, orderBy := range *q.orderBy {
			query.WriteString(" ORDER BY ")
			arguments = append(arguments, orderBy.column.Name)
		}
	}

	if q.limit != nil && *q.limit > 0 {
		query.WriteString(" LIMIT ?")
		arguments = append(arguments, string(rune(*q.limit)))
	}

	query.WriteString(";")

	return query.String(), arguments
}

func Select(t TableDef, cols []ColumnDef) *SelectQuery {
	return &SelectQuery{
		table:   t,
		columns: cols,
	}
}

func (q *SelectQuery) Where(expr ...string) *SelectQuery {
	for _, e := range expr {
		q.where = append(q.where, e)
	}

	return q
}

func (q *SelectQuery) OrderBy(columns []OrderByDef) *SelectQuery {
	q.orderBy = &columns
	return q
}

func (q *SelectQuery) Limit(n int64) *SelectQuery {
	q.limit = &n
	return q
}

func (q *SelectQuery) Validate() error {
	if len(q.columns) == 0 {
		return fmt.Errorf("select query must have at least one column")
	}

	badColumns := make([]string, 0)
	for _, col := range q.columns {
		for _, tableCol := range q.table.Columns {
			if col.Name == tableCol.Name {
				goto nextColumn
			}
		}
		badColumns = append(badColumns, col.Name)
	nextColumn:
	}

	if len(badColumns) > 0 {
		return fmt.Errorf("select query has columns that do not exist in the table: %s", strings.Join(badColumns, ", "))
	}

	return nil
}
