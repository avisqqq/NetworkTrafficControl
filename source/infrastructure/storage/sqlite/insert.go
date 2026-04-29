package sqlite

import (
	"fmt"
	"strings"
)

type InsertQuery struct {
	table         TableDef
	insertColumns []ColumnDef
	rows          [][]ColumnValue
}

func Insert(t TableDef, insertColumns []ColumnDef, rows [][]ColumnValue) *InsertQuery {
	return &InsertQuery{
		table:         t,
		insertColumns: insertColumns,
		rows:          rows,
	}
}

func (q *InsertQuery) SQL() (string, []string) {
	columns := make([]string, len(q.insertColumns))
	arguments := make([]string, 0)

	for i, col := range q.insertColumns {
		columns[i] = col.Name
	}

	query := strings.Builder{}
	query.WriteString(
		fmt.Sprintf(
			"INSERT INTO %s VALUES (%s)",
			q.table.Name,
			strings.Join(columns, ", "),
		),
	)

	values := make([]interface{}, len(q.rows))
	for index, row := range q.rows {
		stringValues := make([]string, len(row))

		for index, column := range row {
			stringValues[index] = "?"
			arguments = append(arguments, column.Value)
		}

		rowString := strings.Join(stringValues, ", ")
		values[index] = fmt.Sprintf("(%s)", rowString)
	}

	query.WriteString(fmt.Sprintf(" (%s) VALUES (%s)", columns, values))
	query.WriteString(";")

	return query.String(), arguments
}

func (q *InsertQuery) Validate() error {
	if len(q.insertColumns) == 0 {
		return fmt.Errorf("insert query must have at least one column")
	}

	if len(q.rows) == 0 {
		return fmt.Errorf("insert query must have at least one row")
	}

	if err := validateInsertColumns(q.table, q.insertColumns); err != nil {
		return err
	}

	for _, row := range q.rows {
		if len(row) != len(q.insertColumns) {
			return fmt.Errorf("each row must have the same number of columns as the insert columns")
		}

		badColumns := make([]string, len(row))
		for i, column := range row {
			for _, tableCol := range q.table.Columns {
				if column.Column.Name == tableCol.Name {
					goto nextColumn
				}
			}
			badColumns[i] = column.Column.Name
		nextColumn:
		}

		if len(badColumns) > 0 {
			return fmt.Errorf("insert query has columns that do not exist in the table: %s", strings.Join(badColumns, ", "))
		}
	}

	return nil
}

func validateInsertColumns(table TableDef, insertColumns []ColumnDef) error {
	badColumns := make([]string, len(insertColumns))
	for _, col := range insertColumns {
		for _, tableCol := range table.Columns {
			if col.Name == tableCol.Name {
				goto nextInsertColumn
			}
			badColumns = append(badColumns, col.Name)
		nextInsertColumn:
		}
	}

	if len(badColumns) > 0 {
		return fmt.Errorf("insert query has columns that do not exist in the table: %s", strings.Join(badColumns, ", "))
	}

	return nil
}
