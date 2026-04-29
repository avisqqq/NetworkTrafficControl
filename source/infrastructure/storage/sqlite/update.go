package sqlite

import (
	"fmt"
	"strings"
)

type UpdateQuery struct {
	table  TableDef
	update []UpdateColumnDef
	where  []string
}

type UpdateColumnDef struct {
	column ColumnDef
	value  string
}

func Update(t TableDef, update []UpdateColumnDef, where []string) *UpdateQuery {
	return &UpdateQuery{
		table:  t,
		update: update,
		where:  where,
	}
}

func (q UpdateQuery) Validate() error {
	if len(q.update) == 0 {
		return fmt.Errorf("update query must have at least one column")
	}

	badColumns := make([]string, 0, len(q.update))
	for _, update := range q.update {
		for _, column := range q.table.Columns {
			if update.column.Name == column.Name {
				goto nextUpdate
			}
		}
		badColumns = append(badColumns, update.column.Name)
	nextUpdate:
	}

	if len(badColumns) > 0 {
		return fmt.Errorf("update query has columns that do not exist in the table: %s", strings.Join(badColumns, ", "))
	}

	return nil
}
