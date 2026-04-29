package sqlite

import (
	"fmt"
	"strings"
)

func CreateTableSQL(t TableDef) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n", t.Name))

	for i, col := range t.Columns {
		sb.WriteString(fmt.Sprintf("    %s %s %s", col.Name, col.Type, col.Attributes))
		if i < len(t.Columns)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}

	sb.WriteString(");\n")

	for _, idx := range t.Indexes {
		sb.WriteString(fmt.Sprintf(
			"CREATE INDEX IF NOT EXISTS %s ON %s (%s)\n",
			idx.Name,
			t.Name,
			strings.Join(func() []string {
				colNames := make([]string, len(idx.Columns))
				for i, col := range idx.Columns {
					colNames[i] = fmt.Sprintf("%s %s", col.Name, func() string {
						if col.Ascending {
							return "ASC"
						}
						return "DESC"
					}())
				}
				return colNames
			}(), ", "),
		))
	}

	sb.WriteString(");\n")

	return sb.String()
}
