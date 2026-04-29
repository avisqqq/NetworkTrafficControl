package sqlite

type TableDef struct {
	Name    string
	Columns []ColumnDef
	Indexes []IndexDef
}

type ColumnDef struct {
	Name       string
	Type       string
	Attributes string
}

type ColumnValue struct {
	Column ColumnDef
	Value  string
}

type IndexColumnDef struct {
	Name      string
	Ascending bool
}

type IndexDef struct {
	Name    string
	Columns []IndexColumnDef
}

func (t TableDef) Column(name string) *ColumnDef {
	for _, c := range t.Columns {
		if c.Name == name {
			return &c
		}
	}

	return nil
}
