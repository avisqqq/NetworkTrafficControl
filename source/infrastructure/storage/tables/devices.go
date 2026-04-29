package tables

import "ntc/source/infrastructure/storage/sqlite"

var DevicesTable = sqlite.TableDef{
	Name: "flows",
	Columns: []sqlite.ColumnDef{
		{Name: "mac", Type: "TEXT", Attributes: "PRIMARY KEY"},
		{Name: "ip", Type: "TEXT", Attributes: "NOT NULL DEFAULT ''"},
		{Name: "ip_version", Type: "INTEGER", Attributes: "NOT NULL DEFAULT 4"},
		{Name: "vendor", Type: "TEXT", Attributes: "NOT NULL DEFAULT ''"},
		{Name: "hostname", Type: "TEXT", Attributes: "NOT NULL DEFAULT ''"},
		{Name: "label", Type: "TEXT", Attributes: "NOT NULL DEFAULT ''"},
		{Name: "known", Type: "INTEGER", Attributes: "NOT NULL DEFAULT 0"},
		{Name: "first_seen", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "last_seen", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "total_bytes", Type: "INTEGER", Attributes: "NOT NULL DEFAULT 0"},
		{Name: "total_pkts", Type: "INTEGER", Attributes: "NOT NULL DEFAULT 0"},
	},
}
