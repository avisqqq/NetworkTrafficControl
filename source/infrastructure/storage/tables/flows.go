package tables

import "ntc/source/infrastructure/storage/sqlite"

var FlowsTable = sqlite.TableDef{
	Name: "flows",
	Columns: []sqlite.ColumnDef{
		{Name: "id", Type: "INTEGER", Attributes: "PRIMARY KEY AUTOINCREMENT"},
		{Name: "src_ip", Type: "TEXT", Attributes: "NOT NULL"},
		{Name: "dst_ip", Type: "TEXT", Attributes: "NOT NULL"},
		{Name: "src_port", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "dst_port", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "proto", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "direction", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "action", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "ip_version", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "bytes", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "pkts", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "started_at", Type: "INTEGER", Attributes: "NOT NULL"},
		{Name: "duration_ms", Type: "INTEGER", Attributes: "NOT NULL"},
	},
	Indexes: []sqlite.IndexDef{
		{
			Name: "idx_flows_src_ip",
			Columns: []sqlite.IndexColumnDef{
				{Name: "scr_ip"},
				{Name: "started_at", Ascending: false},
			},
		},
		{
			Name: "idx_flows_started_at",
			Columns: []sqlite.IndexColumnDef{
				{Name: "started_at", Ascending: false},
			},
		},
	},
}
