//go:build linux

package firewall

import (
	"os"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

func newTestFirewall(t *testing.T) *Firewall {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("needs root: test creates a network namespace")
	}

	runtime.LockOSThread()

	original, err := netns.Get()
	if err != nil {
		t.Fatalf("failed to get current network namespace: %v", err)
	}

	created, err := netns.New()
	if err != nil {
		t.Fatalf("failed to create network namespace: %v", err)
	}

	t.Cleanup(func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("failed to restore network namespace: %v", err)
		}

		created.Close()
		original.Close()
		runtime.UnlockOSThread()
	})

	firewall, err := NewFirewall(nftables.WithNetNSFd(int(created)))
	if err != nil {
		t.Fatalf("failed to create firewall: %v", err)
	}

	return firewall
}

func tableExists(t *testing.T, firewall *Firewall) bool {
	t.Helper()

	tables, err := firewall.conn.ListTablesOfFamily(tableFamily)
	if err != nil {
		t.Fatalf("failed to list table: %v", err)
	}

	for _, table := range tables {
		if table.Name == tableName {
			return true
		}
	}

	return false
}

func TestSetupAndTeardown(t *testing.T) {
	firewall := newTestFirewall(t)

	if tableExists(t, firewall) {
		t.Fatal("table exists in a fresh network namespace")
	}

	if err := firewall.Setup(); err != nil {
		t.Fatalf("first Setup failed: %v", err)
	}
	if !tableExists(t, firewall) {
		t.Fatalf("table is missing after Setup")
	}

	if err := firewall.Setup(); err != nil {
		t.Fatalf("second Setup failed: %v", err)
	}
	if got := countRules(t, firewall); got != 1 {
		t.Fatalf("rule count after second Setup = %d, want 1", got)
	}

	if err := firewall.TearDown(); err != nil {
		t.Fatalf("first Teardown failed: %v", err)
	}
	if tableExists(t, firewall) {
		t.Fatal("table still exists after Teardown")
	}

	err := firewall.TearDown()
	t.Logf("second Teardown returned: %v", err)
}

func countRules(t *testing.T, firewall *Firewall) int {
	t.Helper()

	rules, err := firewall.conn.GetRules(firewall.table, firewall.forwardChain)
	if err != nil {
		t.Fatalf("failed to list rules: %v", err)
	}

	return len(rules)
}
