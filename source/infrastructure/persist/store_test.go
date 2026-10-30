package persist_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ntc/source/application/lists"
	"ntc/source/infrastructure/persist"
)

func TestStoreWritesStableCIDRKeysAndPreservesMockMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lists.json")
	store, err := persist.New(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.SaveMockMode(true); err != nil {
		t.Fatalf("save mock mode: %v", err)
	}
	if err := store.SaveLists(lists.ListSnapshot{
		LocalNetsV4: []string{"192.168.1.0/24"},
		LocalNetsV6: []string{"fd00::/64"},
	}); err != nil {
		t.Fatalf("save lists: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	jsonText := string(data)
	for _, key := range []string{"\"local_nets_v4\"", "\"local_nets_v6\"", "\"mock_mode\": true"} {
		if !strings.Contains(jsonText, key) {
			t.Fatalf("JSON does not contain %s:\n%s", key, jsonText)
		}
	}
}

func TestStoreRoundTripsPolicies(t *testing.T) {
	store, err := persist.New(filepath.Join(t.TempDir(), "lists.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	want := []lists.PolicyEntry{{IP: "2001:db8::1", Port: 53, Protocol: "UDP", Direction: "INGRESS"}}
	if err := store.SaveLists(lists.ListSnapshot{Policies: want}); err != nil {
		t.Fatalf("save lists: %v", err)
	}

	snapshot, err := store.LoadLists()
	if err != nil {
		t.Fatalf("load lists: %v", err)
	}
	if !reflect.DeepEqual(snapshot.Policies, want) {
		t.Fatalf("policies = %v, want %v", snapshot.Policies, want)
	}
}
