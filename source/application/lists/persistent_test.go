package lists_test

import (
	"reflect"
	"testing"

	"ntc/source/application/lists"
	"ntc/source/application/mock"
)

type memoryStore struct {
	snapshot lists.ListSnapshot
	saves    int
}

func (s *memoryStore) LoadLists() (lists.ListSnapshot, error) {
	return s.snapshot, nil
}

func (s *memoryStore) SaveLists(snapshot lists.ListSnapshot) error {
	s.snapshot = snapshot
	s.saves++
	return nil
}

func TestPersistentManagerSnapshotsRuntimeCIDRsOnStartup(t *testing.T) {
	manager := mock.NewManager([]string{"192.168.1.42/24", "fd00::1234/64"})
	store := &memoryStore{snapshot: lists.ListSnapshot{
		LocalNetsV4: []string{"10.0.0.0/8"},
		LocalNetsV6: []string{"2001:db8::/32"},
	}}
	persistent := lists.NewPersistentListManager(manager, store, nil)

	if store.saves != 1 {
		t.Fatalf("startup save count = %d, want 1", store.saves)
	}
	if !reflect.DeepEqual(store.snapshot.LocalNetsV4, []string{"192.168.1.0/24"}) {
		t.Fatalf("startup IPv4 CIDRs = %v", store.snapshot.LocalNetsV4)
	}
	if !reflect.DeepEqual(store.snapshot.LocalNetsV6, []string{"fd00::/64"}) {
		t.Fatalf("startup IPv6 CIDRs = %v", store.snapshot.LocalNetsV6)
	}

	if _, err := persistent.AddToBlackListByString("203.0.113.10"); err != nil {
		t.Fatalf("add blacklist entry: %v", err)
	}

	if store.saves != 2 {
		t.Fatalf("save count after mutation = %d, want 2", store.saves)
	}
	if !reflect.DeepEqual(store.snapshot.Blacklist, []string{"203.0.113.10"}) {
		t.Fatalf("blacklist = %v", store.snapshot.Blacklist)
	}
	if !reflect.DeepEqual(store.snapshot.LocalNetsV4, []string{"192.168.1.0/24"}) {
		t.Fatalf("IPv4 CIDRs = %v", store.snapshot.LocalNetsV4)
	}
	if !reflect.DeepEqual(store.snapshot.LocalNetsV6, []string{"fd00::/64"}) {
		t.Fatalf("IPv6 CIDRs = %v", store.snapshot.LocalNetsV6)
	}
}

func TestRestorePersistentIPListsDoesNotUsePersistedCIDRs(t *testing.T) {
	store := &memoryStore{snapshot: lists.ListSnapshot{
		Blacklist:   []string{"203.0.113.10"},
		Whitelist:   []string{"203.0.113.11"},
		OnlyLocal:   []string{"203.0.113.12"},
		LocalNetsV4: []string{"192.168.1.0/24"},
		LocalNetsV6: []string{"fd00::/64"},
	}}
	manager := mock.NewManager(nil)

	lists.RestorePersistentIPLists(manager, store, nil)

	blacklist, _ := manager.GetFromBlackListByString()
	whitelist, _ := manager.GetFromWhiteListByString()
	onlyLocal, _ := manager.GetFromOnlyLocalByString()
	v4, _ := manager.GetFromLocalNetsV4()
	v6, _ := manager.GetFromLocalNetsV6()
	if len(blacklist) != 1 || len(whitelist) != 1 || len(onlyLocal) != 1 {
		t.Fatalf("restored IP-list lengths = blacklist:%d whitelist:%d only-local:%d", len(blacklist), len(whitelist), len(onlyLocal))
	}
	if len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("persisted CIDRs leaked into runtime: v4:%v v6:%v", v4, v6)
	}
}
