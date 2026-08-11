package lists

import (
	"context"
	"log"
	"sort"
	"sync"

	"ntc/source/domain/network"
	"ntc/source/domain/packet"
)

type StorageLogger interface {
	StorageError(ctx context.Context, operation string, err error)
}

// ListSnapshot is the complete state managed by ListManager. Keeping it as a
// single value avoids growing the storage interface whenever a list is added.
type ListSnapshot struct {
	Blacklist   []string
	Whitelist   []string
	OnlyLocal   []string
	LocalNetsV4 []string
	LocalNetsV6 []string
}

// ListStore is implemented by a persistence adapter. The application layer
// deliberately does not know whether the snapshot is stored as JSON or in any
// other format.
type ListStore interface {
	LoadLists() (ListSnapshot, error)
	SaveLists(ListSnapshot) error
}

type PersistentListManager struct {
	mu     sync.Mutex
	next   ListManager
	store  ListStore
	logger StorageLogger
}

func NewPersistentListManager(next ListManager, store ListStore, logger StorageLogger) *PersistentListManager {
	manager := &PersistentListManager{next: next, store: store, logger: logger}
	// CIDRs come from the initialized runtime manager, never from JSON. Write
	// that authoritative in-memory state as soon as the decorator is created.
	manager.save()
	return manager
}

// RestorePersistentIPLists restores policy IPs only. Local CIDRs are derived
// from system configuration and are intentionally never restored from JSON.
func RestorePersistentIPLists(next ListManager, store ListStore, logger StorageLogger) {
	snapshot, err := store.LoadLists()
	if err != nil {
		log.Printf("persist: load failed: %v", err)
		logStorageError(logger, "load persistent lists", err)
		return
	}

	for _, ip := range snapshot.Blacklist {
		if _, err := next.AddToBlackListByString(ip); err != nil {
			log.Printf("persist: restore blacklist %s: %v", ip, err)
			logStorageError(logger, "restore blacklist "+ip, err)
		}
	}
	for _, ip := range snapshot.Whitelist {
		if _, err := next.AddToWhiteListByString(ip); err != nil {
			log.Printf("persist: restore whitelist %s: %v", ip, err)
			logStorageError(logger, "restore whitelist "+ip, err)
		}
	}
	for _, ip := range snapshot.OnlyLocal {
		if _, err := next.AddToOnlyLocalByString(ip); err != nil {
			log.Printf("persist: restore onlylocal %s: %v", ip, err)
			logStorageError(logger, "restore onlylocal "+ip, err)
		}
	}
}

func (m *PersistentListManager) AddToBlackListByString(ip string) (packet.IPKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.AddToBlackListByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromBlackListByString(ip string) (packet.IPKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.RemoveFromBlackListByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) GetFromBlackListByString() ([]packet.IPEntry, error) {
	return m.next.GetFromBlackListByString()
}

func (m *PersistentListManager) AddToWhiteListByString(ip string) (packet.IPKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.AddToWhiteListByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromWhiteListByString(ip string) (packet.IPKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.RemoveFromWhiteListByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) GetFromWhiteListByString() ([]packet.IPEntry, error) {
	return m.next.GetFromWhiteListByString()
}

func (m *PersistentListManager) AddToOnlyLocalByString(ip string) (packet.IPKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.AddToOnlyLocalByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromOnlyLocalByString(ip string) (packet.IPKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.RemoveFromOnlyLocalByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) GetFromOnlyLocalByString() ([]packet.IPEntry, error) {
	return m.next.GetFromOnlyLocalByString()
}

func (m *PersistentListManager) AddToLocalNetsV4(cidr string) (network.CIDR, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.AddToLocalNetsV4(cidr)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromLocalNetsV4(cidr string) (network.CIDR, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.RemoveFromLocalNetsV4(cidr)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) GetFromLocalNetsV4() ([]network.CIDREntry, error) {
	return m.next.GetFromLocalNetsV4()
}

func (m *PersistentListManager) AddToLocalNetsV6(cidr string) (network.CIDR, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.AddToLocalNetsV6(cidr)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromLocalNetsV6(cidr string) (network.CIDR, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.next.RemoveFromLocalNetsV6(cidr)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) GetFromLocalNetsV6() ([]network.CIDREntry, error) {
	return m.next.GetFromLocalNetsV6()
}

func (m *PersistentListManager) save() {
	blacklist, err := m.next.GetFromBlackListByString()
	if err != nil {
		log.Printf("persist: read blacklist: %v", err)
		logStorageError(m.logger, "read blacklist", err)
		return
	}
	whitelist, err := m.next.GetFromWhiteListByString()
	if err != nil {
		log.Printf("persist: read whitelist: %v", err)
		logStorageError(m.logger, "read whitelist", err)
		return
	}

	onlylocal, err := m.next.GetFromOnlyLocalByString()
	if err != nil {
		log.Printf("persist: read onlylocal: %v", err)
		logStorageError(m.logger, "read onlylocal", err)
		return
	}
	localNetsV4, err := m.next.GetFromLocalNetsV4()
	if err != nil {
		log.Printf("persist: read LocalNetsV4: %v", err)
		logStorageError(m.logger, "read LocalNetsV4", err)
		return
	}
	localNetsV6, err := m.next.GetFromLocalNetsV6()
	if err != nil {
		log.Printf("persist: read LocalNetsV6: %v", err)
		logStorageError(m.logger, "read LocalNetsV6", err)
		return
	}
	snapshot := ListSnapshot{
		Blacklist:   entriesToIPs(blacklist),
		Whitelist:   entriesToIPs(whitelist),
		OnlyLocal:   entriesToIPs(onlylocal),
		LocalNetsV4: cidrsToStrings(localNetsV4),
		LocalNetsV6: cidrsToStrings(localNetsV6),
	}
	if err := m.store.SaveLists(snapshot); err != nil {
		log.Printf("persist: save failed: %v", err)
		logStorageError(m.logger, "save persistent lists", err)
	}
}

func logStorageError(logger StorageLogger, operation string, err error) {
	if logger == nil || err == nil {
		return
	}
	logger.StorageError(context.Background(), operation, err)
}

func entriesToIPs(entries []packet.IPEntry) []string {
	ips := make([]string, 0, len(entries))
	for _, entry := range entries {
		ips = append(ips, entry.IP)
	}
	sort.Strings(ips)
	return ips
}

func cidrsToStrings(cidrs []network.CIDREntry) []string {
	values := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		values = append(values, cidr.CIDR)
	}
	sort.Strings(values)
	return values
}
