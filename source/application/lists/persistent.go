package lists

import (
	"context"
	"log"

	"ntc/source/domain/network"
	"ntc/source/domain/packet"
	"ntc/source/infrastructure/persist"
)

type StorageLogger interface {
	StorageError(ctx context.Context, operation string, err error)
}

type PersistentListManager struct {
	next   ListManager
	store  *persist.Store
	logger StorageLogger
}

func NewPersistentListManager(next ListManager, store *persist.Store, logger StorageLogger) *PersistentListManager {
	return &PersistentListManager{next: next, store: store, logger: logger}
}

func RestorePersistentLists(next ListManager, store *persist.Store, logger StorageLogger) {
	if store == nil {
		return
	}

	data, err := store.Load()
	if err != nil {
		log.Printf("persist: load failed: %v", err)
		logStorageError(logger, "load persistent lists", err)
		return
	}

	for _, ip := range data.Blacklist {
		if _, err := next.AddToBlackListByString(ip); err != nil {
			log.Printf("persist: restore blacklist %s: %v", ip, err)
			logStorageError(logger, "restore blacklist "+ip, err)
		}
	}
	for _, ip := range data.Whitelist {
		if _, err := next.AddToWhiteListByString(ip); err != nil {
			log.Printf("persist: restore whitelist %s: %v", ip, err)
			logStorageError(logger, "restore whitelist "+ip, err)
		}
	}
}

func (m *PersistentListManager) AddToBlackListByString(ip string) (packet.IPKey, error) {
	key, err := m.next.AddToBlackListByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromBlackListByString(ip string) (packet.IPKey, error) {
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
	key, err := m.next.AddToWhiteListByString(ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *PersistentListManager) RemoveFromWhiteListByString(ip string) (packet.IPKey, error) {
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
	return m.next.AddToOnlyLocalByString(ip)
}

func (m *PersistentListManager) RemoveFromOnlyLocalByString(ip string) (packet.IPKey, error) {
	return m.next.RemoveFromOnlyLocalByString(ip)
}

func (m *PersistentListManager) GetFromOnlyLocalByString() ([]packet.IPEntry, error) {
	return m.next.GetFromOnlyLocalByString()
}

func (m *PersistentListManager) AddToLocalNetsV4(cidr string) (network.CIDR, error) {
	return m.next.AddToLocalNetsV4(cidr)
}

func (m *PersistentListManager) RemoveFromLocalNetsV4(cidr string) (network.CIDR, error) {
	return m.next.RemoveFromLocalNetsV4(cidr)
}

func (m *PersistentListManager) GetFromLocalNetsV4() ([]network.CIDREntry, error) {
	return m.next.GetFromLocalNetsV4()
}

func (m *PersistentListManager) AddToLocalNetsV6(cidr string) (network.CIDR, error) {
	return m.next.AddToLocalNetsV6(cidr)
}

func (m *PersistentListManager) RemoveFromLocalNetsV6(cidr string) (network.CIDR, error) {
	return m.next.RemoveFromLocalNetsV6(cidr)
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

	blacklistIPs := entriesToIPs(blacklist)
	whitelistsIPs := entriesToIPs(whitelist)
	if err := m.store.SaveLists(blacklistIPs, whitelistsIPs); err != nil {
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
	return ips
}
