package lists

import (
	"log"

	"ntc/source/domain/network"
	"ntc/source/domain/packet"
	"ntc/source/infrastructure/persist"
)

type PersistentListManager struct {
	next  ListManager
	store *persist.Store
}

func NewPersistentListManager(next ListManager, store *persist.Store) *PersistentListManager {
	return &PersistentListManager{next: next, store: store}
}

func RestorePersistentLists(next ListManager, store *persist.Store) {
	if store == nil {
		return
	}

	data, err := store.Load()
	if err != nil {
		log.Printf("persist: load failed: %v", err)
		return
	}

	for _, ip := range data.Blacklist {
		if _, err := next.AddToBlackListByString(ip); err != nil {
			log.Printf("persist: restore blacklist %s: %v", ip, err)
		}
	}
	for _, ip := range data.Whitelist {
		if _, err := next.AddToWhiteListByString(ip); err != nil {
			log.Printf("persist: restore whitelist %s: %v", ip, err)
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
		return
	}
	whitelist, err := m.next.GetFromWhiteListByString()
	if err != nil {
		log.Printf("persist: read whitelist: %v", err)
		return
	}

	blacklistIPs := entriesToIPs(blacklist)
	whitelistsIPs := entriesToIPs(whitelist)
	if err := m.store.SaveLists(blacklistIPs, whitelistsIPs); err != nil {
		log.Printf("persist: save failed: %v", err)
	}
}

func entriesToIPs(entries []packet.IPEntry) []string {
	ips := make([]string, 0, len(entries))
	for _, entry := range entries {
		ips = append(ips, entry.IP)
	}
	return ips
}
