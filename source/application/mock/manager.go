package mock

import (
	"sync"

	"ntc/source/domain/network"
	"ntc/source/domain/packet"
)

type Manager struct {
	mu        sync.RWMutex
	blacklist map[string]packet.IPKey
	whitelist map[string]packet.IPKey
	onlylocal map[string]packet.IPKey
	localV4   map[string]network.CIDR
	localV6   map[string]network.CIDR
}

func NewManager(localCIDRs []string) *Manager {
	m := &Manager{
		blacklist: make(map[string]packet.IPKey),
		whitelist: make(map[string]packet.IPKey),
		onlylocal: make(map[string]packet.IPKey),
		localV4:   make(map[string]network.CIDR),
		localV6:   make(map[string]network.CIDR),
	}
	for _, raw := range localCIDRs {
		cidr, err := network.CIDRFromString(raw)
		if err != nil {
			continue
		}
		if cidr.Version == 4 {
			m.localV4[cidr.ToString()] = cidr
		} else {
			m.localV6[cidr.ToString()] = cidr
		}
	}
	return m
}

func (m *Manager) AddToBlackListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.blacklist[key.ToString()] = key
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) RemoveFromBlackListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.blacklist, key.ToString())
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) GetFromBlackListByString() ([]packet.IPEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ipEntries(m.blacklist), nil
}

func (m *Manager) AddToWhiteListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.whitelist[key.ToString()] = key
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) RemoveFromWhiteListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.whitelist, key.ToString())
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) GetFromWhiteListByString() ([]packet.IPEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ipEntries(m.whitelist), nil
}

func (m *Manager) AddToOnlyLocalByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.onlylocal[key.ToString()] = key
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) RemoveFromOnlyLocalByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.onlylocal, key.ToString())
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) GetFromOnlyLocalByString() ([]packet.IPEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ipEntries(m.onlylocal), nil
}

func (m *Manager) AddToLocalNetsV4(raw string) (network.CIDR, error) {
	cidr, err := network.CIDRFromString(raw)
	if err != nil {
		return cidr, err
	}
	m.mu.Lock()
	m.localV4[cidr.ToString()] = cidr
	m.mu.Unlock()
	return cidr, nil
}

func (m *Manager) RemoveFromLocalNetsV4(raw string) (network.CIDR, error) {
	cidr, err := network.CIDRFromString(raw)
	if err != nil {
		return cidr, err
	}
	m.mu.Lock()
	delete(m.localV4, cidr.ToString())
	m.mu.Unlock()
	return cidr, nil
}

func (m *Manager) GetFromLocalNetsV4() ([]network.CIDREntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cidrEntries(m.localV4), nil
}

func (m *Manager) AddToLocalNetsV6(raw string) (network.CIDR, error) {
	cidr, err := network.CIDRFromString(raw)
	if err != nil {
		return cidr, err
	}
	m.mu.Lock()
	m.localV6[cidr.ToString()] = cidr
	m.mu.Unlock()
	return cidr, nil
}

func (m *Manager) RemoveFromLocalNetsV6(raw string) (network.CIDR, error) {
	cidr, err := network.CIDRFromString(raw)
	if err != nil {
		return cidr, err
	}
	m.mu.Lock()
	delete(m.localV6, cidr.ToString())
	m.mu.Unlock()
	return cidr, nil
}

func (m *Manager) GetFromLocalNetsV6() ([]network.CIDREntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cidrEntries(m.localV6), nil
}

func (m *Manager) IsBlacklisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blacklist[ip]
	return ok
}

func (m *Manager) IsWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.whitelist[ip]
	return ok
}

func ipEntries(items map[string]packet.IPKey) []packet.IPEntry {
	result := make([]packet.IPEntry, 0, len(items))
	for _, key := range items {
		result = append(result, packet.IPEntry{
			Version: key.Version,
			IP:      key.ToString(),
		})
	}
	return result
}

func cidrEntries(items map[string]network.CIDR) []network.CIDREntry {
	result := make([]network.CIDREntry, 0, len(items))
	for _, cidr := range items {
		result = append(result, cidr.ToEntry())
	}
	return result
}
