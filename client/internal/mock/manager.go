package mock

import (
	"fmt"
	"net"
	"sync"

	"client/internal/model"
)

type Manager struct {
	mu        sync.RWMutex
	blacklist map[string]model.Ip_Key
	whitelist map[string]model.Ip_Key
}

func NewManager() *Manager {
	return &Manager{
		blacklist: make(map[string]model.Ip_Key),
		whitelist: make(map[string]model.Ip_Key),
	}
}

func (m *Manager) AddToBlackList(ip string) (model.Ip_Key, error) {
	key, err := buildKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.blacklist[ip] = key
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) RemoveFromBlackList(ip string) (model.Ip_Key, error) {
	key, err := buildKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.blacklist, ip)
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) GetFromBlackList() ([]model.IpEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return toEntries(m.blacklist), nil
}

func (m *Manager) AddToWhiteList(ip string) (model.Ip_Key, error) {
	key, err := buildKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.whitelist[ip] = key
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) RemoveFromWhiteList(ip string) (model.Ip_Key, error) {
	key, err := buildKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.whitelist, ip)
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) GetFromWhiteList() ([]model.IpEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return toEntries(m.whitelist), nil
}

func (m *Manager) IsBlacklisted(ip string) bool {
	m.mu.RLock()
	_, ok := m.blacklist[ip]
	m.mu.RUnlock()
	return ok
}

func (m *Manager) IsWhitelisted(ip string) bool {
	m.mu.RLock()
	_, ok := m.whitelist[ip]
	m.mu.RUnlock()
	return ok
}

func (m *Manager) Close() {}

func buildKey(ipStr string) (model.Ip_Key, error) {
	var key model.Ip_Key
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return key, fmt.Errorf("invalid IP: %s", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		key.Version = 4
		copy(key.Address[:4], v4)
		return key, nil
	}
	key.Version = 6
	copy(key.Address[:], ip.To16())
	return key, nil
}

func toEntries(m map[string]model.Ip_Key) []model.IpEntry {
	result := make([]model.IpEntry, 0, len(m))
	for ip, key := range m {
		result = append(result, model.IpEntry{IP: ip, Version: key.Version})
	}
	return result
}
