package mock

import (
	"log"
	"sync"

	"ntc/internal/model"
	"ntc/internal/persist"
)

type Manager struct {
	mu        sync.RWMutex
	blacklist map[string]model.IPKey
	whitelist map[string]model.IPKey
	store     *persist.Store
}

func NewManager(store *persist.Store) *Manager {
	m := &Manager{
		blacklist: make(map[string]model.IPKey),
		whitelist: make(map[string]model.IPKey),
		store:     store,
	}
	if store != nil {
		m.loadFromStore()
	}
	return m
}

func (m *Manager) loadFromStore() {
	bl, wl, err := m.store.Load()
	if err != nil {
		log.Printf("persist: load failed: %v", err)
		return
	}
	for _, ip := range bl {
		if key, err := model.BuildIPKey(ip); err == nil {
			m.blacklist[ip] = key
		}
	}
	for _, ip := range wl {
		if key, err := model.BuildIPKey(ip); err == nil {
			m.whitelist[ip] = key
		}
	}
}

func (m *Manager) save() {
	if m.store == nil {
		return
	}
	m.mu.RLock()
	bl := make([]string, 0, len(m.blacklist))
	for ip := range m.blacklist {
		bl = append(bl, ip)
	}
	wl := make([]string, 0, len(m.whitelist))
	for ip := range m.whitelist {
		wl = append(wl, ip)
	}
	m.mu.RUnlock()
	if err := m.store.Save(bl, wl); err != nil {
		log.Printf("persist: save failed: %v", err)
	}
}

func (m *Manager) AddToBlackList(ip string) (model.IPKey, error) {
	key, err := model.BuildIPKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.blacklist[ip] = key
	m.mu.Unlock()
	m.save()
	return key, nil
}

func (m *Manager) RemoveFromBlackList(ip string) (model.IPKey, error) {
	key, err := model.BuildIPKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.blacklist, ip)
	m.mu.Unlock()
	m.save()
	return key, nil
}

func (m *Manager) GetFromBlackList() ([]model.IPEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return toEntries(m.blacklist), nil
}

func (m *Manager) AddToWhiteList(ip string) (model.IPKey, error) {
	key, err := model.BuildIPKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	m.whitelist[ip] = key
	m.mu.Unlock()
	m.save()
	return key, nil
}

func (m *Manager) RemoveFromWhiteList(ip string) (model.IPKey, error) {
	key, err := model.BuildIPKey(ip)
	if err != nil {
		return key, err
	}
	m.mu.Lock()
	delete(m.whitelist, ip)
	m.mu.Unlock()
	m.save()
	return key, nil
}

func (m *Manager) GetFromWhiteList() ([]model.IPEntry, error) {
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

func toEntries(m map[string]model.IPKey) []model.IPEntry {
	result := make([]model.IPEntry, 0, len(m))
	for ip, key := range m {
		result = append(result, model.IPEntry{IP: ip, Version: key.Version})
	}
	return result
}