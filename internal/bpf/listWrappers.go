package bpf

import (
	"ntc/internal/model"
)

func (m *Manager) AddToBlackList(ip string) (model.IPKey, error) {
	key, err := addIPToList(m.blacklist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) RemoveFromBlackList(ip string) (model.IPKey, error) {
	key, err := removeIPFrom(m.blacklist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) GetFromBlackList() ([]model.IPEntry, error) {
	return getIPsFromList(m.blacklist)
}

func (m *Manager) AddToWhiteList(ip string) (model.IPKey, error) {
	key, err := addIPToList(m.whitelist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) RemoveFromWhiteList(ip string) (model.IPKey, error) {
	key, err := removeIPFrom(m.whitelist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) GetFromWhiteList() ([]model.IPEntry, error) {
	return getIPsFromList(m.whitelist)
}