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

func (m *Manager) AddToOnlyLocalList(ip string) (model.IPKey, error) {
	key, err := addIPToList(m.onlylocal, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) RemoveFromOnlyLocalList(ip string) (model.IPKey, error) {
	key, err := removeIPFrom(m.onlylocal, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) GetFromOnlyLocalList() ([]model.IPEntry, error) {
	return getIPsFromList(m.onlylocal)
}

func (m *Manager) GetLocalNetsV4() ([]model.CIDREntry, error) {
	return getCIDRsFromListV4(m.localNetsV4)
}

func (m *Manager) GetLocalNetsV6() ([]model.CIDREntry, error) {
	return getCIDRsFromListV6(m.localNetsV6)
}
