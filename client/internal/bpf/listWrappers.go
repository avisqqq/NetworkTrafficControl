package bpf

import (
	"client/internal/model"
)

func (m *Manager) AddToBlackList(ip string) (model.Ip_Key, error) {
	key, err := AddIpToList(m.Blacklist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) RemoveFromBlackList(ip string) (model.Ip_Key, error) {
	key, err := RemoveIpFrom(m.Blacklist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) GetFromBlackList() ([]model.IpEntry, error) {
	return GetIpFromList(m.Blacklist)
}

func (m *Manager) AddToWhiteList(ip string) (model.Ip_Key, error) {
	key, err := AddIpToList(m.Whitelist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) RemoveFromWhiteList(ip string) (model.Ip_Key, error) {
	key, err := RemoveIpFrom(m.Whitelist, ip)
	if err == nil {
		m.save()
	}
	return key, err
}

func (m *Manager) GetFromWhiteList() ([]model.IpEntry, error) {
	return GetIpFromList(m.Whitelist)
}
