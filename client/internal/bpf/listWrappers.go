package bpf

import (
	"client/internal/model"
)

func (m *Manager) AddToBlackList(ip string) (model.Ip_Key, error) {
	return AddIpToList(m.Blacklist, ip)
}

func (m *Manager) RemoveFromBlackList(ip string) (model.Ip_Key, error) {
	return RemoveIpFrom(m.Blacklist, ip)
}

func (m *Manager) GetFromBlackList() ([]model.IpEntry, error) {
	return GetIpFromList(m.Blacklist)
}

func (m *Manager) AddToWhiteList(ip string) (model.Ip_Key, error) {
	return AddIpToList(m.Whitelist, ip)
}

func (m *Manager) RemoveFromWhiteList(ip string) (model.Ip_Key, error) {
	return RemoveIpFrom(m.Whitelist, ip)
}

func (m *Manager) GetFromWhiteList() ([]model.IpEntry, error) {
	return GetIpFromList(m.Whitelist)
}
