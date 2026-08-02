package lists

import (
	"ntc/source/domain/network"
	"ntc/source/domain/packet"
)

func (m *ListService) AddToOnlyLocalByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return packet.IPKey{}, err
	}
	return key, m.filter.AddToOnlyLocal(key)
}

func (m *ListService) RemoveFromOnlyLocalByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return packet.IPKey{}, err
	}
	return key, m.filter.DeleteFromOnlyLocal(key)
}

func (m *ListService) GetFromOnlyLocalByString() ([]packet.IPEntry, error) {
	key, err := m.filter.GetOnlyLocal()
	if err != nil {
		return []packet.IPEntry{}, err
	}
	return packet.IPKeysToIPEntries(key)

}

func (m *ListService) AddToBlackListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return packet.IPKey{}, err
	}
	return key, m.filter.AddToBlacklist(key)
}
func (m *ListService) RemoveFromBlackListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return packet.IPKey{}, err
	}
	return key, m.filter.DeleteFromBlacklist(key)
}
func (m *ListService) GetFromBlackListByString() ([]packet.IPEntry, error) {
	key, err := m.filter.GetBlacklist()
	if err != nil {
		return []packet.IPEntry{}, err
	}
	return packet.IPKeysToIPEntries(key)

}
func (m *ListService) AddToWhiteListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return packet.IPKey{}, err
	}
	return key, m.filter.AddToWhitelist(key)
}
func (m *ListService) RemoveFromWhiteListByString(ip string) (packet.IPKey, error) {
	key, err := packet.IPKeyFromString(ip)
	if err != nil {
		return packet.IPKey{}, err
	}
	return key, m.filter.DeleteFromWhitelist(key)

}
func (m *ListService) GetFromWhiteListByString() ([]packet.IPEntry, error) {
	key, err := m.filter.GetWhitelist()
	if err != nil {
		return []packet.IPEntry{}, err
	}
	return packet.IPKeysToIPEntries(key)

}
func (m *ListService) AddToLocalNetsV6(ip string) (network.CIDR, error) {
	key, err := network.CIDRFromString(ip)
	if err != nil {
		return network.CIDR{}, err
	}
	return key, m.cidrFilter.AddLocalCIDRV6(key)
}

func (m *ListService) RemoveFromLocalNetsV6(ip string) (network.CIDR, error) {
	key, err := (network.CIDRFromString(ip))
	if err != nil {
		return network.CIDR{}, err
	}
	return key, m.cidrFilter.DeleteLocalCIDRV6(key)
}

func (m *ListService) GetFromLocalNetsV6() ([]network.CIDREntry, error) {
	key, err := m.cidrFilter.GetLocalCIDRsV6()
	if err != nil {
		return []network.CIDREntry{}, err
	}
	return network.CIDRsToEntriesByVersion(key, 6), nil
}
func (m *ListService) AddToLocalNetsV4(ip string) (network.CIDR, error) {
	key, err := network.CIDRFromString(ip)
	if err != nil {
		return network.CIDR{}, err
	}
	return key, m.cidrFilter.AddLocalCIDRV4(key)
}

func (m *ListService) RemoveFromLocalNetsV4(ip string) (network.CIDR, error) {
	key, err := (network.CIDRFromString(ip))
	if err != nil {
		return network.CIDR{}, err
	}
	return key, m.cidrFilter.DeleteLocalCIDRV4(key)
}

func (m *ListService) GetFromLocalNetsV4() ([]network.CIDREntry, error) {
	key, err := m.cidrFilter.GetLocalCIDRsV4()
	if err != nil {
		return []network.CIDREntry{}, err
	}
	return network.CIDRsToEntriesByVersion(key, 4), nil
}
