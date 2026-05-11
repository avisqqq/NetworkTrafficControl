package lists

import (
	"ntc/source/domain/packet"
)

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
	return packet.IpKeysToIpEntries(key)

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
	return packet.IpKeysToIpEntries(key)

}
