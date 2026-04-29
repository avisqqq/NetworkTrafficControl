package packet

import (
	"ntc/source/domain/packet"
	"ntc/source/domain/packet/core"
)

type IpFilter struct {
	whitelistMap packet.Map[packet.IPKey]
	blacklistMap packet.Map[packet.IPKey]
}

func NewIpFilter(whitelistMap, blacklistMap packet.Map[packet.IPKey]) core.IpFilter {
	return &IpFilter{
		whitelistMap: whitelistMap,
		blacklistMap: blacklistMap,
	}
}

func (f *IpFilter) AddToWhitelist(entry packet.IPKey) error {
	return f.whitelistMap.Add(entry)
}

func (f *IpFilter) DeleteFromWhitelist(entry packet.IPKey) error {
	return f.whitelistMap.Delete(entry)
}

func (f *IpFilter) AddToBlacklist(entry packet.IPKey) error {
	return f.blacklistMap.Add(entry)
}

func (f *IpFilter) DeleteFromBlacklist(entry packet.IPKey) error {
	return f.blacklistMap.Delete(entry)
}

func (f *IpFilter) GetWhitelist() ([]packet.IPKey, error) {
	return f.whitelistMap.Get()
}

func (f *IpFilter) GetBlacklist() ([]packet.IPKey, error) {
	return f.blacklistMap.Get()
}
