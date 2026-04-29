package packet

import (
	"ntc/source/domain/packet"
	"ntc/source/domain/packet/core"
)

type IpFilter struct {
	whitelistMap packet.Map[packet.IPEntry]
	blacklistMap packet.Map[packet.IPEntry]
}

func NewIpFilter(whitelistMap, blacklistMap packet.Map[packet.IPEntry]) core.IpFilter {
	return &IpFilter{
		whitelistMap: whitelistMap,
		blacklistMap: blacklistMap,
	}
}

func (f *IpFilter) AddToWhitelist(entry packet.IPEntry) error {
	return f.whitelistMap.Add(entry)
}

func (f *IpFilter) DeleteFromWhitelist(entry packet.IPEntry) error {
	return f.whitelistMap.Delete(entry)
}

func (f *IpFilter) AddToBlacklist(entry packet.IPEntry) error {
	return f.blacklistMap.Add(entry)
}

func (f *IpFilter) DeleteFromBlacklist(entry packet.IPEntry) error {
	return f.blacklistMap.Delete(entry)
}

func (f *IpFilter) GetWhitelist() ([]packet.IPEntry, error) {
	return f.whitelistMap.Get()
}

func (f *IpFilter) GetBlacklist() ([]packet.IPEntry, error) {
	return f.blacklistMap.Get()
}
