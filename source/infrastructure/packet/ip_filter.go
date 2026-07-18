package packet

import (
	"ntc/source/domain/packet"
	"ntc/source/domain/packet/core"
)

type IpFilter struct {
	whitelistMap core.Map[packet.IPKey]
	blacklistMap core.Map[packet.IPKey]
	onlylocalMap core.Map[packet.IPKey]
}

func NewIpFilter(onlylocalMap, whitelistMap, blacklistMap core.Map[packet.IPKey]) core.IpFilter {
	return &IpFilter{
		whitelistMap: whitelistMap,
		blacklistMap: blacklistMap,
		onlylocalMap: onlylocalMap,
	}
}

func (f *IpFilter) AddToOnlyLocal(entry packet.IPKey) error {
	return f.onlylocalMap.Add(entry)
}

func (f *IpFilter) DeleteFromOnlyLocal(entry packet.IPKey) error {
	return f.onlylocalMap.Delete(entry)
}

func (f *IpFilter) GetOnlyLocal() ([]packet.IPKey, error) {
	return f.onlylocalMap.Get()
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
