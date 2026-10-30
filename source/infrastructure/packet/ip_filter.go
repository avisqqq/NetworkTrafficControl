package packet

import (
	"ntc/source/application/lists"
	"ntc/source/domain/packet"
)

type IPFilter struct {
	whitelistMap packet.Map[packet.IPKey]
	blacklistMap packet.Map[packet.IPKey]
	onlylocalMap packet.Map[packet.IPKey]
}

func NewIPFilter(onlylocalMap, whitelistMap, blacklistMap packet.Map[packet.IPKey]) lists.IPFilter {
	return &IPFilter{
		whitelistMap: whitelistMap,
		blacklistMap: blacklistMap,
		onlylocalMap: onlylocalMap,
	}
}

func (f *IPFilter) AddToOnlyLocal(entry packet.IPKey) error {
	return f.onlylocalMap.Add(entry)
}

func (f *IPFilter) DeleteFromOnlyLocal(entry packet.IPKey) error {
	return f.onlylocalMap.Delete(entry)
}

func (f *IPFilter) GetOnlyLocal() ([]packet.IPKey, error) {
	return f.onlylocalMap.Get()
}

func (f *IPFilter) AddToWhitelist(entry packet.IPKey) error {
	return f.whitelistMap.Add(entry)
}

func (f *IPFilter) DeleteFromWhitelist(entry packet.IPKey) error {
	return f.whitelistMap.Delete(entry)
}

func (f *IPFilter) AddToBlacklist(entry packet.IPKey) error {
	return f.blacklistMap.Add(entry)
}

func (f *IPFilter) DeleteFromBlacklist(entry packet.IPKey) error {
	return f.blacklistMap.Delete(entry)
}

func (f *IPFilter) GetWhitelist() ([]packet.IPKey, error) {
	return f.whitelistMap.Get()
}

func (f *IPFilter) GetBlacklist() ([]packet.IPKey, error) {
	return f.blacklistMap.Get()
}
