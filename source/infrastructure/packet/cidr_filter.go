package packet

import (
	"ntc/source/domain/network"
	"ntc/source/domain/packet"
)

type CIDRFilter struct {
	v4 packet.Map[network.CIDR]
	v6 packet.Map[network.CIDR]
}

func NewCIDRFilter(v4Map, v6Map packet.Map[network.CIDR]) *CIDRFilter {
	return &CIDRFilter{
		v4: v4Map,
		v6: v6Map,
	}
}
func (f *CIDRFilter) DeleteLocalCIDRV4(entry network.CIDR) error {
	return f.v4.Delete(entry)
}

func (f *CIDRFilter) GetLocalCIDRsV4() ([]network.CIDR, error) {
	return f.v4.Get()
}

func (f *CIDRFilter) AddLocalCIDRV4(entry network.CIDR) error {
	return f.v4.Add(entry)
}

func (f *CIDRFilter) GetLocalCIDRsV6() ([]network.CIDR, error) {
	return f.v6.Get()
}

func (f *CIDRFilter) DeleteLocalCIDRV6(entry network.CIDR) error {
	return f.v6.Delete(entry)
}

func (f *CIDRFilter) AddLocalCIDRV6(entry network.CIDR) error {
	return f.v6.Add(entry)
}
