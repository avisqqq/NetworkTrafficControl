package lists

import (
	coreDomain "ntc/source/domain/packet/core"
	coreNetwork "ntc/source/domain/network/core"
)

type ListService struct {
	filter coreDomain.IpFilter
	cidrFilter coreNetwork.CIDRFilter
}

func NewListService(f coreDomain.IpFilter, cidrFilter coreNetwork.CIDRFilter) *ListService {
	return &ListService{filter: f, cidrFilter: cidrFilter}
}
