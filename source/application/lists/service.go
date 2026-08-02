package lists

import (
	coreNetwork "ntc/source/domain/network/core"
)

type ListService struct {
	filter     IpFilter
	cidrFilter coreNetwork.CIDRFilter
}

func NewListService(f IpFilter, cidrFilter coreNetwork.CIDRFilter) *ListService {
	return &ListService{filter: f, cidrFilter: cidrFilter}
}
