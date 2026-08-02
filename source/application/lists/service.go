package lists

import (
	coreNetwork "ntc/source/domain/network/core"
)

type ListService struct {
	filter     IPFilter
	cidrFilter coreNetwork.CIDRFilter
}

func NewListService(f IPFilter, cidrFilter coreNetwork.CIDRFilter) *ListService {
	return &ListService{filter: f, cidrFilter: cidrFilter}
}
