package lists

import (
	coreNetwork "ntc/source/domain/network/core"
	corePolicy "ntc/source/domain/policy/core"
)

type ListService struct {
	filter     IPFilter
	cidrFilter coreNetwork.CIDRFilter
	policy     corePolicy.PolicyFilter
}

func NewListService(f IPFilter, cidrFilter coreNetwork.CIDRFilter, policyFilter corePolicy.PolicyFilter) *ListService {
	return &ListService{
		filter:     f,
		cidrFilter: cidrFilter,
		policy:     policyFilter,
	}
}
