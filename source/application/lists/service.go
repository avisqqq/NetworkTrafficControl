package lists

import (
	coreNetwork "ntc/source/domain/network/core"
	coreDomain "ntc/source/domain/packet/core"
	corePolicy "ntc/source/domain/policy/core"
)

type ListService struct {
	filter     coreDomain.IpFilter
	cidrFilter coreNetwork.CIDRFilter
	policy     corePolicy.PolicyFilter
}

func NewListService(f coreDomain.IpFilter, cidrFilter coreNetwork.CIDRFilter, policyFilter corePolicy.PolicyFilter) *ListService {
	return &ListService{
		filter:     f,
		cidrFilter: cidrFilter,
		policy:     policyFilter,
	}
}
