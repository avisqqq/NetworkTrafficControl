package packet

import (
	"ntc/source/domain/packet/core"
	"ntc/source/domain/policy"
)

type PolicyFilter struct {
	policy core.Map[policy.IpPortRuleKey]
}

func NewPolicyFilter(policyMap core.Map[policy.IpPortRuleKey]) *PolicyFilter {
	return &PolicyFilter{
		policy: policyMap,
	}
}

func (f *PolicyFilter) DeletePolicy(entry policy.IpPortRuleKey) error {
	return f.policy.Delete(entry)
}

func (f *PolicyFilter) GetPolicy() ([]policy.IpPortRuleKey, error) {
	return f.policy.Get()
}

func (f *PolicyFilter) AddPolicy(entry policy.IpPortRuleKey) error {
	return f.policy.Add(entry)
}
