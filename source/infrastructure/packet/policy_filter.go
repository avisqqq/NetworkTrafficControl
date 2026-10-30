package packet

import (
	"ntc/source/domain/packet"
	"ntc/source/domain/policy"
)

type PolicyFilter struct {
	policy packet.Map[policy.IPPortRuleKey]
}

func NewPolicyFilter(policyMap packet.Map[policy.IPPortRuleKey]) *PolicyFilter {
	return &PolicyFilter{
		policy: policyMap,
	}
}

func (f *PolicyFilter) DeletePolicy(entry policy.IPPortRuleKey) error {
	return f.policy.Delete(entry)
}

func (f *PolicyFilter) GetPolicy() ([]policy.IPPortRuleKey, error) {
	return f.policy.Get()
}

func (f *PolicyFilter) AddPolicy(entry policy.IPPortRuleKey) error {
	return f.policy.Add(entry)
}
