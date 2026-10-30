package core

import "ntc/source/domain/policy"

type PolicyFilter interface {
	AddPolicy(policy.IPPortRuleKey) error
	DeletePolicy(policy.IPPortRuleKey) error
	GetPolicy() ([]policy.IPPortRuleKey, error)
}
