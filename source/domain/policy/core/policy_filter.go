package core

import "ntc/source/domain/policy"

type PolicyFilter interface {
	AddPolicy(policy.IpPortRuleKey) error
	DeletePolicy(policy.IpPortRuleKey) error
	GetPolicy() ([]policy.IpPortRuleKey, error)
}
