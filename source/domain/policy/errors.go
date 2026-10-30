package policy

import "errors"

var (
	ErrRuleNotFound     = errors.New("policy rule not found")
	ErrRuleLimitReached = errors.New("policy rule limit reached")
)
