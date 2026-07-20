package core

import (
	"context"

	coreNetwork "ntc/source/domain/network/core"
	corePolicy "ntc/source/domain/policy/core"
)

type EbpfLoader interface {
	NewIpFilter() IpFilter
	NewCIDRFilter() coreNetwork.CIDRFilter
	NewPolicyFilter() corePolicy.PolicyFilter

	LoadCollection(objPath string) error
	ListenInterface(interfaceName string) error
	AttachProgram() error
	NewReader(ctx context.Context) (Reader, error)
	Close() error
}
