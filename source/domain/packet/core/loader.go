package core

import 
(
"context"
"ntc/source/domain/network/core"
)

type EbpfLoader interface {
	NewIpFilter() IpFilter
	NewCIDRFilter() core.CIDRFilter

	LoadCollection(objPath string) error
	ListenInterface(interfaceName string) error
	AttachProgram() error
	NewReader(ctx context.Context) (Reader, error)
	Close() error
}
