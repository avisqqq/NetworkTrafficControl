package core

import "context"

type EbpfLoader interface {
	NewIpFilter() IpFilter
	LoadCollection(objPath string) error
	ListenInterface(interfaceName string) error
	AttachProgram() error
	NewReader(ctx context.Context) (Reader, error)
	Close() error
}
