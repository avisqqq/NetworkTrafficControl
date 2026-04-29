package core

type EbpfLoader interface {
	NewIpFilter() IpFilter
	LoadCollection(objPath string) error
	ListenInterface(interfaceName string) error
	AttachProgram() error
	Close() error
}
