package packet

import (
	"context"
	"ntc/source/application/lists"
	"ntc/source/application/packetstream"
	"ntc/source/domain/network/core"
)

type EbpfLoader interface {
	NewIPFilter() lists.IPFilter
	NewCIDRFilter() core.CIDRFilter

	LoadCollection(objPath string) error
	ListenInterface(interfaceName string) error
	AttachProgram() error
	NewReader(ctx context.Context) (packetstream.Reader, error)
	Close() error
}
