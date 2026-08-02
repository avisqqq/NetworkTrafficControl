package packet

import (
	"context"
	"ntc/source/application/lists"
	appNetwork "ntc/source/application/network"
	"ntc/source/application/packetstream"
)

type Runtime struct {
	Reader packetstream.Reader
	Lists  lists.ListManager
}

type PacketApp struct {
	loader EbpfLoader
}

func (l *PacketApp) Start(ctx context.Context, objPath, iface string, localCIDRs []string) (*Runtime, error) {
	if err := l.loader.LoadCollection(objPath); err != nil {
		return nil, err
	}
	if err := l.loader.ListenInterface(iface); err != nil {
		return nil, err
	}
	if err := l.loader.AttachProgram(); err != nil {
		return nil, err
	}

	reader, err := l.loader.NewReader(ctx)
	if err != nil {
		return nil, err
	}

	ipFilter := l.loader.NewIPFilter()
	mapFilter := l.loader.NewCIDRFilter()
	if _, err := appNetwork.NewService(mapFilter).LoadDefaultLocalNets(localCIDRs, iface); err != nil {
		return nil, err
	}
	listService := lists.NewListService(ipFilter, mapFilter)

	return &Runtime{
		Reader: reader,
		Lists:  listService,
	}, nil
}

func NewPacketApp(l EbpfLoader) *PacketApp {
	return &PacketApp{loader: l}
}
