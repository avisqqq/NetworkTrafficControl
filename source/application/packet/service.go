package packet

import (
	"context"

	"ntc/source/application/lists"
	appNetwork "ntc/source/application/network"
	"ntc/source/domain/packet/core"
)

type Runtime struct {
	Reader core.Reader
	Lists  lists.ListManager
}

type PacketApp struct {
	loader core.EbpfLoader
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

	ipFilter := l.loader.NewIpFilter()
	mapFilter := l.loader.NewCIDRFilter()
	policyFilter := l.loader.NewPolicyFilter()
	if _, err := appNetwork.NewService(mapFilter).LoadDefaultLocalNets(localCIDRs, iface); err != nil {
		return nil, err
	}
	listService := lists.NewListService(ipFilter, mapFilter, policyFilter)

	return &Runtime{
		Reader: reader,
		Lists:  listService,
	}, nil
}

func NewPacketApp(l core.EbpfLoader) *PacketApp {
	return &PacketApp{loader: l}
}
