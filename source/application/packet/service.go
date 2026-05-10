package packet

import (
	"ntc/source/domain/packet/core"
)

type PacketApp struct {
	loader core.EbpfLoader
}

func (l *PacketApp) Start(objPath, iface string) error {
	if err := l.loader.LoadCollection(objPath); err != nil {
		return err
	}
	if err := l.loader.ListenInterface(iface); err != nil {
		return err
	}
	if err := l.loader.AttachProgram(); err != nil {
		return err
	}
	return nil
}


func NewPacketApp(l core.EbpfLoader) *PacketApp{
	return &PacketApp{loader: l}
}
