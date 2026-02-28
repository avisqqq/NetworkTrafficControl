package bpf

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Manager struct {
	Coll      *ebpf.Collection
	Link      link.Link
	Events    *ringbuf.Reader
	Blacklist *ebpf.Map
	Whitelist *ebpf.Map
}

func Load(objPath, ifaceName string) (*Manager, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		coll.Close()
		return nil, err
	}

	prog := coll.Programs["xdp_basic"]

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		coll.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		lnk.Close()
		coll.Close()
		return nil, err
	}

	return &Manager{
		Coll:      coll,
		Link:      lnk,
		Events:    rd,
		Blacklist: coll.Maps["blacklist"],
		Whitelist: coll.Maps["whitelist"],
	}, nil
}

func (m *Manager) Close() {
	m.Events.Close()
	m.Link.Close()
	m.Coll.Close()
}
