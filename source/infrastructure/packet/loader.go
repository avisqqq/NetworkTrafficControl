package packet

import (
	"context"
	"log"
	"net"
	"ntc/source/application/lists"
	"ntc/source/application/packet"
	"ntc/source/application/packetstream"
	networkCore "ntc/source/domain/network/core"
	"ntc/source/infrastructure/packet/maps"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Loader struct {
	networkInterface *net.Interface
	collection       *ebpf.Collection
	ingressLink      link.Link
	egressLink       link.Link
	packets          *ringbuf.Reader
}

func NewEbpfLoader() packet.EbpfLoader {
	return &Loader{}
}

func (l *Loader) NewIPFilter() lists.IPFilter {
	whitelistMap := maps.NewIPMap(l.collection, "whitelist")
	blacklistMap := maps.NewIPMap(l.collection, "blacklist")
	onlylocalMap := maps.NewIPMap(l.collection, "onlylocal")

	return NewIPFilter(onlylocalMap, whitelistMap, blacklistMap)
}
func (l *Loader) NewCIDRFilter() networkCore.CIDRFilter {
	v4 := maps.NewCIDRMap(l.collection, "local_nets_v4", 4)
	v6 := maps.NewCIDRMap(l.collection, "local_nets_v6", 6)

	return NewCIDRFilter(v4, v6)
}

func (l *Loader) NewReader(ctx context.Context) (packetstream.Reader, error) {
	reader, err := ringbuf.NewReader(l.collection.Maps["events"])
	if err != nil {
		log.Fatalf("ebpf/loader:NewReader -> failed to create ring buffer reader: %v", err)
		return nil, err
	}
	l.packets = reader
	return NewReader(ctx, l.packets), nil
}

func (l *Loader) LoadCollection(objPath string) error {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("ebpf/loader:LoadCollection -> failed to load collection spec: %v", err)
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("ebpf/loader:LoadCollection -> failed to create collection: %v", err)
		return err
	}

	l.collection = coll
	return nil
}

func (l *Loader) ListenInterface(interfaceName string) error {
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("ebpf/loader:ListenInterface -> failed to get network interface: %v", err)
		return err
	}

	l.networkInterface = networkInterface
	return nil
}

func (l *Loader) AttachProgram() error {
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: l.networkInterface.Index,
		Attach:    ebpf.AttachTCXIngress,
		Program:   l.collection.Programs["tc_ingress"],
	})
	if err != nil {
		log.Fatalf("ebpf/loader:AttachProgram -> failed to attach ingress link: %v", err)
		return err
	}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: l.networkInterface.Index,
		Attach:    ebpf.AttachTCXEgress,
		Program:   l.collection.Programs["tc_egress"],
	})
	if err != nil {
		log.Fatalf("ebpf/loader:AttachProgram -> failed to attach egress link: %v", err)
		return err
	}

	l.ingressLink = ingressLink
	l.egressLink = egressLink
	return nil
}

func (l *Loader) Close() error {
	if l.packets != nil {
		if err := l.packets.Close(); err != nil {
			log.Printf("ebpf/loader:Close -> falied to close reader: %v", err)
		}
	}
	if err := l.ingressLink.Close(); err != nil {
		log.Printf("ebpf/loader:Close -> failed to close ingress link: %v", err)
		return err
	}

	if err := l.egressLink.Close(); err != nil {
		log.Printf("ebpf/loader:Close -> failed to close egress link: %v", err)
		return err
	}
	if l.collection != nil {
		l.collection.Close()
	}
	return nil
}
