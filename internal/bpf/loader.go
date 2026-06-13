package bpf

import (
	"context"
	"log"
	"net"

	"ntc/internal/model"
	"ntc/internal/persist"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Manager struct {
	coll        *ebpf.Collection
	ingressLink link.Link
	egressLink  link.Link
	events      *ringbuf.Reader
	blacklist   *ebpf.Map
	whitelist   *ebpf.Map
	onlylocal   *ebpf.Map
	localNetsV4 *ebpf.Map
	localNetsV6 *ebpf.Map
	store       *persist.Store
}

func Load(objPath, ifaceName string, store *persist.Store, cidrs []string) (*Manager, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		coll:        coll,
		blacklist:   coll.Maps["blacklist"],
		whitelist:   coll.Maps["whitelist"],
		onlylocal:   coll.Maps["onlylocal"],
		localNetsV4: coll.Maps["local_nets_v4"],
		localNetsV6: coll.Maps["local_nets_v6"],
		store:       store,
	}
	if err := loadLocalNets(m.localNetsV4, m.localNetsV6, cidrs); err != nil {
		coll.Close()
		return nil, err
	}
	if store != nil {
		m.loadFromStore()
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		coll.Close()
		return nil, err
	}

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
		Program:   coll.Programs["tc_ingress"],
	})
	if err != nil {
		coll.Close()
		return nil, err
	}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
		Program:   coll.Programs["tc_egress"],
	})
	if err != nil {
		ingressLink.Close()
		coll.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		egressLink.Close()
		ingressLink.Close()
		coll.Close()
		return nil, err
	}

	m.ingressLink = ingressLink
	m.egressLink = egressLink
	m.events = rd
	return m, nil
}

func (m *Manager) ReadEvents(ctx context.Context) <-chan model.Event {
	return readEvents(ctx, m.events)
}

func (m *Manager) loadFromStore() {
	bl, wl, err := m.store.Load()
	if err != nil {
		log.Printf("persist: load failed: %v", err)
		return
	}
	for _, ip := range bl {
		if _, err := addIPToList(m.blacklist, ip); err != nil {
			log.Printf("persist: restore blacklist %s: %v", ip, err)
		}
	}
	for _, ip := range wl {
		if _, err := addIPToList(m.whitelist, ip); err != nil {
			log.Printf("persist: restore whitelist %s: %v", ip, err)
		}
	}
}

func (m *Manager) save() {
	if m.store == nil {
		return
	}
	bl, err := getIPsFromList(m.blacklist)
	if err != nil {
		log.Printf("persist: save blacklist: %v", err)
		return
	}
	wl, err := getIPsFromList(m.whitelist)
	if err != nil {
		log.Printf("persist: save whitelist: %v", err)
		return
	}
	blIPs := make([]string, len(bl))
	for i, e := range bl {
		blIPs[i] = e.IP
	}
	wlIPs := make([]string, len(wl))
	for i, e := range wl {
		wlIPs[i] = e.IP
	}
	if err := m.store.Save(blIPs, wlIPs); err != nil {
		log.Printf("persist: save failed: %v", err)
	}
}

func (m *Manager) Close() {
	m.events.Close()
	m.egressLink.Close()
	m.ingressLink.Close()
	m.coll.Close()
}
