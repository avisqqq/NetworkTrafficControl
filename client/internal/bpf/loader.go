package bpf

import (
	"log"
	"net"

	"client/internal/persist"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Manager struct {
	Coll        *ebpf.Collection
	IngressLink link.Link
	EgressLink  link.Link
	Events      *ringbuf.Reader
	Blacklist   *ebpf.Map
	Whitelist   *ebpf.Map
	Interface   string
	Ifindex     int
	store       *persist.Store
}

func Load(objPath, ifaceName string, store *persist.Store) (*Manager, error) {
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

	ingress, ok := coll.Programs["tc_ingress"]
	if !ok {
		coll.Close()
		return nil, errMissingProgram("tc_ingress")
	}
	egress, ok := coll.Programs["tc_egress"]
	if !ok {
		coll.Close()
		return nil, errMissingProgram("tc_egress")
	}

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   ingress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		coll.Close()
		return nil, err
	}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   egress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
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

	m := &Manager{
		Coll:        coll,
		IngressLink: ingressLink,
		EgressLink:  egressLink,
		Events:      rd,
		Blacklist:   coll.Maps["blacklist"],
		Whitelist:   coll.Maps["whitelist"],
		Interface:   iface.Name,
		Ifindex:     iface.Index,
		store:       store,
	}
	if store != nil {
		m.loadFromStore()
	}
	return m, nil
}

func (m *Manager) loadFromStore() {
	bl, wl, err := m.store.Load()
	if err != nil {
		log.Printf("persist: load failed: %v", err)
		return
	}
	for _, ip := range bl {
		if _, err := AddIpToList(m.Blacklist, ip); err != nil {
			log.Printf("persist: restore blacklist %s: %v", ip, err)
		}
	}
	for _, ip := range wl {
		if _, err := AddIpToList(m.Whitelist, ip); err != nil {
			log.Printf("persist: restore whitelist %s: %v", ip, err)
		}
	}
}

func (m *Manager) save() {
	if m.store == nil {
		return
	}
	bl, err := GetIpFromList(m.Blacklist)
	if err != nil {
		log.Printf("persist: save blacklist: %v", err)
		return
	}
	wl, err := GetIpFromList(m.Whitelist)
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
	m.Events.Close()
	m.EgressLink.Close()
	m.IngressLink.Close()
	m.Coll.Close()
}

type errMissingProgram string

func (e errMissingProgram) Error() string {
	return "missing eBPF program: " + string(e)
}
