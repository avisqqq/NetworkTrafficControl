package maps

import (
	"fmt"
	"ntc/source/domain/packet"

	"github.com/cilium/ebpf"
)

type IpMap struct {
	ebpfMap *ebpf.Map
	name    string
}

func NewIpMap(collation *ebpf.Collection, name string) packet.Map[packet.IPKey] {
	eBPFmap := collation.Maps[name]
	return &IpMap{ebpfMap: eBPFmap, name: name}
}

func (m *IpMap) Add(entry packet.IPKey) error {
	val := uint8(1)
	if err := m.ebpfMap.Update(entry, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("ItpMap.Add: failed to add IP to %s: %w", m.name, err)
	}

	return nil
}

func (m *IpMap) Delete(entry packet.IPKey) error {
	if err := m.ebpfMap.Delete(entry); err != nil {
		return fmt.Errorf("ItpMap.Delete: failed to remove IP from %s: %w", m.name, err)
	}

	return nil
}

func (m *IpMap) Get() ([]packet.IPKey, error) {
	var result []packet.IPKey
	iteration := m.ebpfMap.Iterate()
	var key packet.IPKey
	var value uint8

	for iteration.Next(&key, &value) {
		result = append(result, key)
	}

	if err := iteration.Err(); err != nil {
		return nil, fmt.Errorf("ItpMap.Get: failed to iterate IP of %s: %w", m.name, err)
	}

	return result, nil
}

func (m *IpMap) Close() error {
	return m.ebpfMap.Close()
}
