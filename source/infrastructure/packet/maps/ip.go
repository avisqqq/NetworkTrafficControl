package maps

import (
	"log"
	"ntc/source/domain/packet"

	"github.com/cilium/ebpf"
)

type IpMap struct {
	ebpfMap *ebpf.Map
}

func NewIpMap(m *ebpf.Map) packet.Map[packet.IPKey] {
	return &IpMap{ebpfMap: m}
}

func (m *IpMap) Add(entry packet.IPKey) error {
	val := uint8(1)
	if err := m.ebpfMap.Update(entry, val, ebpf.UpdateAny); err != nil {
		log.Panicf("IpMap:Add -> Failed to add IP to blacklist: %v", err)
		return err
	}

	return nil
}

func (m *IpMap) Delete(entry packet.IPKey) error {
	if err := m.ebpfMap.Delete(entry); err != nil {
		log.Panicf("IpMap:Delete -> Failed to remove IP from blacklist: %v", err)
		return err
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
		log.Panicf("IpMap:Get -> Failed to iterate IP map: %v", err)
		return nil, err
	}

	return result, nil
}

func (m *IpMap) Close() error {
	return m.ebpfMap.Close()
}
