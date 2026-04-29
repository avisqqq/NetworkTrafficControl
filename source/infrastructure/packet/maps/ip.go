package maps

import (
	"log"
	"ntc/internal/model"
	"ntc/source/domain/packet"

	"github.com/cilium/ebpf"
)

type IpMap struct {
	ebpfMap *ebpf.Map
}

func NewIpMap(m *ebpf.Map) packet.Map[packet.IPEntry] {
	return &IpMap{ebpfMap: m}
}

func (m *IpMap) Add(entry packet.IPEntry) error {
	val := uint8(1)
	if err := m.ebpfMap.Update(entry, val, ebpf.UpdateAny); err != nil {
		log.Panicf("IpMap:Add -> Failed to add IP to blacklist: %v", err)
		return err
	}

	return nil
}

func (m *IpMap) Delete(entry packet.IPEntry) error {
	if err := m.ebpfMap.Delete(entry); err != nil {
		log.Panicf("IpMap:Delete -> Failed to remove IP from blacklist: %v", err)
		return err
	}

	return nil
}

func (m *IpMap) Get() ([]packet.IPEntry, error) {
	var result []packet.IPEntry
	iteration := m.ebpfMap.Iterate()
	var key model.IPKey
	var value uint8

	for iteration.Next(&key, &value) {
		result = append(result, packet.IPEntry{
			Address: model.ParseIP(key),
			Version: key.Version,
		})
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
