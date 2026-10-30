package maps

import (
	"fmt"

	"ntc/source/domain/packet"
	"ntc/source/domain/policy"

	"github.com/cilium/ebpf"
)

type IPPortMap struct {
	ebpfMap *ebpf.Map
	name    string
}

func NewIPPortMap(collation *ebpf.Collection, name string) packet.Map[policy.IPPortRuleKey] {
	eBPFmap := collation.Maps[name]
	return &IPPortMap{ebpfMap: eBPFmap, name: name}
}

func (m *IPPortMap) Add(entry policy.IPPortRuleKey) error {
	val := uint8(1)
	if err := m.ebpfMap.Update(entry, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("ItpMap.Add: failed to add IP to %s: %w", m.name, err)
	}

	return nil
}

func (m *IPPortMap) Delete(entry policy.IPPortRuleKey) error {
	if err := m.ebpfMap.Delete(entry); err != nil {
		return fmt.Errorf("ItpMap.Delete: failed to remove IP from %s: %w", m.name, err)
	}

	return nil
}

func (m *IPPortMap) Get() ([]policy.IPPortRuleKey, error) {
	var result []policy.IPPortRuleKey
	iteration := m.ebpfMap.Iterate()
	var key policy.IPPortRuleKey
	var value uint8

	for iteration.Next(&key, &value) {
		result = append(result, key)
	}

	if err := iteration.Err(); err != nil {
		return nil, fmt.Errorf("ItpMap.Get: failed to iterate IP of %s: %w", m.name, err)
	}

	return result, nil
}

func (m *IPPortMap) Close() error {
	return m.ebpfMap.Close()
}
