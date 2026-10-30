package maps

import (
	"errors"
	"fmt"
	"syscall"

	"ntc/source/domain/packet"
	"ntc/source/domain/policy"

	"github.com/cilium/ebpf"
)

type IPPortMap struct {
	ebpfMap *ebpf.Map
	name    string
}

func NewIPPortMap(collection *ebpf.Collection, name string) packet.Map[policy.IPPortRuleKey] {
	eBPFmap := collection.Maps[name]
	return &IPPortMap{ebpfMap: eBPFmap, name: name}
}

func (m *IPPortMap) Add(entry policy.IPPortRuleKey) error {
	val := uint8(1)
	err := m.ebpfMap.Update(entry, val, ebpf.UpdateAny)
	if errors.Is(err, syscall.E2BIG) {
		return fmt.Errorf("IPPortMap.Add: failed to add rule to %s: %w", m.name, policy.ErrRuleLimitReached)
	}
	if err != nil {
		return fmt.Errorf("IPPortMap.Add: failed to add rule to %s: %w", m.name, err)
	}

	return nil
}

func (m *IPPortMap) Delete(entry policy.IPPortRuleKey) error {
	err := m.ebpfMap.Delete(entry)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("IPPortMap.Delete: failed to remove rule from %s: %w", m.name, policy.ErrRuleNotFound)
	}
	if err != nil {
		return fmt.Errorf("IPPortMap.Delete: failed to remove rule from %s: %w", m.name, err)
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
		return nil, fmt.Errorf("IPPortMap.Get: failed to iterate rules of %s: %w", m.name, err)
	}

	return result, nil
}

func (m *IPPortMap) Close() error {
	return m.ebpfMap.Close()
}
