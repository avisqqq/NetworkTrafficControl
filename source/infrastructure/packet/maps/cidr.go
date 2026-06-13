package maps

import (
	"fmt"
	"ntc/source/domain/network"
	"ntc/source/domain/packet"

	"github.com/cilium/ebpf"
)

type cidr4Key struct {
      PrefixLen uint32
      Addr      [4]byte
}

type cidr6Key struct {
      PrefixLen uint32
      Addr      [16]byte
}

type CIDRMap struct {
	ebpfMap *ebpf.Map
	name    string
	version uint8
}

func NewCIDRMap(collation *ebpf.Collection, name string, version uint8) packet.Map[network.CIDR] {
	eBPFmap := collation.Maps[name]
	return &CIDRMap{ebpfMap: eBPFmap, name: name, version: version}
}

func cidr4KeyFromDomain(c network.CIDR) cidr4Key {
      var key cidr4Key
      key.PrefixLen = c.PrefixLen
      copy(key.Addr[:], c.IP[:4])
      return key
}


func cidr6KeyFromDomain(c network.CIDR) cidr6Key {
      return cidr6Key{
          PrefixLen: c.PrefixLen,
          Addr:      c.IP,
      }
}

func cidrFromV4Key(key cidr4Key) network.CIDR {
      var c network.CIDR
      c.Version = 4
      c.PrefixLen = key.PrefixLen
      copy(c.IP[:4], key.Addr[:])
      return c
}

func cidrFromV6Key(key cidr6Key) network.CIDR {
      return network.CIDR{
          Version:   6,
          PrefixLen: key.PrefixLen,
          IP:        key.Addr,
      }
}

func (m *CIDRMap) Add(entry network.CIDR) error {
	val := uint8(1)

	switch m.version {
	case 4:
		key := cidr4KeyFromDomain(entry)
		if err := m.ebpfMap.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("CIDRMap.Add: failed to add CIDR to %s v:%d: %w", m.name, m.version, err)
		}
	case 6:
		key := cidr6KeyFromDomain(entry)
		if err := m.ebpfMap.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("CIDRMap.Add: failed to add CIDR to %s v:%d: %w", m.name, m.version, err)
		}
	default:
		return fmt.Errorf("CIDRMap.Add: unsupported IP version %d for map %s ", m.version, m.name)
	}
	return nil
}

func (m *CIDRMap) Delete(entry network.CIDR) error {
	switch m.version {
	case 4:
		key := cidr4KeyFromDomain(entry)
		if err := m.ebpfMap.Delete(key); err != nil {
			return fmt.Errorf("CIDRMap.Delete: failed to remove CIDR from %s v:%d: %w", m.name, m.version, err)
		}
	case 6:
		key := cidr6KeyFromDomain(entry)
		if err := m.ebpfMap.Delete(key); err != nil {
			return fmt.Errorf("CIDRMap.Delete: failed to remove CIDR from %s v:%d: %w", m.name, m.version, err)
		}
	default:
		return fmt.Errorf("CIDRMap.Delete: unsupported IP version %d for map %s ", m.version, m.name)
	}
	return nil
}

func (m *CIDRMap) Get() ([]network.CIDR, error) {
	var value uint8
	var result []network.CIDR
	iteration := m.ebpfMap.Iterate()
	switch m.version {
	case 4:
		var key cidr4Key
	for iteration.Next(&key, &value) {
		result = append(result, cidrFromV4Key(key))
	}
	case 6:
		var key cidr6Key
	for iteration.Next(&key, &value) {
		result = append(result, cidrFromV6Key(key))
	}
	default:
		return nil, fmt.Errorf("CIDRMap.Get: unsupported IP version %d for map %s ", m.version, m.name)
	}

	

	if err := iteration.Err(); err != nil {
		return nil, fmt.Errorf("CIDRMap.Get: failed to iterate CIDR of %s v:%d: %w", m.name, m.version, err)
	}

	return result, nil
}

func (m *CIDRMap) Close() error {
	return m.ebpfMap.Close()
}