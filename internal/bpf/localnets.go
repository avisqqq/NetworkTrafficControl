package bpf

import (
	"fmt"
	"net"

	"ntc/internal/model"

	"github.com/cilium/ebpf"
)

func parseCIDRKey(key any) string {
	switch k := key.(type) {
	case cidr4Key:
		return fmt.Sprintf("%s/%d",
			net.IP(k.Addr[:]).String(), k.PrefixLen)
	case cidr6Key:
		return fmt.Sprintf("%s/%d",
			net.IP(k.Addr[:]).String(), k.PrefixLen)
	default:
		return ""
	}
}

type cidr6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

type cidr4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

func loadLocalNets(v4Map, v6Map *ebpf.Map, cidrs []string) error {
	val := uint8(1)

	for _, raw := range cidrs {
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("parse local CIDRS %q: %w", raw, err)
		}
		ones, _ := ipNet.Mask.Size()

		if v4 := ipNet.IP.To4(); v4 != nil {
			var key cidr4Key
			key.PrefixLen = uint32(ones)
			copy(key.Addr[:], v4)

			if err := v4Map.Put(key, val); err != nil {
				return fmt.Errorf("put IPv4 local CIDR %q: %w", raw, err)
			}
			continue

		}

		if v6 := ipNet.IP.To16(); v6 != nil {
			var key cidr6Key
			key.PrefixLen = uint32(ones)
			copy(key.Addr[:], v6)

			if err := v6Map.Put(key, val); err != nil {
				return fmt.Errorf("put IPv6 local CIDR %q: %w", raw, err)
			}
		}
	}

	return nil
}

func getCIDRsFromListV4(m *ebpf.Map) ([]model.CIDREntry, error) {
	result := make([]model.CIDREntry, 0)
	iter := m.Iterate()

	var key cidr4Key
	var value uint8

	for iter.Next(&key, &value) {
		result = append(result, model.CIDREntry{
			CIDR:      parseCIDRKey(key),
			PrefixLen: key.PrefixLen,
			Version:   4,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func getCIDRsFromListV6(m *ebpf.Map) ([]model.CIDREntry, error) {
	result := make([]model.CIDREntry, 0)
	iter := m.Iterate()

	var key cidr6Key
	var value uint8

	for iter.Next(&key, &value) {
		result = append(result, model.CIDREntry{
			CIDR:      parseCIDRKey(key),
			PrefixLen: key.PrefixLen,
			Version:   6,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
