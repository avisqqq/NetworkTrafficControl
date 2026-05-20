package network

import (
	"fmt"
	"net"
)

type CIDR struct {
	IP        [16]byte
	PrefixLen uint32
	Version   uint8
}

type CIDREntry struct {
	CIDR      string `json:"cidr"`
	PrefixLen uint32 `json:"prefix_len"`
	Version   uint8  `json:"version"`
}

func CIDRsToEntriesByVersion(cidrs []CIDR, version uint8) []CIDREntry {
	entries := make([]CIDREntry, 0)

	for _, cidr := range cidrs {
		if cidr.Version != version {
			continue
		}

		entries = append(entries, cidr.ToEntry())
	}

	return entries
}
func CIDRsToEntries(cidrs []CIDR) []CIDREntry {
	entries := make([]CIDREntry, 0, len(cidrs))

	for _, cidr := range cidrs {
		entries = append(entries, cidr.ToEntry())
	}

	return entries
}
func CIDRFromString(raw string) (CIDR, error) {
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return CIDR{}, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, _ := ipNet.Mask.Size()
	var c CIDR

	c.PrefixLen = uint32(ones)

	if v4 := ip.To4(); v4 != nil {
		c.Version = 4
		copy(c.IP[:4], v4)
		return c, nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return CIDR{}, fmt.Errorf("invalid IP address in CIDR")
	}
	c.Version = 6
	copy(c.IP[:], v6)
	return c, nil
}
func (c CIDR) ToEntry() CIDREntry {
	return CIDREntry{
		CIDR:      c.ToString(),
		PrefixLen: c.PrefixLen,
		Version:   c.Version,
	}
}

func (c CIDR) ToString() string {
	switch c.Version {
	case 4:
		return fmt.Sprintf("%s/%d", net.IP(c.IP[:4]).String(), c.PrefixLen)
	case 6:
		return fmt.Sprintf("%s/%d", net.IP(c.IP[:16]).String(), c.PrefixLen)
	default:
		return fmt.Sprintf("<invalid>/%d", c.PrefixLen)
	}
}
