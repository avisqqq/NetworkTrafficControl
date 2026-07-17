package packet

import (
	"fmt"
	"net"
)

type IPKey struct {
	Version uint8
	Address [16]byte
}

type IPEntry struct {
	Version uint8  `json:"version"`
	IP      string `json:"ip"`
}

func IPVersion(ip net.IP) uint8 {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func (k *IPKey) ToString() string {
	if k.Version == 4 {
		return net.IP(k.Address[:4]).String()
	}
	return net.IP(k.Address[:16]).String()
}

func IPKeyFromString(ipStr string) (IPKey, error) {
	var key IPKey
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return key, fmt.Errorf("invalid IP: %s", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		key.Version = 4
		copy(key.Address[:4], v4)
		return key, nil
	}
	key.Version = 6
	copy(key.Address[:], ip.To16())
	return key, nil
}

func IpKeysToIpEntries(keys []IPKey) ([]IPEntry, error) {
	entries := make([]IPEntry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, IPEntry{
			Version: key.Version,
			IP:      key.ToString(),
		})
	}
	return entries, nil
}

func (p *Packet) PacketIpsToString() (string, string) {
	if p.IPVersion == 4 {
		return net.IP(p.Src[:4]).String(), net.IP(p.Dst[:4]).String()
	}
	return net.IP(p.Src[:]).String(), net.IP(p.Dst[:]).String()
}
