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
	Address string `json:"address"`
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
