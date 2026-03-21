package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
)

func Uint32ToIP(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func IpToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid ipv4")
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func (m *Manager) AddToBlackList(ipStr string) error {
	key, err := IpToUint32(ipStr)
	if err != nil {
		return err
	}
	val := uint8(1)
	return m.Blacklist.Put(key, val)
}

func (m *Manager) RemoveFromBlackList(ipStr string) error {
	key, err := IpToUint32(ipStr)
	if err != nil {
		return err
	}
	return m.Blacklist.Delete(key)
}

func (m *Manager) AddToWhiteList(ipStr string) error {
	key, err := IpToUint32(ipStr)
	if err != nil {
		return err
	}
	val := uint8(1)
	return m.Whitelist.Put(key, val)
}

func (m *Manager) RemoveFromWhiteList(ipStr string) error {
	key, err := IpToUint32(ipStr)
	if err != nil {
		return err
	}
	return m.Whitelist.Delete(key)
}
