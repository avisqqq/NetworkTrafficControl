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

func (m *Manager) GetFromBlackList() ([]string, error) {
	var result []string
	iter := m.Blacklist.Iterate()

	var key uint32
	var value uint8

	for iter.Next(&key, &value) {
		ip := Uint32ToIP(key)
		result = append(result, ip)
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
func (m *Manager) GetFromWhiteList() ([]string, error) {
	var result []string
	iter := m.Whitelist.Iterate()

	var key uint32
	var value uint8

	for iter.Next(&key, &value) {
		ip := Uint32ToIP(key)
		result = append(result, ip)
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
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
