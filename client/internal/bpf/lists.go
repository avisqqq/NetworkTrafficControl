package bpf

import (
	"client/internal/model"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
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
func BuildIpKey(ipString string) (model.Ip_Key, error) {
	var key model.Ip_Key

	ip := net.ParseIP(ipString)
	if ip == nil {
		return key, fmt.Errorf("Invalid IP")
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		key.Version = 4
		copy(key.Address[:4], ipv4)
		return key, nil
	}

	ipv6 := ip.To16()
	if ipv6 == nil {
		return key, fmt.Errorf("Invalid IP")
	}

	key.Version = 6
	copy(key.Address[:], ipv6)
	return key, nil
}

// ??? DO NEED
func ParseIp(raw [16]byte, version uint8) string {
	if version == 4 {
		return net.IP(raw[:4]).String()
	}
	return net.IP(raw[:16]).String()
}

func ParseIpKey(key model.Ip_Key) string {
	if key.Version == 4 {
		return net.IP(key.Address[:4]).String()
	}
	return net.IP(key.Address[:16]).String()
}

func AddIpToList(m *ebpf.Map, ipStr string) (model.Ip_Key, error) {
	key, err := BuildIpKey(ipStr)
	if err != nil {
		return key, err
	}
	val := uint8(1)
	if err := m.Put(key, val); err != nil {
		return key, err
	}
	return key, nil
}

func RemoveIpFrom(m *ebpf.Map, ipStr string) (model.Ip_Key, error) {
	key, err := BuildIpKey(ipStr)
	if err != nil {
		return key, err
	}
	if err := m.Delete(key); err != nil {
		return key, err
	}
	return key, nil
}

func GetIpFromList(m *ebpf.Map) ([]model.IpEntry, error) {

	var result []model.IpEntry
	iter := m.Iterate()

	var key model.Ip_Key
	var value uint8

	for iter.Next(&key, &value) {
		ip := ParseIpKey(key)
		result = append(result, model.IpEntry{
			IP:      ip,
			Version: key.Version,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
