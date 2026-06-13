package bpf

import (
	"encoding/binary"
	"net"

	"ntc/internal/model"

	"github.com/cilium/ebpf"
)

func Uint32ToIP(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func ParseIp(raw [16]byte, version uint8) string {
	if version == 4 {
		return net.IP(raw[:4]).String()
	}
	return net.IP(raw[:16]).String()
}

func addIPToList(m *ebpf.Map, ipStr string) (model.IPKey, error) {
	key, err := model.BuildIPKey(ipStr)
	if err != nil {
		return key, err
	}
	val := uint8(1)
	if err := m.Put(key, val); err != nil {
		return key, err
	}
	return key, nil
}

func removeIPFrom(m *ebpf.Map, ipStr string) (model.IPKey, error) {
	key, err := model.BuildIPKey(ipStr)
	if err != nil {
		return key, err
	}
	if err := m.Delete(key); err != nil {
		return key, err
	}
	return key, nil
}

func getIPsFromList(m *ebpf.Map) ([]model.IPEntry, error) {
	var result []model.IPEntry
	iter := m.Iterate()

	var key model.IPKey
	var value uint8

	for iter.Next(&key, &value) {
		result = append(result, model.IPEntry{
			IP:      model.ParseIP(key),
			Version: key.Version,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
