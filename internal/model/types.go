package model

import (
	"fmt"
	"net"
)

type Event struct {
	Ts        uint64
	Seq       uint64
	Src       [16]uint8
	Dst       [16]uint8
	SrcPort   uint16
	DstPort   uint16
	PktSize   uint16
	Proto     uint8
	Action    uint8
	IPVersion uint8
	Direction uint8
	TCPFlags  uint8
	Pad       [1]byte
}

type OutEvent struct {
	Time      string `json:"time"`
	Seq       uint64 `json:"seq"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Proto     string `json:"proto"`
	Action    string `json:"action"`
	Direction string `json:"direction"`
}

// --- Action ---

type Action uint8

const (
	ActPass Action = iota
	ActDrop
	ActSkip
	ActSSHBypass
	ActOnlyLocalDrop
	ActUnknown
)

func (a Action) String() string {
	switch a {
	case ActPass:
		return "PASS"
	case ActDrop:
		return "DROP"
	case ActSkip:
		return "SKIP"
	case ActSSHBypass:
		return "SSH"
	case ActOnlyLocalDrop:
		return "ONLY_LOCAL_DROP"
	default:
		return "UNKNOWN"
	}
}

func ParseAction(v uint8) Action {
	switch Action(v) {
	case ActPass, ActDrop, ActSkip, ActSSHBypass, ActOnlyLocalDrop:
		return Action(v)
	default:
		return ActUnknown
	}
}

// --- Direction ---

type Direction uint8

const (
	DirIngress Direction = 0
	DirEgress  Direction = 1
)

func (d Direction) String() string {
	if d == DirEgress {
		return "EGRESS"
	}
	return "INGRESS"
}

func ParseDirection(d uint8) string {
	return Direction(d).String()
}

// --- Proto ---

func ProtoString(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "OTHER"
	}
}

// --- IP ---

type IPKey struct {
	Version uint8
	Address [16]byte
}

func ParseIP(k IPKey) string {
	if k.Version == 4 {
		return net.IP(k.Address[:4]).String()
	}
	return net.IP(k.Address[:16]).String()
}

func BuildIPKey(ipStr string) (IPKey, error) {
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
func IpVersion(ip net.IP) uint8 {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

type IPEntry struct {
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}

type CIDREntry struct {
	CIDR      string `json:"cidr"`
	PrefixLen uint32 `json:"prefix_len"`
	Version   uint8  `json:"version"`
}
