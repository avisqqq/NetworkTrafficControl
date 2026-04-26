package model

import "net"

type Event struct {
	Ts      uint64
	Seq     uint64
	Ifindex uint32
	SrcPort uint16
	DstPort uint16

	Src [16]uint8
	Dst [16]uint8

	Proto     uint8
	Action    uint8
	IPVersion uint8
	Direction uint8
	Pad       [4]byte
}

type Action uint8

const (
	ActPass Action = iota
	ActDrop
	ActSkip
	ActSSHBypass
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
	default:
		return "UNKNOWN"
	}
}

func ParseAction(v uint8) Action {
	switch Action(v) {
	case ActPass, ActDrop, ActSkip, ActSSHBypass:
		return Action(v)
	default:
		return ActUnknown
	}
}

func ProtoString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1, 58:
		return "ICMP"
	default:
		return "OTHER"
	}
}

type Direction uint8

const (
	DirIngress Direction = iota
	DirEgress
	DirUnknown
)

func (d Direction) String() string {
	switch d {
	case DirIngress:
		return "INGRESS"
	case DirEgress:
		return "EGRESS"
	default:
		return "UNKNOWN"
	}
}

func ParseDirection(v uint8) Direction {
	switch Direction(v) {
	case DirIngress, DirEgress:
		return Direction(v)
	default:
		return DirUnknown
	}
}

type Ip_Key struct {
	Version uint8
	Address [16]byte
}

func ParseIP(k Ip_Key) string {
	if k.Version == 4 {
		return net.IP(k.Address[:4]).String()
	}
	return net.IP(k.Address[:16]).String()
}

func ParseRawIP(raw [16]uint8, version uint8) string {
	if version == 4 {
		return net.IP(raw[:4]).String()
	}
	return net.IP(raw[:16]).String()
}

type IpEntry struct {
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}
