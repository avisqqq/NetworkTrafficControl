package model

import "net"

type Event struct {
	Ts  uint64
	Seq uint64

	Src [16]uint8
	Dst [16]uint8

	Proto      uint8
	Action     uint8
	Ip_Version uint8
	Direction  uint8
	Pad        [4]byte
}

const (
	DirIngress uint8 = 0
	DirEgress  uint8 = 1
)

func ParseDirection(d uint8) string {
	if d == DirEgress {
		return "EGRESS"
	}
	return "INGRESS"
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
	default:
		return "OTHER"
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

type IpEntry struct {
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}
