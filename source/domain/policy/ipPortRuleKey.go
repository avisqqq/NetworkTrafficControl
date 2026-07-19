package policy

import (
	"ntc/source/domain/packet"
)

type IpPortRuleKey struct {
	IP        packet.IPKey `json:"ip"`
	Pad       uint8
	Port      uint16 `json:"port"`
	Protocol  uint8  `json:"protocol"`
	Direction uint8  `json:"direction"`
}

func (r IpPortRuleKey) ToRule() Rule {
	return Rule{
		IP:        r.IP,
		Port:      r.Port,
		Protocol:  Protocol(r.Protocol),
		Direction: packet.Direction(r.Direction),
	}
}
