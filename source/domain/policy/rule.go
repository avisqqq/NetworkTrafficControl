package policy

import (
	"fmt"

	"ntc/source/domain/packet"
)

type Rule struct {
	IP        packet.IPKey
	Port      uint16
	Protocol  Protocol
	Direction packet.Direction
}

func NewRule(ip packet.IPKey,
	port uint16,
	protocol Protocol,
	direction packet.Direction,
) (Rule, error) {
	if port == 0 {
		return Rule{}, fmt.Errorf("port must be greater than 0: value = %q", port)
	}
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return Rule{}, fmt.Errorf("invalid policy protocol: value = %q", protocol)
	}

	return Rule{
		IP:        ip,
		Port:      port,
		Protocol:  protocol,
		Direction: direction,
	}, nil
}

func (r Rule) ToPolicyKey() IpPortRuleKey {
	return IpPortRuleKey{
		IP:        r.IP,
		Pad:       0,
		Port:      r.Port,
		Protocol:  uint8(r.Protocol),
		Direction: uint8(r.Direction),
	}
}
