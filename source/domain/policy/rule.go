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
	if direction != packet.DirIngress && direction != packet.DirEgress {
		return Rule{}, fmt.Errorf("invalid policy direction: value = %q", direction)
	}

	return Rule{
		IP:        ip,
		Port:      port,
		Protocol:  protocol,
		Direction: direction,
	}, nil
}

// RuleFromStrings builds a Rule from the plain form used by the HTTP API and
// by persisted snapshots.
func RuleFromStrings(ip string, port uint16, protocol, direction string) (Rule, error) {
	ipKey, err := packet.IPKeyFromString(ip)
	if err != nil {
		return Rule{}, err
	}
	parsedProtocol, err := ProtocolFromString(protocol)
	if err != nil {
		return Rule{}, err
	}
	parsedDirection, err := packet.DirectionFromString(direction)
	if err != nil {
		return Rule{}, err
	}
	return NewRule(ipKey, port, parsedProtocol, parsedDirection)
}

func (r Rule) ToPolicyKey() IPPortRuleKey {
	return IPPortRuleKey{
		IP:        r.IP,
		Pad:       0,
		Port:      r.Port,
		Protocol:  uint8(r.Protocol),
		Direction: uint8(r.Direction),
	}
}

func (r Rule) ToString() string {
	return fmt.Sprintf(
		"%s:%d/%s->%s",
		r.IP.ToString(),
		r.Port,
		r.Protocol,
		r.Direction,
	)
}
