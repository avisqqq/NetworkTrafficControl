package policy

import (
	"ntc/source/domain/packet"
)

type IpPortRuleKey struct {
	IP        packet.IPKey
	Pad       uint8
	Port      uint16
	Protocol  uint8
	Direction uint8
}
