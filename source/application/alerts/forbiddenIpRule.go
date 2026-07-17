package alerts

import (
	"fmt"

	"ntc/source/domain/alert"
	"ntc/source/domain/packet"
)

type ForbiddenIpRule struct{}

func NewForbiddenIpRule() ForbiddenIpRule {
	return ForbiddenIpRule{}
}

func (ForbiddenIpRule) ID() string {
	return "blacklisted-ip"
}

func (ForbiddenIpRule) Type() string {
	return "forbidden-ip"
}

func (ForbiddenIpRule) Severity() alert.Saverity {
	return alert.SaverityCritical
}

func (ForbiddenIpRule) Evaluate(p packet.Packet) (Match, bool) {
	if packet.ParseAction(p.Action) != packet.ActDrop {
		return Match{}, false
	}
	src, dst := p.PacketIpsToString()
	return Match{
		Value: "src: " + src + "or" + "dst: " + dst,
		Message: fmt.Sprintf(
			"Traffic involving blacklisted ip was blocked: %s -> %s",
			src,
			dst,
		),
		DeduplicationKey: fmt.Sprintf(
			"blacklisted-ip:%s:%s",
			src,
			dst,
		),
	}, true
}
