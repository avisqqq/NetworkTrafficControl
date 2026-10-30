package alerts

import (
	"fmt"

	"ntc/source/domain/alert"
	"ntc/source/domain/packet"
)

type ForbiddenIPRule struct{}

func NewForbiddenIPRule() ForbiddenIPRule {
	return ForbiddenIPRule{}
}

func (ForbiddenIPRule) ID() string {
	return "blacklisted-ip"
}

func (ForbiddenIPRule) Type() string {
	return "forbidden-ip"
}

func (ForbiddenIPRule) Severity() alert.Severity {
	return alert.SeverityCritical
}

func (ForbiddenIPRule) Evaluate(p packet.Packet) (Match, bool) {
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
