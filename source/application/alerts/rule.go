package alerts

import (
	"ntc/source/domain/alert"
	"ntc/source/domain/packet"
)

type Match struct {
	Value            string
	Message          string
	DeduplicationKey string
}

type Rule interface {
	ID() string
	Type() string
	Severity() alert.Severity
	Evaluate(packet.Packet) (Match, bool)
}
