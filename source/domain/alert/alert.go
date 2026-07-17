package alert

import (
	"time"

	"ntc/source/domain/packet"
)

type Saverity string

const (
	SaverityWarning  Saverity = "warning"
	SaverityCritical Saverity = "critical"
)

type Alert struct {
	ID               string
	RuleID           string
	RuleType         string
	Saverity         Saverity
	Message          string
	DeduplicationKey string
	TriggeredAt      time.Time
	Packet           packet.Packet
	MatchedValue     string
}
