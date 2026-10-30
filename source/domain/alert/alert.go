package alert

import (
	"time"

	"ntc/source/domain/packet"
)

type Severity string

const (
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Alert struct {
	ID               string
	RuleID           string
	RuleType         string
	Severity         Severity
	Message          string
	DeduplicationKey string
	TriggeredAt      time.Time
	Packet           packet.Packet
	MatchedValue     string
}
