package alerts

// TODO: REWORK FOR NORMAL LogSystem
import (
	"context"
	"log"

	"ntc/source/domain/alert"
)

type LogSink struct{}

func (LogSink) CreateAlert(_ context.Context, candidate alert.Alert) error {
	log.Printf(
		"ALERT rule=%s, severity=%s, message=%q",
		candidate.RuleType,
		candidate.Severity,
		candidate.Message,
	)
	return nil
}
