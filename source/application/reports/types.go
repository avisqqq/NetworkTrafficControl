package reports

import (
	"context"
	"encoding/json"
	"time"

	"ntc/source/application/analytics"
)

type AnalyticsProvider interface {
	Summary(limit int) (analytics.Summary, error)
	HostSummary(ip string, limit int) (analytics.Summary, error)
}

type AIClient interface {
	Generate(ctx context.Context, prompt Prompt) (json.RawMessage, error)
}

type Logger interface {
	AIReportRequested(ctx context.Context, hostIP string, limit int, model string)
	AIReportSucceeded(ctx context.Context, report Report)
	AIReportFailed(ctx context.Context, hostIP string, limit int, model string, err error)
}

type Export struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Scope       string            `json:"scope"`
	HostIP      string            `json:"host_ip,omitempty"`
	Limit       int               `json:"limit"`
	Summary     analytics.Summary `json:"summary"`
}

type Prompt struct {
	Model string `json:"model"`
	Input Export `json:"input"`
}

type Report struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Model       string          `json:"model"`
	DurationMS  int64           `json:"duration_ms"`
	Input       Export          `json:"input"`
	Report      json.RawMessage `json:"report"`
}
