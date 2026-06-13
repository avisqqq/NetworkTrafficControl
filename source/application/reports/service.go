package reports

import (
	"context"
	"errors"
	"time"

	"ntc/source/application/analytics"
)

type Service struct {
	analytics AnalyticsProvider
	client    AIClient
	logger    Logger
	model     string
	maxRows   int
	now       func() time.Time
}

func NewService(analytics AnalyticsProvider, client AIClient, model string, maxRows int) *Service {
	if maxRows <= 0 {
		maxRows = 50
	}
	if maxRows > 100 {
		maxRows = 100
	}
	return &Service{
		analytics: analytics,
		client:    client,
		model:     model,
		maxRows:   maxRows,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) SetLogger(logger Logger) {
	s.logger = logger
}

func (s *Service) Export(hostIP string, limit int) (Export, error) {
	limit = s.normalizeLimit(limit)

	var summary analytics.Summary
	var err error

	scope := "global"
	if hostIP != "" {
		scope = "host"
		summary, err = s.analytics.HostSummary(hostIP, limit)
	} else {
		summary, err = s.analytics.Summary(limit)
	}
	if err != nil {
		return Export{}, err
	}
	return Export{
		GeneratedAt: s.now(),
		Scope:       scope,
		HostIP:      hostIP,
		Limit:       limit,
		Summary:     summary,
	}, nil
}

func (s *Service) Generate(ctx context.Context, hostIP string, limit int) (Report, error) {
	if s.client == nil {
		err := errors.New("local ai client is disabled")
		s.logFailed(ctx, hostIP, s.normalizeLimit(limit), err)
		return Report{}, err
	}

	input, err := s.Export(hostIP, limit)
	if err != nil {
		s.logFailed(ctx, hostIP, s.normalizeLimit(limit), err)
		return Report{}, err
	}

	if s.logger != nil {
		s.logger.AIReportRequested(ctx, input.HostIP, input.Limit, s.model)
	}

	started := time.Now()
	response, err := s.client.Generate(ctx, Prompt{
		Model: s.model,
		Input: input,
	})
	if err != nil {
		s.logFailed(ctx, input.HostIP, input.Limit, err)
		return Report{}, err
	}

	report := Report{
		GeneratedAt: s.now(),
		Model:       s.model,
		DurationMS:  time.Since(started).Milliseconds(),
		Input:       input,
		Report:      response,
	}
	if s.logger != nil {
		s.logger.AIReportSucceeded(ctx, report)
	}
	return report, nil
}

func (s *Service) logFailed(ctx context.Context, hostIP string, limit int, err error) {
	if s.logger == nil || err == nil {
		return
	}
	s.logger.AIReportFailed(ctx, hostIP, limit, s.model, err)
}

func (s *Service) normalizeLimit(limit int) int {
	if limit <= 0 {
		return s.maxRows
	}
	if limit > s.maxRows {
		return s.maxRows
	}
	return limit
}
