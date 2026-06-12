package reports

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"ntc/source/application/analytics"
)

type analyticsStub struct {
	summaryLimit     int
	hostSummaryIP    string
	hostSummaryLimit int
	err              error
}

func (s *analyticsStub) Summary(limit int) (analytics.Summary, error) {
	s.summaryLimit = limit
	return analytics.Summary{
		Totals: analytics.SummaryTotals{Packets: 10, Bytes: 1000},
	}, s.err
}

func (s *analyticsStub) HostSummary(ip string, limit int) (analytics.Summary, error) {
	s.hostSummaryIP = ip
	s.hostSummaryLimit = limit
	return analytics.Summary{
		Totals: analytics.SummaryTotals{Hosts: 1, Packets: 5, Bytes: 500},
	}, s.err
}

type aiStub struct {
	prompt Prompt
	err    error
}

func (s *aiStub) Generate(ctx context.Context, prompt Prompt) (json.RawMessage, error) {
	s.prompt = prompt
	return json.RawMessage(`{"summary":"ok"}`), s.err
}

type reportLoggerStub struct {
	requestedHostIP string
	requestedLimit  int
	requestedModel  string
	succeededReport Report
	failedHostIP    string
	failedLimit     int
	failedModel     string
	failedErr       error
}

func (s *reportLoggerStub) AIReportRequested(ctx context.Context, hostIP string, limit int, model string) {
	s.requestedHostIP = hostIP
	s.requestedLimit = limit
	s.requestedModel = model
}

func (s *reportLoggerStub) AIReportSucceeded(ctx context.Context, report Report) {
	s.succeededReport = report
}

func (s *reportLoggerStub) AIReportFailed(ctx context.Context, hostIP string, limit int, model string, err error) {
	s.failedHostIP = hostIP
	s.failedLimit = limit
	s.failedModel = model
	s.failedErr = err
}

func TestExportUsesGlobalSummaryAndClampsLimit(t *testing.T) {
	analytics := &analyticsStub{}
	service := NewService(analytics, nil, "model", 25)
	service.now = func() time.Time { return time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC) }

	export, err := service.Export("", 80)
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}

	if export.Scope != "global" {
		t.Fatalf("expected global scope, got %q", export.Scope)
	}
	if export.Limit != 25 {
		t.Fatalf("expected clamped export limit 25, got %d", export.Limit)
	}
	if analytics.summaryLimit != 25 {
		t.Fatalf("expected analytics limit 25, got %d", analytics.summaryLimit)
	}
	if export.Summary.Totals.Bytes != 1000 {
		t.Fatalf("expected summary totals to be exported")
	}
}

func TestExportUsesHostSummary(t *testing.T) {
	analytics := &analyticsStub{}
	service := NewService(analytics, nil, "model", 50)

	export, err := service.Export("192.168.0.10", 10)
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}

	if export.Scope != "host" {
		t.Fatalf("expected host scope, got %q", export.Scope)
	}
	if export.HostIP != "192.168.0.10" {
		t.Fatalf("expected host ip to be exported")
	}
	if analytics.hostSummaryIP != "192.168.0.10" || analytics.hostSummaryLimit != 10 {
		t.Fatalf("expected host summary lookup, got ip=%q limit=%d", analytics.hostSummaryIP, analytics.hostSummaryLimit)
	}
}

func TestGenerateReturnsDisabledErrorWithoutClient(t *testing.T) {
	service := NewService(&analyticsStub{}, nil, "model", 50)

	_, err := service.Generate(context.Background(), "", 10)
	if err == nil {
		t.Fatal("expected disabled error")
	}
}

func TestGenerateSendsExportToAIClient(t *testing.T) {
	ai := &aiStub{}
	service := NewService(&analyticsStub{}, ai, "qwen2.5:1.5b", 50)

	report, err := service.Generate(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if report.Model != "qwen2.5:1.5b" {
		t.Fatalf("expected model in report, got %q", report.Model)
	}
	if ai.prompt.Model != "qwen2.5:1.5b" {
		t.Fatalf("expected prompt model, got %q", ai.prompt.Model)
	}
	if ai.prompt.Input.Limit != 10 {
		t.Fatalf("expected prompt limit 10, got %d", ai.prompt.Input.Limit)
	}
	if string(report.Report) != `{"summary":"ok"}` {
		t.Fatalf("unexpected report body: %s", report.Report)
	}
}

func TestGenerateLogsAIReportLifecycle(t *testing.T) {
	ai := &aiStub{}
	logger := &reportLoggerStub{}
	service := NewService(&analyticsStub{}, ai, "qwen2.5:1.5b", 50)
	service.SetLogger(logger)

	report, err := service.Generate(context.Background(), "192.168.0.10", 10)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if logger.requestedHostIP != "192.168.0.10" || logger.requestedLimit != 10 || logger.requestedModel != "qwen2.5:1.5b" {
		t.Fatalf("unexpected request log: host=%q limit=%d model=%q", logger.requestedHostIP, logger.requestedLimit, logger.requestedModel)
	}
	if string(logger.succeededReport.Report) != `{"summary":"ok"}` {
		t.Fatalf("expected success log to include report response, got %s", logger.succeededReport.Report)
	}
	if logger.succeededReport.Input.HostIP != report.Input.HostIP {
		t.Fatalf("expected success log to receive generated report")
	}
}

func TestGenerateReturnsAIClientError(t *testing.T) {
	logger := &reportLoggerStub{}
	service := NewService(&analyticsStub{}, &aiStub{err: errors.New("ai unavailable")}, "model", 50)
	service.SetLogger(logger)

	_, err := service.Generate(context.Background(), "", 10)
	if err == nil {
		t.Fatal("expected ai client error")
	}
	if logger.failedErr == nil || logger.failedLimit != 10 || logger.failedModel != "model" {
		t.Fatalf("expected failed report log, got limit=%d model=%q err=%v", logger.failedLimit, logger.failedModel, logger.failedErr)
	}
}
