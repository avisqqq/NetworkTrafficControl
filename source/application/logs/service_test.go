package logs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"ntc/source/application/reports"
	domain "ntc/source/domain/logs"
)

type repoStub struct {
	logs []domain.AppLog
}

func (r *repoStub) Add(ctx context.Context, log domain.AppLog) (domain.AppLog, error) {
	r.logs = append(r.logs, log)
	return log, nil
}

func (r *repoStub) Get(ctx context.Context, filter Filter) ([]domain.AppLog, error) {
	return r.logs, nil
}

func TestAIReportSucceededStoresResponseMetadata(t *testing.T) {
	repo := &repoStub{}
	service := NewService(repo)

	service.AIReportSucceeded(context.Background(), reports.Report{
		GeneratedAt: time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
		Model:       "qwen2.5:1.5b",
		DurationMS:  123,
		Input: reports.Export{
			Scope:  "host",
			HostIP: "192.168.50.4",
			Limit:  5,
		},
		Report: json.RawMessage(`{"summary":"ok","risk_level":"low"}`),
	})

	if len(repo.logs) != 1 {
		t.Fatalf("expected one log row, got %d", len(repo.logs))
	}
	row := repo.logs[0]
	if row.Category != domain.CategoryAI || row.Event != domain.EventAIReportSucceeded {
		t.Fatalf("unexpected log category/event: %s %s", row.Category, row.Event)
	}

	var metadata struct {
		HostIP     string          `json:"host_ip"`
		Model      string          `json:"model"`
		DurationMS int64           `json:"duration_ms"`
		Response   json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal([]byte(row.MetadataJSON), &metadata); err != nil {
		t.Fatalf("metadata is not valid json: %v", err)
	}
	if metadata.HostIP != "192.168.50.4" || metadata.Model != "qwen2.5:1.5b" || metadata.DurationMS != 123 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if string(metadata.Response) != `{"summary":"ok","risk_level":"low"}` {
		t.Fatalf("expected AI response in metadata, got %s", metadata.Response)
	}
}
