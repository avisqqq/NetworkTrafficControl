package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"ntc/source/application/reports"
)

type ReportProvider interface {
	Export(hostIP string, limit int) (reports.Export, error)
	Generate(ctx context.Context, hostIP string, limit int) (reports.Report, error)
}

func AnalysisExportHandler(provider ReportProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		export, err := provider.Export(r.URL.Query().Get("ip"), parseLimit(r.URL.Query().Get("limit"), 50))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(export)
	}
}

func AnalysisReportHandler(provider ReportProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			IP    string `json:"ip"`
			Limit int    `json:"limit"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&request)
		}

		report, err := provider.Generate(r.Context(), request.IP, request.Limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	}
}

func parseLimit(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}
