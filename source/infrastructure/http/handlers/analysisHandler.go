package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ntc/source/application/analytics"
)

type AnalyticsSummaryProvider interface {
	Summary(limit int) (analytics.Summary, error)
	HostSummary(ip string, limit int) (analytics.Summary, error)
	KnownHosts() ([]analytics.KnownHost, error)
}

func AnalysisSummaryHandler(provider AnalyticsSummaryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
			}
		}

		summary, err := provider.Summary(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}
}

func AnalysisHostHandler(provider AnalyticsSummaryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "missing ip", http.StatusBadRequest)
			return
		}

		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
			}
		}

		summary, err := provider.HostSummary(ip, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}
}

func AnalysisHostsHandler(provider AnalyticsSummaryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		hosts, err := provider.KnownHosts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(hosts)
	}
}
