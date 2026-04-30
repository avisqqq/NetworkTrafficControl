package api

import (
	"encoding/json"
	"net/http"
	"time"

	"ntc/internal/model"
	"ntc/internal/stats"
)

type ListManager interface {
	AddToBlackList(ip string) (model.IPKey, error)
	RemoveFromBlackList(ip string) (model.IPKey, error)
	GetFromBlackList() ([]model.IPEntry, error)
	AddToWhiteList(ip string) (model.IPKey, error)
	RemoveFromWhiteList(ip string) (model.IPKey, error)
	GetFromWhiteList() ([]model.IPEntry, error)
	AddToOnlyLocalList(ip string) (model.IPKey, error)
	RemoveFromOnlyLocalList(ip string) (model.IPKey, error)
	GetFromOnlyLocalList() ([]model.IPEntry, error)
	GetLocalNetsV4() ([]model.CIDREntry, error)
	GetLocalNetsV6() ([]model.CIDREntry, error)
}

func NewServer(addr, webDir, iface, path string, mockMode bool, mgr ListManager, sse *SSE, ipStats *stats.IPTracker) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/runtime/state", runtimeStateHandler(mockMode))
	mux.HandleFunc("/network/devices", networkDevicesHandler(iface, path))
	mux.HandleFunc("/network/localnets/v4", readOnlyListHandler(mgr.GetLocalNetsV4))
	mux.HandleFunc("/network/localnets/v6", readOnlyListHandler(mgr.GetLocalNetsV6))
	mux.HandleFunc("/metrics", metricsHandler(ipStats))
	mux.HandleFunc("/blacklist", listHandler(mgr.AddToBlackList, mgr.RemoveFromBlackList, mgr.GetFromBlackList))
	mux.HandleFunc("/whitelist", listHandler(mgr.AddToWhiteList, mgr.RemoveFromWhiteList, mgr.GetFromWhiteList))
	mux.HandleFunc("/onlylocal", listHandler(mgr.AddToOnlyLocalList, mgr.RemoveFromOnlyLocalList, mgr.GetFromOnlyLocalList))
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func runtimeStateHandler(mockMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			MockMode bool `json:"mockMode"`
		}{
			MockMode: mockMode,
		})
	}
}
