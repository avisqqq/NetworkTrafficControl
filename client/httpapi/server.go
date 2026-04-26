package httpapi

import (
	"net/http"
	"time"

	"client/internal/model"
	"client/internal/stats"
)

type ListManager interface {
	AddToBlackList(ip string) (model.IPKey, error)
	RemoveFromBlackList(ip string) (model.IPKey, error)
	GetFromBlackList() ([]model.IPEntry, error)
	AddToWhiteList(ip string) (model.IPKey, error)
	RemoveFromWhiteList(ip string) (model.IPKey, error)
	GetFromWhiteList() ([]model.IPEntry, error)
}

func NewServer(addr, webDir string, mgr ListManager, sse *SSE, ipStats *stats.IPTracker) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/metrics", metricsHandler(ipStats))
	mux.HandleFunc("/blacklist", listHandler(mgr.AddToBlackList, mgr.RemoveFromBlackList, mgr.GetFromBlackList))
	mux.HandleFunc("/whitelist", listHandler(mgr.AddToWhiteList, mgr.RemoveFromWhiteList, mgr.GetFromWhiteList))
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}