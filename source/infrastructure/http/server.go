package http

import (
	"net/http"
	"time"

	"ntc/source/application/lists"
)

func NewServer(addr, webDir string, mgr lists.ListManager, sse *SSE, metrics MetricsProvider) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/blacklist", handler(mgr.AddToBlackListByString, mgr.RemoveFromBlackListByString, mgr.GetFromBlackListByString))
	mux.HandleFunc("/whitelist", handler(mgr.AddToWhiteListByString, mgr.RemoveFromWhiteListByString, mgr.GetFromWhiteListByString))
	mux.HandleFunc("/metrics",metricsHandler(metrics))
	mux.Handle("/", http.FileServer(http.Dir(webDir)))
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
