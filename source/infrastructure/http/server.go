package http

import (
	"net/http"
	"ntc/source/application/lists"
	"time"
)

func NewServer(addr string, mgr lists.ListManager, sse *SSE) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/blacklist", handler(mgr.AddToBlackListByString, mgr.RemoveFromBlackListByString, mgr.GetFromBlackListByString))
	mux.HandleFunc("/whitelist", handler(mgr.AddToWhiteListByString, mgr.RemoveFromWhiteListByString, mgr.GetFromWhiteListByString))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
