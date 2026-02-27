package httpapi

import (
	"net/http"

	"client/internal/bpf"
)

func NewServer(addr string, mgr *bpf.Manager, sse *SSE) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/blacklist", BlacklistHandler(mgr))

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}
