package httpapi

import (
	"net/http"

	"client/internal/bpf"
)

func NewServer(addr string, mgr *bpf.Manager, sse *SSE) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/blacklist", BlacklistHandler(mgr))
	mux.HandleFunc("/whitelist", WhitelistHandler(mgr))
	fs := http.FileServer(http.Dir("./web"))
	mux.Handle("/", fs)

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}
