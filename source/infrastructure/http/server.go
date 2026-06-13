package http

import (
	"net/http"
	"time"

	"ntc/source/application/lists"
	"ntc/source/infrastructure/http/handlers"
)

func NewServer(addr, webDir, iface, leaseFile string, mgr lists.ListManager, sse *SSE, metrics MetricsProvider, mockMode bool) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/blacklist", handlers.IpHandler(mgr.AddToBlackListByString, mgr.RemoveFromBlackListByString, mgr.GetFromBlackListByString))
	mux.HandleFunc("/whitelist", handlers.IpHandler(mgr.AddToWhiteListByString, mgr.RemoveFromWhiteListByString, mgr.GetFromWhiteListByString))
	mux.HandleFunc("/onlylocal", handlers.IpHandler(mgr.AddToOnlyLocalByString, mgr.RemoveFromOnlyLocalByString, mgr.GetFromOnlyLocalByString))

	mux.HandleFunc("/runtime/state", handlers.RuntimeStateHandler(mockMode))
	mux.HandleFunc("/network/devices", handlers.HostnameHandler(iface, leaseFile, mockMode))
	mux.HandleFunc("/network/localnets/v4", handlers.CidrHandler(mgr.AddToLocalNetsV4, mgr.RemoveFromLocalNetsV4, mgr.GetFromLocalNetsV4))
	mux.HandleFunc("/network/localnets/v6", handlers.CidrHandler(mgr.AddToLocalNetsV6, mgr.RemoveFromLocalNetsV6, mgr.GetFromLocalNetsV6))
	mux.HandleFunc("/metrics", metricsHandler(metrics))
	mux.Handle("/", http.FileServer(http.Dir(webDir)))
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
