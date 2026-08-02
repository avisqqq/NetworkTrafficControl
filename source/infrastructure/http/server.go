package http

import (
	"net/http"
	"time"

	"ntc/source/application/analytics"
	"ntc/source/application/inspection"
	"ntc/source/application/lists"
	"ntc/source/application/reports"
	appsystem "ntc/source/application/system"
	"ntc/source/infrastructure/http/handlers"
)

func NewServer(addr, webDir, iface, leaseFile string, mgr lists.ListManager, sse *SSE, metrics MetricsProvider, system *appsystem.Service, mockMode bool, appLogs handlers.AppLogProvider, logger APIErrorLogger, inspector *inspection.Service, analytics *analytics.Service, reports *reports.Service) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", sse.Handler)
	mux.HandleFunc("/blacklist", handlers.IPHandler(mgr.AddToBlackListByString, mgr.RemoveFromBlackListByString, mgr.GetFromBlackListByString))
	mux.HandleFunc("/whitelist", handlers.IPHandler(mgr.AddToWhiteListByString, mgr.RemoveFromWhiteListByString, mgr.GetFromWhiteListByString))
	mux.HandleFunc("/onlylocal", handlers.IPHandler(mgr.AddToOnlyLocalByString, mgr.RemoveFromOnlyLocalByString, mgr.GetFromOnlyLocalByString))

	mux.HandleFunc("/runtime/state", handlers.RuntimeStateHandler(mockMode))
	mux.HandleFunc("/network/devices", handlers.HostnameHandler(iface, leaseFile, mockMode, analytics))
	mux.HandleFunc("/network/localnets/v4", handlers.CidrHandler(mgr.AddToLocalNetsV4, mgr.RemoveFromLocalNetsV4, mgr.GetFromLocalNetsV4))
	mux.HandleFunc("/network/localnets/v6", handlers.CidrHandler(mgr.AddToLocalNetsV6, mgr.RemoveFromLocalNetsV6, mgr.GetFromLocalNetsV6))
	mux.HandleFunc("/metrics", metricsHandler(metrics))
	mux.HandleFunc("/app/logs", handlers.AppLogsHandler(appLogs))
	mux.HandleFunc("/packet/inspect", handlers.PacketInspectHandler(inspector))
	mux.HandleFunc("/analysis/summary", handlers.AnalysisSummaryHandler(analytics))
	mux.HandleFunc("/analysis/host", handlers.AnalysisHostHandler(analytics))
	mux.HandleFunc("/analysis/hosts", handlers.AnalysisHostsHandler(analytics))
	mux.HandleFunc("/analysis/export", handlers.AnalysisExportHandler(reports))
	mux.HandleFunc("/analysis/report", handlers.AnalysisReportHandler(reports))
	mux.HandleFunc("/system/events", handlers.SystemEventsHandler(system))
	mux.Handle("/", http.FileServer(http.Dir(webDir)))
	return &http.Server{
		Addr:              addr,
		Handler:           LoggingMiddleware(mux, logger),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
