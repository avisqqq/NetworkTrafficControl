package httpapi

import (
	"net/http"

	"client/internal/model"
)

type ListManager interface {
	AddToBlackList(ip string) (model.Ip_Key, error)
	RemoveFromBlackList(ip string) (model.Ip_Key, error)
	GetFromBlackList() ([]model.IpEntry, error)
	AddToWhiteList(ip string) (model.Ip_Key, error)
	RemoveFromWhiteList(ip string) (model.Ip_Key, error)
	GetFromWhiteList() ([]model.IpEntry, error)
}

func NewServer(addr string, mgr ListManager, sse *SSE) *http.Server {
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
