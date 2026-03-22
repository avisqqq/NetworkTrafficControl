package httpapi

import (
	"client/internal/bpf"
	"encoding/json"
	"net/http"
)

func BlacklistHandler(mgr *bpf.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var req BlacklistReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			if err := mgr.AddToBlackList(req.IP); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(BlacklistResp{OK: true, IP: req.IP})

		case http.MethodDelete:
			ip := r.URL.Query().Get("ip")
			if ip == "" {
				http.Error(w, "missing ip", 400)
				return
			}

			if err := mgr.RemoveFromBlackList(ip); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(BlacklistResp{OK: true, IP: ip})
		case http.MethodGet:
			list, err := mgr.GetFromBlackList()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(list)

		default:
			http.Error(w, "method not allowed", 405)
		}
	}
}
