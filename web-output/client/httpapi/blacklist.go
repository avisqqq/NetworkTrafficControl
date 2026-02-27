package httpapi

import (
	"encoding/json"
	"net/http"

	"client/internal/bpf"
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
		default:
			http.Error(w, "method not allowed", 405)
		}
	}
}
