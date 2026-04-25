package httpapi

import (
	"encoding/json"
	"net/http"

	"client/internal/model"
)

func BlacklistHandler(mgr ListManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var req IpRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			key, err := mgr.AddToBlackList(req.IP)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(IpResponse{
				OK:      true,
				IP:      model.ParseIP(key),
				Version: key.Version,
			})

		case http.MethodDelete:
			ip := r.URL.Query().Get("ip")
			if ip == "" {
				http.Error(w, "missing ip", 400)
				return
			}
			key, err := mgr.RemoveFromBlackList(ip)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(IpResponse{
				OK: true,
				IP: model.ParseIP(key),
			})

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
