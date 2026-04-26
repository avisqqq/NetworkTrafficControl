package httpapi

import (
	"encoding/json"
	"net/http"

	"client/internal/model"
)

func listHandler(
	add    func(string) (model.IPKey, error),
	remove func(string) (model.IPKey, error),
	getAll func() ([]model.IPEntry, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var req IpRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			key, err := add(req.IP)
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
			key, err := remove(ip)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(IpResponse{
				OK: true,
				IP: model.ParseIP(key),
			})

		case http.MethodGet:
			list, err := getAll()
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