package handlers

import (
	"encoding/json"
	"net/http"
	"ntc/source/domain/packet"
	"ntc/source/infrastructure/http/dto"
)

func IPHandler(
	add func(string) (packet.IPKey, error),
	remove func(string) (packet.IPKey, error),
	getAll func() ([]packet.IPEntry, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var req dto.IPRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			key, err := add(req.IP)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			_ = json.NewEncoder(w).Encode(dto.IPResponse{
				OK:      true,
				IP:      key.ToString(),
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
			_ = json.NewEncoder(w).Encode(dto.IPResponse{
				OK:      true,
				IP:      key.ToString(),
				Version: key.Version,
			})

		case http.MethodGet:
			list, err := getAll()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_ = json.NewEncoder(w).Encode(list)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
