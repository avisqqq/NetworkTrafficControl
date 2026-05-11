package http

import (
	"encoding/json"
	"net/http"

	"ntc/source/domain/packet"
)

func handler(
	add func(string) (packet.IPKey, error),
	remove func(string) (packet.IPKey, error),
	getAll func() ([]packet.IPEntry, error),
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
			json.NewEncoder(w).Encode(IpResponse{
				OK: true,
				IP: key.ToString(),
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

// func readOnlyListHandler[T any](getAll func() ([]T, error)) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method != http.MethodGet {
// 			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
// 			return
// 		}

// 		list, err := getAll()
// 		if err != nil {
// 			http.Error(w, err.Error(), http.StatusInternalServerError)
// 			return
// 		}

// 		json.NewEncoder(w).Encode(list)
// 	}
// }
