package handlers

import (
	"encoding/json"
	"net/http"

	"ntc/source/domain/network"
	"ntc/source/infrastructure/http/dto"
)

func CidrHandler(
	add func(string) (network.CIDR, error),
	remove func(string) (network.CIDR, error),
	getAll func() ([]network.CIDREntry, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var req dto.CidrRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			key, err := add(req.CIDR)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(dto.CidrResponse{
				OK:      true,
				CIDR:    key.ToString(),
				PrefixLen: key.PrefixLen,
				Version: key.Version,
			})

		case http.MethodDelete:
			cidr := r.URL.Query().Get("cidr")
			if cidr == "" {
				http.Error(w, "missing cidr", 400)
				return
			}
			key, err := remove(cidr)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(dto.CidrResponse{
				OK:      true,
				CIDR:    key.ToString(),
				PrefixLen: key.PrefixLen,
				Version: key.Version,
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
