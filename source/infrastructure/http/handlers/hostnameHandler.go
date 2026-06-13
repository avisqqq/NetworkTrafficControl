package handlers

import (
	"encoding/json"
	"net/http"

	"ntc/source/application/network"
)

func HostnameHandler(iface, leaseFile string, mockMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if mockMode {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(network.MockDevices())
			return
		}

		devices, err := network.ReadDevices(iface, leaseFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(devices)
	}
}
