package handlers

import (
	"encoding/json"
	"net/http"

	"ntc/source/application/inspection"
)

func PacketInspectHandler(inspector *inspection.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req inspection.PacketRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inspector.InspectPacket(r.Context(), req))
	}
}
