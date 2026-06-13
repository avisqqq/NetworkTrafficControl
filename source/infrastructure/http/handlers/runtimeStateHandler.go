package handlers

import (
	"encoding/json"
	"net/http"
)

func RuntimeStateHandler(mockMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			MockMode bool `json:"mockMode"`
		}{
			MockMode: mockMode,
		})
	}
}