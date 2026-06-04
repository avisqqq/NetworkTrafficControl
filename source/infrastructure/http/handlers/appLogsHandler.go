package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	applogs "ntc/source/application/logs"
	domain "ntc/source/domain/logs"
	"ntc/source/infrastructure/http/dto"
)

type AppLogProvider interface {
	Get(ctx context.Context, filter applogs.Filter) ([]domain.AppLog, error)
}

func AppLogsHandler(logs AppLogProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := 200
		if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
			parsed, err := strconv.Atoi(rawLimit)
			if err != nil {
				http.Error(w, "bad limit", http.StatusBadRequest)
				return
			}
			limit = parsed
		}

		rows, err := logs.Get(r.Context(), applogs.Filter{Limit: limit})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		response := make([]dto.AppLogResponse, 0, len(rows))
		for _, row := range rows {
			response = append(response, dto.AppLogResponse{
				ID:           row.ID,
				CreatedAt:    row.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Level:        string(row.Level),
				Category:     string(row.Category),
				Event:        string(row.Event),
				Message:      row.Message,
				EntityType:   string(row.EntityType),
				EntityID:     row.EntityID,
				Actor:        string(row.Actor),
				Source:       string(row.Source),
				MetadataJSON: row.MetadataJSON,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
