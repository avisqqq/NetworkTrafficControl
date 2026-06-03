package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	domainsystem "ntc/source/domain/system"
)

type SystemSnapshotProvider interface {
	Snapshot() (domainsystem.Snapshot, error)
}

func SystemEventsHandler(system SystemSnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}

		send := func() {
			snapshot, err := system.Snapshot()
			if err != nil {
				return
			}

			b, err := json.Marshal(snapshot)
			if err != nil {
				return
			}

			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}

		send()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				send()
			}
		}
	}
}
