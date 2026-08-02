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

		// Reports whether the stream is still alive: a failed write means the
		// client is gone, and there is no way to report that over the same
		// connection. A snapshot or encoding error only skips one tick.
		send := func() bool {
			snapshot, err := system.Snapshot()
			if err != nil {
				return true
			}

			b, err := json.Marshal(snapshot)
			if err != nil {
				return true
			}

			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}

		if !send() {
			return
		}

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if !send() {
					return
				}
			}
		}
	}
}
