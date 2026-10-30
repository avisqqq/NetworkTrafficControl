package http

import (
	"net/http"
	"sync"
	"time"
)

type SSE struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func NewSSE() *SSE {
	return &SSE{
		clients: make(map[chan []byte]struct{}),
	}
}

func (s *SSE) Broadcast(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- b:
		default:
		}
	}
}

func (s *SSE) Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", 500)
		return
	}

	ch := make(chan []byte, 128)

	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
		close(ch)
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			// One write per frame: a partial frame is not valid SSE, and it
			// gives the loop a single place to notice the client is gone.
			frame := make([]byte, 0, len("data: ")+len(b)+2)
			frame = append(frame, "data: "...)
			frame = append(frame, b...)
			frame = append(frame, '\n', '\n')
			if _, err := w.Write(frame); err != nil {
				// Nothing can be reported over a dead connection. Returning
				// drops the subscription now instead of writing into a broken
				// socket until the request context fires.
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
