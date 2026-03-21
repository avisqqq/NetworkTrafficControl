package httpapi

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
			w.Write([]byte("data: "))
			w.Write(b)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-ticker.C:
			w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		}
	}
}
