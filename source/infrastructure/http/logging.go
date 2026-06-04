package http

import (
	"bytes"
	"context"
	"net/http"
	"strings"
)

type APIErrorLogger interface {
	APIError(ctx context.Context, method, path string, status int, message string)
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.body.Len() < 512 {
		remaining := 512 - r.body.Len()
		capture := data
		if len(capture) > remaining {
			capture = capture[:remaining]
		}
		r.body.Write(capture)
	}
	return r.ResponseWriter.Write(data)
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func LoggingMiddleware(next http.Handler, logger APIErrorLogger) http.Handler {
	if logger == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)

		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if status < http.StatusBadRequest {
			return
		}

		message := strings.TrimSpace(recorder.body.String())
		if message == "" {
			message = http.StatusText(status)
		}
		logger.APIError(r.Context(), r.Method, r.URL.Path, status, message)
	})
}
