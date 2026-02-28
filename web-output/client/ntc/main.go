package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"client/httpapi"
	"client/internal/bpf"
	"client/internal/model"
)

func main() {
	// Graceful shutdown context
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	// --- Load BPF + attach XDP ---
	mgr, err := bpf.Load("xdp_ring.bpf.o", "wlan0")
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Close()

	// --- Create SSE hub ---
	sse := httpapi.NewSSE()

	// --- Start ringbuf reader ---
	events := bpf.ReadEvents(ctx, mgr.Events)

	go func() {
		for e := range events {

			out := model.OutEvent{
				Ts:    e.Ts,
				Seq:   e.Seq,
				Src:   bpf.Uint32ToIP(e.Src),
				Dst:   bpf.Uint32ToIP(e.Dst),
				Proto: e.Proto,
			}

			j, err := json.Marshal(out)
			if err != nil {
				continue
			}

			sse.Broadcast(j)
		}
	}()

	// --- Create HTTP server ---
	srv := httpapi.NewServer(":8080", mgr, sse)

	go func() {
		log.Println("HTTP listening on :8080")
		if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			log.Fatal(err)
		}
	}()

	// --- Wait for shutdown ---
	<-ctx.Done()
	log.Println("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = srv.Shutdown(shutdownCtx)

	mgr.Close() // ← this is required

	return
}
