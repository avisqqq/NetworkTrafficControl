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
	"client/internal/clock"
	"client/internal/model"
)

func main() {
	// Empty if UTC
	clk := clock.New("Europe/Warsaw")
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

	// SECOND INTERFACE

	// mgr2, err := bpf.Load("xdp_ring.bpf.o", "eth0")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer mgr2.Close()
	// --- Create SSE hub ---
	sse := httpapi.NewSSE()

	// --- Start ringbuf reader ---
	events := bpf.ReadEvents(ctx, mgr.Events)

	go func() {
		for e := range events {

			eventTime := clk.FromTs(e.Ts)

			out := model.OutEvent{
				Time:   eventTime.Format("15:04:05.000"),
				Seq:    e.Seq,
				Src:    bpf.Uint32ToIP(e.Src),
				Dst:    bpf.Uint32ToIP(e.Dst),
				Proto:  model.ProtoString(e.Proto),
				Action: model.ParseAction(e.Action).String(),
			}

			j, err := json.Marshal(out)
			if err != nil {
				continue
			}

			sse.Broadcast(j)
		}
	}()

	// events2 := bpf.ReadEvents(ctx, mgr2.Events)
	// go func() {
	// 	for e := range events2 {

	// 		out := model.OutEvent{
	// 			Ts:    e.Ts,
	// 			Seq:   e.Seq,
	// 			Src:   bpf.Uint32ToIP(e.Src),
	// 			Dst:   bpf.Uint32ToIP(e.Dst),
	// 			Proto: e.Proto,
	// 		}

	// 		j, err := json.Marshal(out)
	// 		if err != nil {
	// 			continue
	// 		}

	// 		sse.Broadcast(j)
	// 	}
	// }()

	port := ":8086"
	// --- Create HTTP server ---
	srv := httpapi.NewServer(port, mgr, sse)

	go func() {
		log.Println("HTTP listening on" + port)
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
