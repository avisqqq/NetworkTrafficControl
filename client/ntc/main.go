package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"client/httpapi"
	"client/internal/bpf"
	"client/internal/clock"
	"client/internal/mock"
	"client/internal/model"
)

func main() {
	mockMode := flag.Bool("mock", false, "run with synthetic packet generator (no eBPF required)")
	flag.Parse()

	clk := clock.New("Europe/Warsaw")

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	var mgr httpapi.ListManager
	var events <-chan model.Event

	if *mockMode {
		log.Println("Starting in mock mode — synthetic traffic generator active")
		m := mock.NewManager()
		mgr = m
		events = mock.GenerateEvents(ctx, m)
	} else {
		m, err := bpf.Load("xdp_ring.bpf.o", "wlan0")
		if err != nil {
			log.Fatal(err)
		}
		defer m.Close()
		mgr = m
		events = bpf.ReadEvents(ctx, m.Events)
	}

	sse := httpapi.NewSSE()

	go func() {
		for e := range events {
			eventTime := clk.FromTs(e.Ts)

			out := model.OutEvent{
				Time:   eventTime.Format("15:04:05.000"),
				Seq:    e.Seq,
				Src:    bpf.ParseIp(e.Src, e.Ip_Version),
				Dst:    bpf.ParseIp(e.Dst, e.Ip_Version),
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

	port := ":8086"
	srv := httpapi.NewServer(port, mgr, sse)

	go func() {
		log.Println("HTTP listening on" + port)
		if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = srv.Shutdown(shutdownCtx)
}