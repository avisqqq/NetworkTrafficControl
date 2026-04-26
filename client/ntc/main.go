package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"client/httpapi"
	"client/internal/bpf"
	"client/internal/clock"
	"client/internal/config"
	"client/internal/mock"
	"client/internal/model"
	"client/internal/persist"
)

func main() {
	mockMode := flag.Bool("mock", false, "run with synthetic packet generator (no eBPF required)")
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	clk := clock.New(cfg.Server.Timezone)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	var mgr httpapi.ListManager
	var events <-chan model.Event
	ifaceName := "mock0"

	store, err := persist.New(cfg.Persistence.Path)
	if err != nil {
		log.Fatalf("persist: %v", err)
	}

	if *mockMode {
		log.Println("Starting in mock mode — synthetic traffic generator active")
		m := mock.NewManager(store)
		mgr = m
		events = mock.GenerateEvents(ctx, m)
	} else {
		if len(cfg.Network.Interfaces) == 0 {
			log.Fatal("config: network.interfaces must contain at least one interface")
		}
		ifaceName = cfg.Network.Interfaces[0]
		m, err := bpf.Load("tc_ring.bpf.o", ifaceName, store)
		if err != nil {
			log.Fatal(err)
		}
		defer m.Close()
		mgr = m
		events = bpf.ReadEvents(ctx, m.Events)
		ifaceName = m.Interface
	}

	sse := httpapi.NewSSE()

	go func() {
		for e := range events {
			eventTime := clk.FromTs(e.Ts)
			out := httpapi.NewEventDTO(e, ifaceName, eventTime)
			_ = sse.BroadcastJSON(out)
		}
	}()

	addr := cfg.ServerAddr()
	srv := httpapi.NewServer(addr, mgr, sse)

	go func() {
		log.Printf("HTTP listening on %s", addr)
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
