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
		iface := cfg.Network.Interfaces[0]
		m, err := bpf.Load("tc_filter.bpf.o", iface, store)
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
				Time:      eventTime.Format("15:04:05.000"),
				Seq:       e.Seq,
				Src:       bpf.ParseIp(e.Src, e.Ip_Version),
				Dst:       bpf.ParseIp(e.Dst, e.Ip_Version),
				Proto:     model.ProtoString(e.Proto),
				Action:    model.ParseAction(e.Action).String(),
				Direction: model.ParseDirection(e.Direction),
			}

			j, err := json.Marshal(out)
			if err != nil {
				continue
			}

			sse.Broadcast(j)
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