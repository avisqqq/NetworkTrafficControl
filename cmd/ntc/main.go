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

	"ntc/internal/api"
	"ntc/internal/bpf"
	"ntc/internal/clock"
	"ntc/internal/config"
	"ntc/internal/flow"
	"ntc/internal/mock"
	"ntc/internal/model"
	"ntc/internal/persist"
	"ntc/internal/stats"
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

	var mgr api.ListManager
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
		events = m.ReadEvents(ctx)
	}

	sse      := api.NewSSE()
	tracker  := flow.NewTracker()
	ipStats  := stats.NewIPTracker()

	// Consume raw packets: update flow table + IP stats, forward to SSE for live view.
	go func() {
		flushTicker := time.NewTicker(5 * time.Second)
		evictTicker := time.NewTicker(2 * time.Minute)
		defer flushTicker.Stop()
		defer evictTicker.Stop()

		for {
			select {
			case e, ok := <-events:
				if !ok {
					return
				}
				tracker.Update(e)

				srcIP := bpf.ParseIp(e.Src, e.IPVersion)
				ipStats.Update(srcIP, e)

				eventTime := clk.FromTs(e.Ts)
				out := model.OutEvent{
					Time:      eventTime.Format("15:04:05.000"),
					Seq:       e.Seq,
					Src:       srcIP,
					Dst:       bpf.ParseIp(e.Dst, e.IPVersion),
					Proto:     model.ProtoString(e.Proto),
					Action:    model.ParseAction(e.Action).String(),
					Direction: model.ParseDirection(e.Direction),
				}
				if j, err := json.Marshal(out); err == nil {
					sse.Broadcast(j)
				}

			case <-flushTicker.C:
				tracker.Flush()
				ipStats.SetActiveFlows(tracker.ActiveCount())

			case <-evictTicker.C:
				ipStats.Evict()
			}
		}
	}()

	// Log closed flows — placeholder for SQLite export.
	go func() {
		for f := range tracker.Flows() {
			log.Printf("flow closed: %s:%d → %s:%d proto=%d pkts=%d bytes=%d",
				bpf.ParseIp(f.Src, f.IPVersion), f.SrcPort,
				bpf.ParseIp(f.Dst, f.IPVersion), f.DstPort,
				f.Proto, f.PktCount, f.ByteCount,
			)
		}
	}()

	addr := cfg.ServerAddr()
	srv := api.NewServer(addr, "./dist", mgr, sse, ipStats)

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