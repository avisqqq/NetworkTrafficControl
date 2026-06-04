package main

import (
	"context"
	"flag"
	"log"
	"ntc/source/application/clock"
	"ntc/source/application/inspection"
	"ntc/source/application/lists"
	appLogService "ntc/source/application/logs"
	"ntc/source/application/mock"
	appNetwork "ntc/source/application/network"
	packetapp "ntc/source/application/packet"
	"ntc/source/application/packetstream"
	appsystem "ntc/source/application/system"
	"ntc/source/application/traffic"
	"ntc/source/config"
	infrageo "ntc/source/infrastructure/geo"
	infrahttp "ntc/source/infrastructure/http"
	infrapacket "ntc/source/infrastructure/packet"
	"ntc/source/infrastructure/persist"
	infraStorage "ntc/source/infrastructure/storage"
	infraLog "ntc/source/infrastructure/storage/gorm/repositories"
	infrasystem "ntc/source/infrastructure/system"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	mockMode := flag.Bool("mock", false, "run with synthetic packet generator (no eBPF required)")
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if len(cfg.Network.Interfaces) == 0 {
		log.Fatal("config: network.interfaces must contain at least one interface")
	}

	networkInterface := cfg.Network.Interfaces[0]
	leaseFile := cfg.Network.LeaseFile

	store, err := persist.New(cfg.Persistence.Path)
	if err != nil {
		log.Fatalf("persist: %v", err)
	}
	if err := store.SaveMockMode(*mockMode); err != nil {
		log.Printf("persist: save mock mode: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	appLogDb, err := infraStorage.Open(cfg.AppLogs.Path)
	if err != nil {
		log.Fatalf("app logs: %v", err)
	}
	appLogRepo := infraLog.NewAppLogRepository(appLogDb)
	appLog := appLogService.NewService(appLogRepo)
	appLog.ConfigLoaded(ctx)
	appLog.ServiceStarted(ctx)
	defer stop()

	var runtime *packetapp.Runtime
	if *mockMode {
		log.Println("main: starting in mock mode")
		localCIDRs, err := appNetwork.LocalCIDRs(cfg.Network.CIDRs, networkInterface)
		if err != nil {
			log.Printf("network: local cidrs unavailable in mock mode: %v", err)
		}
		manager := mock.NewManager(localCIDRs)
		lists.RestorePersistentLists(manager, store, appLog)
		runtime = &packetapp.Runtime{
			Reader: mock.NewReader(ctx, manager),
			Lists:  lists.NewLoggedListManager(lists.NewPersistentListManager(manager, store, appLog), appLog),
		}
	} else {
		loader := infrapacket.NewEbpfLoader()
		defer loader.Close()

		packetApp := packetapp.NewPacketApp(loader)
		runtime, err = packetApp.Start(ctx, "tc_filter.bpf.o", networkInterface, cfg.Network.CIDRs)
		if err != nil {
			log.Fatalf("main: start packet app: %v", err)
		}
		lists.RestorePersistentLists(runtime.Lists, store, appLog)
		runtime.Lists = lists.NewLoggedListManager(lists.NewPersistentListManager(runtime.Lists, store, appLog), appLog)
	}

	clk := clock.New(cfg.Server.Timezone)
	sse := infrahttp.NewSSE()
	sseConsumer := infrahttp.NewPacketSseConsumer(sse, clk)
	metricsService := traffic.NewService()
	metricsService.Start(ctx)
	systemService := appsystem.NewService(infrasystem.NewSystemCollector())
	var geoProvider inspection.GeoProvider
	if cfg.Geo.Enabled && cfg.Geo.Provider == "ip-api" {
		geoProvider = infrageo.NewIPAPIProvider(
			time.Duration(cfg.Geo.TimeoutSeconds)*time.Second,
			time.Duration(cfg.Geo.CacheTTLSeconds)*time.Second,
		)
	}
	inspectionService := inspection.NewService(geoProvider, appLog)
	dispatcher := packetstream.NewDispatcher(
		runtime.Reader,
		sseConsumer,
		metricsService,
	)
	dispatcher.Start(ctx)

	server := infrahttp.NewServer(cfg.ServerAddr(), "./dist", networkInterface, leaseFile, runtime.Lists, sse, metricsService, systemService, *mockMode, appLog, appLog, inspectionService)

	go func() {

		log.Printf("main: listening on %s", server.Addr)

		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("main: http server: %v", err)
		}
	}()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("main: shutdown server: %v", err)
	}
}
