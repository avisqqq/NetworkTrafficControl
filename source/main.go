package main

import (
	"context"
	"log"
	packetapp "ntc/source/application/packet"
	infrahttp "ntc/source/infrastructure/http"
	infrapacket "ntc/source/infrastructure/packet"
	"ntc/source/application/traffic"
	"ntc/source/application/packetstream"
	"ntc/source/application/clock"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var networkInterface = "wlan0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loader := infrapacket.NewEbpfLoader()
	defer loader.Close()

	packetApp := packetapp.NewPacketApp(loader)
	runtime, err := packetApp.Start(ctx, "tc_filter.bpf.o", networkInterface)
	if err != nil {
		log.Fatalf("main: start packet app: %v", err)
	}
	clk := clock.New("Europe/Warsaw")
	sse := infrahttp.NewSSE()
	sseConsumer := infrahttp.NewPacketSseConsumer(sse, clk)
	metricsService := traffic.NewService()
	metricsService.Start(ctx)
	dispatcher := packetstream.NewDispatcher(
		runtime.Reader, 
		sseConsumer,
		metricsService,
	)
	dispatcher.Start(ctx)

	server := infrahttp.NewServer(":8086","./dist", runtime.Lists, sse, metricsService) // TODO: create consuming system and metric service

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
