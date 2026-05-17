package main

import (
	"context"
	"log"
	packetapp "ntc/source/application/packet"
	infrahttp "ntc/source/infrastructure/http"
	infrapacket "ntc/source/infrastructure/packet"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loader := infrapacket.NewEbpfLoader()
	defer loader.Close()

	packetApp := packetapp.NewPacketApp(loader)
	runtime, err := packetApp.Start(ctx, "tc_filter.bpf.o", "enp2s0")
	if err != nil {
		log.Fatalf("main: start packet app: %v", err)
	}
	sse := infrahttp.NewSSE()
	infrahttp.StreamPackets(ctx, runtime.Reader, sse)

	server := infrahttp.NewServer(":8080", runtime.Lists, sse)

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
