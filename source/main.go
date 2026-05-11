package main

import (
	"log"
	"ntc/source/application/lists"
	packetapp "ntc/source/application/packet"
	infrahttp "ntc/source/infrastructure/http"
	infrapacket "ntc/source/infrastructure/packet"
)

func main() {
	loader := infrapacket.NewEbpfLoader()
	defer loader.Close()

	service := packetapp.NewPacketApp(loader)
	if err := service.Start("tc_filter.bpf.o", "enp2s0"); err != nil {
		log.Fatalf("main: start packet app: %v", err)
	}

	ipFilter := loader.NewIpFilter()
	listService := lists.NewListService(ipFilter)

	server := infrahttp.NewServer(":8080", listService)
	log.Printf("main: listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("main: http server: %v", err)
	}
}
