package main

import (
	"fmt"
	app "ntc/source/application/packet"
	"ntc/source/infrastructure/packet"
)

func main() {
	loader := packet.NewEbpfLoader()
	service := app.NewPacketApp(loader)
	if err := service.Start("tc_filter.bpf.o", "enp2s0"); err != nil {
		fmt.Printf("Main: %v", err)
	}
	fmt.Printf("%+v\n", loader) // print struct fields with names
}
