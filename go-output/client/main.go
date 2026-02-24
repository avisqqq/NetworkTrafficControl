package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	Ts    uint64
	Src   uint32
	Dst   uint32
	Proto uint8
}

func ipToString(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b).String()
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("xdp_ring.bpf.o")
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	iface, err := net.InterfaceByName("wlan0")
	if err != nil {
		log.Fatal(err)
	}

	prog := coll.Programs["xdp_basic"]

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lnk.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	fmt.Println("Listening...")

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatal(err)
		}

		var e Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}

		fmt.Printf("proto=%d src=%s dst=%s\n",
			e.Proto,
			ipToString(e.Src),
			ipToString(e.Dst),
		)
	}
}
