package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"unsafe" // for calculating event size

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	Ts    uint64
	Seq   uint64
	Src   uint32
	Dst   uint32
	Proto uint8
	Pad   [7]byte
}

func ipToString(v uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b).String()
}

func main() {
	fmt.Println(unsafe.Sizeof(Event{}))

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
		fmt.Println("raw:", hex.EncodeToString(record.RawSample))
		if err != nil {
			log.Fatal(err)
		}

		var e Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}

		fmt.Printf("seq=%d proto=%d src=%s dst=%s\n",
			e.Seq,
			e.Proto,
			ipToString(e.Src),
			ipToString(e.Dst),
		)
	}
}
