package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

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
type OutEvent struct {
	Ts    uint64 `json:"ts"`
	Seq   uint64 `json:"seq"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto uint8  `json:"proto"`
}

func ipToString(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid ipv4")
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func addToBlackList(m *ebpf.Map, ipStr string) error {
	key, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}
	val := uint8(1)
	return m.Put(key, val)
}

func main() {
	// TEST

	// BPF LOAD
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
	// Add BlackList
	blacklistMap := coll.Maps["blacklist"]
	macIP := "192.168.50.73"
	err = addToBlackList(blacklistMap, macIP)
	if err != nil {
		log.Printf("blackList error: ", err)
	}

	// SSE pubsub
	var (
		mu      sync.Mutex
		clients = map[chan []byte]struct{}{}
	)

	broadcast := func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		for ch := range clients {
			select {
			case ch <- b:
			default:
				// drop live update
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rec, err := rd.Read()
			fmt.Printf("raw: ", rec)
			if err != nil {
				return
			}
			var e Event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}
			out := OutEvent{
				Ts:    e.Ts,
				Seq:   e.Seq,
				Src:   ipToString(e.Src),
				Dst:   ipToString(e.Dst),
				Proto: e.Proto,
			}

			j, err := json.Marshal(out)
			if err != nil {
				continue
			}
			broadcast(j)
		}
	}()

	// HTTP
	mux := http.NewServeMux()
	webDir := "web"
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		ch := make(chan []byte, 128)
		mu.Lock()
		clients[ch] = struct{}{}
		mu.Unlock()
		defer func() {
			mu.Lock()
			delete(clients, ch)
			mu.Unlock()
			close(ch)
		}()

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case b := <-ch:
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(b)
				_, _ = w.Write([]byte("\n\n"))
				flusher.Flush()
			case <-ticker.C:
				_, _ = w.Write([]byte(": ping\n\n"))
				flusher.Flush()
			}
		}
	})

	srv := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: logRequest(mux),
	}

	// shutdown
	go func() {
		sigch := make(chan os.Signal, 2)
		signal.Notify(sigch, os.Interrupt, syscall.SIGTERM)
		<-sigch
		cancel()
		_ = srv.Shutdown(context.Background())
	}()

	abs, _ := filepath.Abs(webDir)
	log.Printf("Web: http://0.0.0.0:8080/ (servering %s)\n", abs)
	log.Printf("SSE: http://0.0.0.0:8080/events\n")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
