# Architecture Decisions & R&D Wnioski

## 1. Problem z obecnym podejściem (packet-per-event)

Obecna architektura wysyła jeden SSE event per pakiet. Przy dużym ruchu:
- Memory exhaustion — kolejka SSE rośnie szybciej niż klient odbiera
- RPi ma ograniczone RAM (512MB–4GB) — przy 100k pkt/s to kwestia sekund
- Brak możliwości detekcji ataków — nie ma agregacji, tylko surowe pakiety

---

## 2. Decyzja: przejście na Flow-based model

**Zamiast:** stream pakietów → SSE → frontend

**Docelowo:** pakiety → Flow Tracker → agregacja → SSE (stats + alerty) → frontend

### Co to jest flow

Flow = unikalna 5-tuple: `(src_ip, dst_ip, src_port, dst_port, proto)`

Każdy pakiet **aktualizuje** istniejący flow zamiast tworzyć nowy event.
Flow jest zamykany gdy:
- Minął idle timeout (np. 30s bez pakietu)
- Pobaczono TCP FIN/RST
- Wymuszony flush (np. co 60s)

**Efekt:** 10 000 pkt/s z 50 aktywnych połączeń → 50 rekordów/30s zamiast 300 000 events/30s.

---

## 3. Decyzja: XDP → TC eBPF

### Dlaczego XDP jest niewystarczający

| Problem | Szczegół |
|---|---|
| Tylko ingress | XDP nie widzi ruchu wychodzącego — nie można blokować egress |
| Brak native XDP na WiFi | `wlan0` na RPi wpada w generic XDP (wolniejszy, traci główną zaletę) |
| Brak conntrack | Nie można rozróżnić nowych połączeń od established |
| Ubogi kontekst | Tylko surowe bajty — brak metadanych kernelowych |

### Dlaczego TC eBPF jest lepszy dla NTC

| Zaleta | Szczegół |
|---|---|
| Ingress + Egress | Pełna kontrola ruchu w obu kierunkach |
| Działa na WiFi | Natywnie na wszystkich typach interfejsów |
| `struct __sk_buff` | Bogaty kontekst: długość, protokół, mark, priority |
| Conntrack | `bpf_skb_ct_lookup()` — dostęp do stanu TCP połączenia |
| Modyfikacja pakietów | Pełna — checksum, nagłówki, bajty |

### Zmiana w kodzie Go

```go
// Teraz (XDP)
link.AttachXDP(link.XDPOptions{...})  // tylko ingress

// Docelowo (TC)
link.AttachTCX(link.TCXOptions{
    Interface: iface.Index,
    Attach:    ebpf.AttachTCXIngress,
    Program:   ingressProg,
})
link.AttachTCX(link.TCXOptions{
    Interface: iface.Index,
    Attach:    ebpf.AttachTCXEgress,
    Program:   egressProg,
})
```

### Zmiana w programie C

```c
// Teraz
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { ... }
// akcje: XDP_DROP, XDP_PASS

// Docelowo
SEC("tc")
int tc_prog(struct __sk_buff *skb) { ... }
// akcje: TC_ACT_SHOT, TC_ACT_OK
```

---

## 4. Conntrack — nowe połączenia vs established

Kernel śledzi stan każdego połączenia TCP:
- `NEW` — pierwszy pakiet, połączenie nieznane
- `ESTABLISHED` — handshake zakończony, ruch dwukierunkowy
- `RELATED` — powiązane (np. FTP data)
- `INVALID` — pakiet nie pasuje do żadnego stanu

### Dlaczego to ważne

Bez conntrack (stateless) — blokujesz 1.2.3.4:
```
→ SYN z 1.2.3.4   → DROP ✓
← własna odpowiedź → DROP ✗  (blokujesz własny ruch!)
```

Z conntrack (stateful):
```
→ SYN z 1.2.3.4   → NEW   → DROP ✓
← SYN+ACK (Ty)    → NEW   → PASS ✓
← dane established → PASS ✓
```

### Praktyczne zastosowanie w NTC

```
Wykryto port scan z 5.6.7.8 → dynamicznie dodaj do blacklisty
→ TC egress widzi pakiet DO 5.6.7.8 → NEW → DROP
  (blokujesz własne odpowiedzi — atakujący nie wie czy port jest otwarty)
```

---

## 5. Brakujące dane w struct event

Żeby wykrywać ataki, eBPF struct musi zawierać:

```c
struct event {
    __u64  ts;
    __u32  seq;
    __u8   src[16];
    __u8   dst[16];
    __u16  src_port;    // BRAKUJE — wymagane do port scan detekcji
    __u16  dst_port;    // BRAKUJE
    __u16  pkt_size;    // BRAKUJE — wymagane do amplification detekcji
    __u8   tcp_flags;   // BRAKUJE — SYN/ACK/RST/FIN, wymagane do SYN flood
    __u8   ip_version;
    __u8   proto;
    __u8   action;
    __u8   direction;   // BRAKUJE — ingress/egress
};
```

---

## 6. Jakie ataki wykrywamy i jak

| Atak | Sygnał detekcji | Potrzebne dane |
|---|---|---|
| SYN flood | Masa SYN bez ACK do jednego dst | tcp_flags, dst_ip, okno czasowe |
| UDP flood | Masowy UDP do jednego dst | proto, dst_ip, pkt_count/s |
| ICMP flood | Masowy ICMP | proto, dst_ip, pkt_count/s |
| DNS amplification | Duże odpowiedzi UDP/53 wychodzące | dst_port=53, direction, pkt_size |
| Vertical port scan | Jeden src → wiele portów tego samego dst | src_ip, dst_ip, unikalne dst_port |
| Horizontal scan | Jeden src → wiele IP na tym samym porcie | src_ip, unikalne dst_ip, dst_port |
| SYN scan (half-open) | Wysoki SYN/RST ratio, brak handshake | tcp_flags per flow |
| Brute force | Wiele połączeń src→dst:port | (src, dst, dst_port), count |
| Exfiltration | Asymetryczny flow — dużo danych wychodzi | direction, byte_count per flow |

---

## 7. Docelowa architektura systemu

```
┌─────────────────────────────────────────────┐
│  KERNEL SPACE (TC eBPF)                     │
│                                             │
│  Per-pakiet: ts, src, dst, ports,           │
│  tcp_flags, size, direction                 │
│                                             │
│  Ring buffer → minimalny struct             │
└───────────────────┬─────────────────────────┘
                    │ ~wszystkie pakiety
                    ▼
┌─────────────────────────────────────────────┐
│  GO USERSPACE — Flow Tracker                │
│                                             │
│  FlowTable: map[FlowKey]*FlowRecord         │
│  - aktualizuje flow per pakiet              │
│  - zamknięte flows → FlowExporter           │
│                                             │
│  IPStats: map[IP]*SlidingWindow             │
│  - 60 bucketów × 1s                        │
│  - pkt/s, bytes/s, unikalne dst_ports,     │
│    unikalne src_ips, SYN/ACK ratio         │
└───────┬──────────────────┬──────────────────┘
        │ flows (co 5s)    │ stats (co 1s)
        ▼                  ▼
┌───────────────┐  ┌───────────────────────────┐
│  SQLite       │  │  Anomaly Detector         │
│               │  │                           │
│  flows        │  │  Reguły (konfigurowalnie  │
│  ip_stats     │  │  przez YAML):             │
│  alerts       │  │  - ddos_detector          │
└───────────────┘  │  - port_scan_detector     │
                   │  - syn_flood_detector     │
                   │  - brute_force_detector   │
                   └─────────────┬─────────────┘
                                 │ alerts
                                 ▼
                   ┌─────────────────────────────┐
                   │  SSE Broadcaster            │
                   │                             │
                   │  Wysyła:                    │
                   │  - stats_tick (co 1s)       │
                   │  - flow_event (nowy flow)   │
                   │  - alert (detekcja)         │
                   │                             │
                   │  NIE wysyła surowych pkt    │
                   └─────────────────────────────┘
```

---

## 8. Struktury danych Go

```go
type FlowKey struct {
    Src     [16]byte
    Dst     [16]byte
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}

type FlowRecord struct {
    FirstSeen time.Time
    LastSeen  time.Time
    PktCount  uint64
    ByteCount uint64
    TCPFlags  uint8  // bitwise OR wszystkich widzianych flag
    Direction uint8  // ingress / egress
}

// Per-IP sliding window — 60 bucketów × 1s
type IPWindow struct {
    mu         sync.Mutex
    Pkts       [60]uint32
    Bytes      [60]uint32
    DstPorts   map[uint16]struct{}   // reset co minutę
    UniqueSrcs map[[16]byte]struct{} // dla DDoS dst
    SynCount   uint32
    AckCount   uint32
    cursor     int
    lastRotate time.Time
}
```

---

## 9. SQLite schema

```sql
CREATE TABLE flows (
    id         INTEGER PRIMARY KEY,
    ts_start   INTEGER NOT NULL,
    ts_end     INTEGER NOT NULL,
    src        TEXT NOT NULL,
    dst        TEXT NOT NULL,
    src_port   INTEGER,
    dst_port   INTEGER,
    proto      INTEGER,
    pkt_count  INTEGER,
    byte_count INTEGER,
    tcp_flags  INTEGER,
    direction  INTEGER,
    action     INTEGER
);
CREATE INDEX idx_flows_ts  ON flows(ts_start);
CREATE INDEX idx_flows_src ON flows(src);
CREATE INDEX idx_flows_dst ON flows(dst);

CREATE TABLE ip_stats (
    ts        INTEGER NOT NULL,
    ip        TEXT NOT NULL,
    direction TEXT NOT NULL,
    pkts      INTEGER,
    bytes     INTEGER,
    PRIMARY KEY (ts, ip, direction)
);

CREATE TABLE alerts (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    type    TEXT NOT NULL,   -- ddos | port_scan | syn_flood | brute_force
    src     TEXT,
    dst     TEXT,
    detail  TEXT             -- JSON z dodatkowymi danymi
);
```

---

## 10. Format SSE events (docelowy)

```json
// stats_tick (co 1s) — zamiast surowych pakietów
{
  "type": "stats_tick",
  "ts": 1714000000,
  "total_pkts_per_sec": 1250,
  "total_bytes_per_sec": 890000,
  "top_talkers": [
    {"ip": "192.168.1.10", "pkts": 800, "bytes": 600000}
  ]
}

// alert
{
  "type": "alert",
  "ts": 1714000005,
  "alert_type": "port_scan",
  "src": "192.168.1.99",
  "dst": "192.168.1.1",
  "detail": {"unique_ports": 234, "window_sec": 60}
}

// flow_event
{
  "type": "flow_new",
  "src": "192.168.1.10", "src_port": 54321,
  "dst": "8.8.8.8",      "dst_port": 53,
  "proto": "UDP"
}
```

---

## 11. Priorytet implementacji

| Krok | Co | Dlaczego priorytet |
|---|---|---|
| 1 | Rozszerzyć eBPF struct (porty, tcp_flags, pkt_size, direction) | Fundament — bez tego nic nie działa |
| 2 | Migracja XDP → TC eBPF | Odblokowuje egress + WiFi + conntrack |
| 3 | Flow Tracker w Go | Eliminuje problem pamięci |
| 4 | SQLite persistence dla flows i alertów | Historia do analizy |
| 5 | Anomaly Detector (DDoS + port scan) | Najcenniejsza funkcja dla użytkownika |
| 6 | Przeprojektować SSE na aggregated events | Wymagane po Flow Tracker |
| 7 | Frontend — wykresy, alerty, widok flows | Finalna warstwa |

---

## 12. Rola RPi w sieci (ważna decyzja architektoniczna)

Żeby blokować ruch, RPi **musi być inline** (router/gateway):

```
Internet ←→ [eth0  RPi  wlan0] ←→ urządzenia WiFi
```

W trybie pasywnego monitora (port mirroring) można tylko obserwować, nie blokować.