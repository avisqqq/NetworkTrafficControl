# Аналіз: Що потрібно для комплексного виявлення атак

## 1. Яких даних бракує в поточній моделі

Поточний `struct event` в eBPF захоплює: `ts, seq, src_ip, dst_ip, ip_version, proto, action`.

Щоб виявляти DDoS, port scan, brute force — **обов'язково потрібно**:

```c
struct event {
    __u64  ts;
    __u32  seq;
    __u8   src[16];
    __u8   dst[16];
    __u16  src_port;    // ВІДСУТНЄ
    __u16  dst_port;    // ВІДСУТНЄ
    __u16  pkt_size;    // ВІДСУТНЄ — байти
    __u8   tcp_flags;   // ВІДСУТНЄ — SYN/ACK/RST/FIN
    __u8   ip_version;
    __u8   proto;
    __u8   action;
    __u8   direction;   // ВІДСУТНЄ — ingress/egress
};
```

Без портів не виявиш port scan. Без TCP flags не відрізниш SYN flood від нормального TCP. Без розміру не виявиш amplification. Це фундаментальна зміна в XDP.

---

## 2. Що виявляємо і яких даних потребує кожна детекція

| Атака | Сигнал | Потрібні дані |
|---|---|---|
| **SYN flood** | Маса SYN без ACK до одного dst | tcp_flags, dst_ip, часове вікно |
| **UDP flood** | Масовий UDP до одного dst | proto, dst_ip, pkt_count/s |
| **ICMP flood** | Масовий ICMP | proto, dst_ip, pkt_count/s |
| **DNS amplification** | Великі відповіді UDP/53 назовні | dst_port=53, direction, pkt_size |
| **Vertical port scan** | Один src → багато портів того ж dst | src_ip, dst_ip, унікальні dst_port |
| **Horizontal scan** | Один src → багато IP на тому ж порті | src_ip, унікальні dst_ip, dst_port |
| **SYN scan (half-open)** | Високий SYN/RST ratio, без handshake | tcp_flags per flow |
| **Brute force** | Багато з'єднань src→dst:port | (src, dst, dst_port), count |
| **Exfiltration** | Асиметричний flow — багато даних виходить | direction, byte_count per flow |

---

## 3. Ключова концепція: Flow-based модель замість packet-based

Відмовляєшся від мислення "пакет за пакетом" і переходиш на **flow records** — саме так працює NetFlow/IPFIX (стандарт в enterprise).

**Flow** = унікальний 5-tuple: `(src_ip, dst_ip, src_port, dst_port, proto)`

Кожен пакет **оновлює** існуючий flow замість створення нового event. Flow "закривається" коли:
- Минув idle timeout (наприклад 30s без пакету)
- Побачено TCP FIN/RST
- Примусовий flush (наприклад кожні 60s)

Ефект: 10 000 пакетів/s з 50 активних з'єднань → 50 записів/30s замість 300 000 events/30s.

---

## 4. Цільова архітектура

```
┌─────────────────────────────────────────────┐
│  KERNEL SPACE (eBPF XDP)                    │
│                                             │
│  Per-пакет: ts, src, dst, ports,            │
│  tcp_flags, size, direction                 │
│                                             │
│  Ring buffer → мінімальний struct,          │
│  тільки те що kernel бачить нативно         │
└───────────────────┬─────────────────────────┘
                    │ ~всі пакети
                    ▼
┌─────────────────────────────────────────────┐
│  GO USERSPACE — Flow Tracker                │
│                                             │
│  FlowTable: map[FlowKey]*FlowRecord         │
│  - оновлює flow per пакет                   │
│  - закриті flows → FlowExporter             │
│                                             │
│  IPStats: map[IP]*SlidingWindow             │
│  - 60 buckets × 1s                         │
│  - pkt/s, bytes/s, унікальні dst_ports,    │
│    унікальні src_ips, SYN/ACK ratio        │
└───────┬──────────────────┬──────────────────┘
        │ flows (кожні 5s) │ stats (кожну 1s)
        ▼                  ▼
┌───────────────┐  ┌───────────────────────────┐
│  SQLite       │  │  Anomaly Detector         │
│               │  │                           │
│  flows        │  │  Правила:                 │
│  ip_stats     │  │  - ddos_detector          │
│  alerts       │  │  - port_scan_detector     │
└───────────────┘  │  - brute_force_detector   │
                   └─────────────┬─────────────┘
                                 │ alerts
                                 ▼
                   ┌─────────────────────────────┐
                   │  SSE Broadcaster            │
                   │                             │
                   │  Надсилає:                  │
                   │  - stats_tick (кожну 1s)   │
                   │  - flow_event (новий flow)  │
                   │  - alert (детекція)         │
                   │                             │
                   │  НЕ надсилає сирі пакети    │
                   └─────────────────────────────┘
```

---

## 5. Структури даних у Go

```go
// Flow key — ідентифікатор унікального з'єднання
type FlowKey struct {
    Src     [16]byte
    Dst     [16]byte
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}

// Flow record — акумульований стан з'єднання
type FlowRecord struct {
    FirstSeen time.Time
    LastSeen  time.Time
    PktCount  uint64
    ByteCount uint64
    TCPFlags  uint8  // bitwise OR всіх побачених прапорів
    Direction uint8  // ingress / egress
}

// Per-IP sliding window (60 buckets × 1s)
type IPWindow struct {
    mu          sync.Mutex
    Pkts        [60]uint32
    Bytes       [60]uint32
    DstPorts    map[uint16]struct{}   // скидається кожну хвилину
    UniqueSrcs  map[[16]byte]struct{} // для DDoS dst
    SynCount    uint32
    AckCount    uint32
    cursor      int  // поточний bucket (round-robin)
    lastRotate  time.Time
}
```

---

## 6. Правила детекції

```go
// Приклад правил — конфігуруються через YAML

type Rules struct {
    DDoS struct {
        PktsPerSecondThreshold uint32  // напр. 10_000
        UniqueSourcesThreshold int     // напр. 50 унікальних IP до одного dst за 5s
    }
    PortScan struct {
        UniquePortsThreshold int  // напр. 20 портів від одного src за 60s
        UniqueHostsThreshold int  // напр. 20 хостів від одного src за 60s
    }
    SYNFlood struct {
        SYNRatioThreshold float32  // напр. SYN/(SYN+ACK) > 0.9
        MinSYNCount       uint32   // напр. мін. 1000 SYN щоб правило спрацювало
    }
    BruteForce struct {
        ConnectionsThreshold int  // напр. 100 з'єднань (src,dst,port) за 60s
    }
}
```

---

## 7. SQLite схема

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
    detail  TEXT             -- JSON з додатковими даними
);
```

---

## 8. Що SSE надсилає замість сирих пакетів

```json
// stats_tick (кожну 1s)
{
  "type": "stats_tick",
  "ts": 1714000000,
  "total_pkts_per_sec": 1250,
  "total_bytes_per_sec": 890000,
  "top_talkers": [
    {"ip": "192.168.1.10", "pkts": 800, "bytes": 600000},
    {"ip": "10.0.0.5",     "pkts": 450, "bytes": 290000}
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

// flow_event (новий або закритий flow)
{
  "type": "flow_new",
  "src": "192.168.1.10", "src_port": 54321,
  "dst": "8.8.8.8",      "dst_port": 53,
  "proto": "UDP"
}
```

---

## 9. Пріоритет реалізації

1. **Крок 1 — розширити eBPF struct** — порти, tcp_flags, pkt_size, direction (зміна в XDP + Go model)
2. **Крок 2 — Flow Tracker у Go** (найважливіший компонент, усуває проблему пам'яті)
3. **Крок 3 — SQLite persistence** для flows та алертів
4. **Крок 4 — Anomaly Detector** з правилами DDoS + port scan (найцінніше для користувача)
5. **Крок 5 — перепроєктувати SSE** на aggregated events
6. **Крок 6 — frontend** — графіки, карта алертів, перегляд flows

---

## Підсумок

Фундаментальна зміна — перехід з **"stream пакетів"** на **"stream flows + алертів"**. Kernel робить те що робить найкраще (захоплює пакети), Go робить агрегацію та детекцію, SQLite зберігає історію для аналізу. RPi без проблем витягне цю архітектуру навіть при кількох тисячах пакетів на секунду.