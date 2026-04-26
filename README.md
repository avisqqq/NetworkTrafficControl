# NetworkTrafficControl

NTC is a Linux TC eBPF network traffic monitor and controller designed for Raspberry Pi. It attaches TC programs to a network interface for full ingress and egress visibility, aggregates packets into flows, exposes Prometheus metrics, and ships a Svelte web UI for live event inspection and IP list management.

## Features

- **TC eBPF** — ingress + egress on all interface types including WiFi
- **Flow tracking** — 5-tuple aggregation (src/dst IP, ports, proto); flows expire on idle timeout, TCP FIN/RST, or forced flush
- **Per-IP sliding window** — 60s rolling stats: pkt/s, bytes/s, unique destination ports, SYN/ACK counts
- **Prometheus `/metrics`** — broken down by protocol, direction, and firewall action; scraped by VictoriaMetrics
- **Grafana dashboards** — Overview, Top Talkers, Security (port scan + SYN flood indicators)
- **Svelte web UI** — live SSE event table with filtering, pause/resume, blacklist/whitelist management
- **Blacklist / Whitelist** — eBPF maps with up to 1024 entries, persisted to JSON across restarts
- **SSH bypass** — TCP port 22 is never dropped regardless of list state
- **Mock mode** (`--mock`) — synthetic traffic generator for local development without eBPF or RPi
- **YAML config** — port, timezone, interface, persistence path

## Architecture

```
┌─────────────────────────────────────┐
│  TC eBPF (kernel)                   │
│  ingress + egress                   │
│  src/dst IP, ports, tcp_flags,      │
│  pkt_size, direction, action        │
└─────────────────┬───────────────────┘
                  │ ring buffer
                  ▼
┌─────────────────────────────────────┐
│  Go userspace                       │
│                                     │
│  Flow Tracker   — 5-tuple flows     │
│  IP Stats       — 60s sliding win   │
│  SSE Broadcast  — live event stream │
│  /metrics       — Prometheus format │
└──────┬──────────────────┬───────────┘
       │ scrape (10s)     │ SSE / HTTP
       ▼                  ▼
  VictoriaMetrics     Browser UI
       │              (Svelte)
       ▼
    Grafana
  (3 dashboards)
```

## Repository Layout

```
.
├── deploy.sh                    # Build and deploy script
├── deploy.env                   # RPi connection config (gitignored)
├── deploy.env.example           # Template for deploy.env
├── config.yaml                  # Runtime config
├── docker-compose.yml           # VictoriaMetrics + Grafana stack
├── victoria/
│   └── scrape.yaml              # Prometheus scrape config (dev: host.docker.internal)
├── grafana/
│   └── provisioning/
│       ├── datasources/         # Auto-provisioned VictoriaMetrics datasource
│       └── dashboards/          # NTC Overview, Top Talkers, Security
├── eBPF/
│   └── tc_filter.bpf.c          # TC eBPF program (ingress + egress)
└── client/
    ├── ntc/main.go              # Go entrypoint
    ├── httpapi/                 # HTTP handlers, SSE, /metrics
    ├── internal/
    │   ├── bpf/                 # eBPF loading, event parsing, map helpers
    │   ├── clock/               # Timestamp conversion
    │   ├── config/              # YAML config loader
    │   ├── flow/                # Flow tracker (5-tuple aggregation)
    │   ├── mock/                # Synthetic packet generator
    │   ├── model/               # Shared types (Event, OutEvent, IPKey…)
    │   ├── persist/             # JSON persistence for blacklist/whitelist
    │   └── stats/               # Per-IP sliding window + global counters
    ├── web/                     # Built Svelte app (served by Go, do not edit)
    └── web-svelte/              # Svelte source (npm run build → web/)
```

## Configuration

```yaml
server:
  port: 8086
  timezone: Europe/Warsaw   # IANA timezone, empty = UTC

network:
  interfaces:
    - wlan0                 # interface to attach TC to

persistence:
  path: ./data/lists.json
```

## Local Development

Run with synthetic traffic generator — no eBPF or Linux required:

```sh
# Terminal 1 — Go backend
cd client && go run ./ntc --mock

# Terminal 2 — Svelte dev server with proxy (optional, for frontend changes)
cd client/web-svelte && npm run dev
```

Open `http://localhost:8086` (served by Go) or `http://localhost:5173` (Vite dev server with HMR).

### Monitoring stack (local)

```sh
docker compose up -d
```

- Grafana: `http://localhost:3000` (admin / admin)
- VictoriaMetrics: `http://localhost:8428`

Scrape target is pre-configured to `host.docker.internal:8086`.

### Rebuild frontend

```sh
cd client/web-svelte && npm run build
# or via deploy.sh:
./deploy.sh local
```

## Raspberry Pi — First Time Setup

**1. Configure connection:**

```sh
cp deploy.env.example deploy.env
# Edit deploy.env: RPI_HOST, RPI_USER, RPI_DIR
```

**2. Set up SSH key:**

```sh
ssh-keygen -t ed25519
ssh-copy-id rpi@rpi.local
```

**3. Install dependencies (eBPF toolchain + Go + Docker):**

```sh
./deploy.sh rpi-install-dependencies
```

**4. Build and deploy NTC:**

```sh
./deploy.sh rpi-build
```

**5. Install systemd service:**

```sh
./deploy.sh rpi-install-service
```

**6. Install monitoring stack (VictoriaMetrics + Grafana):**

```sh
./deploy.sh rpi-install-stack
```

- NTC web UI: `http://rpi.local:8086`
- Grafana: `http://rpi.local:3000` (admin / admin)
- VictoriaMetrics: `http://rpi.local:8428`

## Subsequent Deploys

```sh
./deploy.sh rpi-build
ssh rpi@rpi.local 'sudo systemctl restart ntc'
```

## deploy.sh Targets

| Target | Description |
|---|---|
| `local` | Build frontend + eBPF + Go locally, copy to `execute/` |
| `rpi` | Cross-compile on macOS, scp artifacts to RPi |
| `rpi-build` | Build frontend locally, rsync sources to RPi, build eBPF + Go on device |
| `rpi-install-dependencies` | Install clang, llvm, linux-headers, Go, Docker on RPi |
| `rpi-install-service` | Install and enable NTC systemd service on RPi |
| `rpi-install-stack` | Copy and start VictoriaMetrics + Grafana via Docker Compose on RPi |

## API

### Event Stream (SSE)

```sh
curl http://localhost:8086/events
```

```json
{
  "time": "12:34:56.789",
  "seq": 42,
  "src": "192.168.0.10",
  "dst": "1.1.1.1",
  "proto": "TCP",
  "action": "PASS",
  "direction": "INGRESS"
}
```

| Action | Description |
|---|---|
| `PASS` | Packet allowed normally |
| `DROP` | Source/dest matched blacklist — packet dropped |
| `SKIP` | Source/dest matched whitelist — packet passed |
| `SSH` | TCP port 22 — always bypassed |

### Metrics

```sh
curl http://localhost:8086/metrics
```

Key metrics exposed:

| Metric | Type | Description |
|---|---|---|
| `ntc_packets_per_second` | gauge | Total pkt/s (60s avg) |
| `ntc_bytes_per_second` | gauge | Total bytes/s (60s avg) |
| `ntc_active_ips` | gauge | Distinct source IPs in last 60s |
| `ntc_active_flows` | gauge | Currently tracked flows |
| `ntc_packets_total{proto,direction,action}` | counter | Packet counters by dimension |
| `ntc_bytes_total{proto}` | counter | Byte counters by protocol |
| `ntc_ip_packets_per_second{ip}` | gauge | Per-IP pkt/s (top 10) |
| `ntc_ip_unique_dst_ports{ip}` | gauge | Unique ports per IP (port scan signal) |
| `ntc_ip_syn_count{ip}` | gauge | SYN count per IP (SYN flood signal) |

### Blacklist / Whitelist

```sh
# Add
curl -X POST http://localhost:8086/blacklist \
  -H 'Content-Type: application/json' -d '{"ip":"1.2.3.4"}'

# Remove
curl -X DELETE 'http://localhost:8086/blacklist?ip=1.2.3.4'

# List
curl http://localhost:8086/blacklist
```

Same endpoints for `/whitelist`. Both support IPv4 and IPv6.

## Notes

- eBPF maps hold up to 1024 entries per list.
- The server must run as root (or with `CAP_NET_ADMIN`) to load eBPF programs.
- Mock mode runs without any kernel privileges.