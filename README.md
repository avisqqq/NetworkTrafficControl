# NetworkTrafficControl

NetworkTrafficControl, or NTC, is a Linux TC eBPF network traffic monitor and controller built for Raspberry Pi. It attaches a TC filter to a configured network interface, reads packet events in Go, keeps live traffic metrics, persists IP lists, stores aggregated analytics in SQLite, and serves a Svelte web UI.

The program can also run in mock mode for local development without eBPF or Raspberry Pi hardware.

## Current Features

- TC eBPF packet visibility for ingress and egress traffic.
- Packet actions for normal pass, blacklist drop, whitelist skip, SSH bypass, and only-local drop.
- Blacklist, whitelist, and only-local IP lists persisted to JSON.
- Live packet event stream over Server-Sent Events.
- Prometheus `/metrics` endpoint with traffic rates, protocol counters, direction counters, action counters, top talkers, and security indicators.
- Flow and per-IP traffic tracking with a 60 second sliding window.
- SQLite app log storage.
- SQLite analytics storage for hosts, peers, services, countries, blocked peers, and totals.
- Optional geo enrichment through `ip-api`.
- Network device discovery from the configured lease file.
- System telemetry stream for the web UI.
- Svelte UI served by the Go backend from `dist/`.
- Mock traffic generator for development.
- VictoriaMetrics and Grafana monitoring stack under `monitoring/`.

## Architecture

```text
TC eBPF filter
  -> Go packet reader
  -> packet dispatcher
       -> SSE live events
       -> Prometheus metrics
       -> SQLite analytics aggregation
  -> HTTP API + Svelte UI
```

Analytics are intentionally stored as counters and summaries rather than raw packet dumps. This keeps the database small enough for a Raspberry Pi and makes the data suitable for local report generation.

## Repository Layout

```text
.
├── source/                         Go backend
│   ├── ntc.go                      main entrypoint
│   ├── config/                     YAML config loading
│   ├── domain/                     packet, network, log, and system domain types
│   ├── application/                services and orchestration
│   │   ├── analytics/              aggregated traffic analytics
│   │   ├── inspection/             packet/IP inspection and geo enrichment
│   │   ├── lists/                  blacklist, whitelist, only-local logic
│   │   ├── logs/                   app log service
│   │   ├── mock/                   synthetic packet source
│   │   ├── network/                local CIDR and device helpers
│   │   ├── packet/                 packet runtime startup
│   │   ├── packetstream/           event dispatcher
│   │   ├── system/                 system telemetry service
│   │   └── traffic/                flow and stats tracking
│   └── infrastructure/
│       ├── http/                   API handlers, metrics, SSE
│       ├── packet/                 eBPF loader, reader, map helpers
│       │   └── c/tc_filter.bpf.c   TC eBPF program
│       ├── geo/                    geo provider implementation
│       ├── persist/                JSON persistence for lists
│       ├── storage/                SQLite/Gorm setup and repositories
│       └── system/                 system collector
├── web/                            Svelte frontend source
├── dist/                           built frontend served by Go
├── data/                           runtime SQLite/JSON data
├── monitoring/                     VictoriaMetrics and Grafana config
├── scripts/deploy.sh               local/RPi build and deploy helper
├── config.yaml                     runtime configuration
├── go.mod
└── go.sum
```

## Configuration

Default runtime config is in `config.yaml`:

```yaml
server:
  port: 8086
  timezone: Europe/Warsaw

network:
  interfaces:
    - wlan0
  cidrs:
  lease_file: /var/lib/misc/dnsmasq.leases

persistence:
  path: ./data/lists.json

app_logs:
  path: ./data/app_logs.db

analytics:
  path: ./data/analytics.db

geo:
  enabled: true
  provider: ip-api
  timeout_seconds: 2
  cache_ttl_seconds: 86400
```

Notes:

- `network.interfaces[0]` is the interface used for TC attachment.
- If `network.cidrs` is empty, NTC tries to discover local CIDRs from the interface.
- Relative data paths are resolved relative to the config file location.
- `geo.enabled` enriches inspected peers and analytics rows when a provider is configured.

## Local Development

Run backend with synthetic traffic:

```sh
go run ./source --mock
```

Run the Svelte dev server when changing frontend code:

```sh
cd web
npm run dev
```

Open:

- Go-served app: `http://localhost:8086`
- Vite dev app: `http://localhost:5173`

Build the frontend:

```sh
cd web
npm run build
```

Run Go tests:

```sh
go test ./...
```

## Raspberry Pi Deployment

Create `deploy.env` if you need non-default SSH values:

```sh
RPI_HOST=rpi.local
RPI_USER=rpi
RPI_DIR=/home/rpi/ntc
NTC_PORT=8086
```

Install Raspberry Pi dependencies:

```sh
./scripts/deploy.sh rpi-install-dependencies
```

Build on the Raspberry Pi and copy artifacts into `RPI_DIR`:

```sh
./scripts/deploy.sh rpi-build
```

Run manually on the Pi:

```sh
ssh rpi@rpi.local 'cd /home/rpi/ntc && sudo ./ntc'
```

Install the systemd service:

```sh
./scripts/deploy.sh rpi-install-service
```

Manage the service:

```sh
ssh rpi@rpi.local 'sudo systemctl status ntc'
ssh rpi@rpi.local 'sudo systemctl restart ntc'
ssh rpi@rpi.local 'sudo journalctl -u ntc -f'
```

## Monitoring Stack

Start VictoriaMetrics and Grafana locally:

```sh
docker compose -f monitoring/docker-compose.yml up -d
```

Install the monitoring stack on the Raspberry Pi:

```sh
./scripts/deploy.sh rpi-install-stack
```

URLs after deployment:

- NTC UI: `http://rpi.local:8086`
- Grafana: `http://rpi.local:3000`
- VictoriaMetrics: `http://rpi.local:8428`

Monitoring details and dashboard notes are in [monitoring/README.md](monitoring/README.md).

## HTTP API

### Live Packet Events

```sh
curl http://localhost:8086/events
```

Example event:

```json
{
  "time": "12:34:56.789",
  "seq": 42,
  "src": "192.168.0.10",
  "dst": "1.1.1.1",
  "proto": "TCP",
  "action": "PASS",
  "direction": "EGRESS"
}
```

### Lists

```sh
curl http://localhost:8086/blacklist
curl http://localhost:8086/whitelist
curl http://localhost:8086/onlylocal
```

Add an IP:

```sh
curl -X POST http://localhost:8086/blacklist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"1.2.3.4"}'
```

Remove an IP:

```sh
curl -X DELETE 'http://localhost:8086/blacklist?ip=1.2.3.4'
```

### Runtime And Network

```sh
curl http://localhost:8086/runtime/state
curl http://localhost:8086/network/devices
curl http://localhost:8086/network/localnets/v4
curl http://localhost:8086/network/localnets/v6
```

### Packet Inspection

```sh
curl -X POST http://localhost:8086/packet/inspect \
  -H 'Content-Type: application/json' \
  -d '{"src":"192.168.0.10","dst":"1.1.1.1","src_port":12345,"dst_port":443,"proto":"TCP","action":"PASS","ip_version":4,"direction":"EGRESS"}'
```

### Analytics

```sh
curl 'http://localhost:8086/analysis/summary?limit=50'
curl 'http://localhost:8086/analysis/host?ip=192.168.0.10&limit=50'
```

The analytics response contains:

- `peers`: top host-to-peer traffic rows.
- `services`: top services by bytes.
- `countries`: traffic grouped by peer country.
- `blocked`: blocked peer counters.
- `totals`: host, peer, service, country, blocked, packet, and byte totals.

### Logs And System Events

```sh
curl 'http://localhost:8086/app/logs?limit=200'
curl http://localhost:8086/system/events
```

### Metrics

```sh
curl http://localhost:8086/metrics
```

Important metrics:

| Metric | Type | Description |
|---|---|---|
| `ntc_packets_per_second` | gauge | Total packets per second over the 60s window |
| `ntc_bytes_per_second` | gauge | Total bytes per second over the 60s window |
| `ntc_packets_total{proto}` | counter | Packet counters by protocol |
| `ntc_bytes_total{proto}` | counter | Byte counters by protocol |
| `ntc_direction_packets_total{direction}` | counter | Packet counters by ingress/egress |
| `ntc_direction_bytes_total{direction}` | counter | Byte counters by ingress/egress |
| `ntc_action_packets_total{action}` | counter | Packet counters by firewall action |
| `ntc_action_bytes_total{action}` | counter | Byte counters by firewall action |
| `ntc_active_ips` | gauge | Distinct source IPs seen in the last 60s |
| `ntc_active_flows` | gauge | Currently tracked flows |
| `ntc_ip_packets_per_second{ip}` | gauge | Top source IP packet rates |
| `ntc_ip_bytes_per_second{ip}` | gauge | Top source IP byte rates |
| `ntc_ip_unique_dst_ports{ip}` | gauge | Port-scan signal |
| `ntc_ip_syn_count{ip}` | gauge | SYN flood signal |
| `ntc_ip_ack_count{ip}` | gauge | ACK count signal |

## Packet Actions

| Action | Description |
|---|---|
| `PASS` | Packet allowed normally |
| `DROP` | Packet matched blacklist and was dropped |
| `SKIP` | Packet matched whitelist and was passed |
| `SSH` | TCP port 22 bypass |
| `ONLY_LOCAL_DROP` | Packet blocked by only-local policy |
| `UNKNOWN` | Unrecognized action value |

## Operational Notes

- Real eBPF mode must run as root or with the needed network capabilities.
- Mock mode does not need kernel privileges.
- SSH traffic is bypassed so remote access is not accidentally blocked.
- SQLite analytics writes are batched and disabled after fatal disk I/O failures to protect the running service.
- Geo enrichment depends on external network access unless a local provider is added.
