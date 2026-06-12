# Deployment

This document covers local development, Raspberry Pi deployment, systemd, and monitoring.

## Local Development

Run backend with mock traffic:

```sh
go run ./source --mock
```

Build frontend:

```sh
cd web
npm run build
```

Run frontend dev server:

```sh
cd web
npm run dev
```

Run tests:

```sh
go test ./...
```

## Raspberry Pi Config

Optional `deploy.env`:

```sh
RPI_HOST=rpi.local
RPI_USER=rpi
RPI_DIR=/home/rpi/ntc
NTC_PORT=8086
```

Runtime config is `config.yaml`.

Important values:

| Key | Purpose |
|---|---|
| `server.port` | HTTP port |
| `server.timezone` | Display timezone |
| `network.interfaces[0]` | Interface used by TC eBPF |
| `network.cidrs` | Optional manually configured local CIDRs |
| `network.lease_file` | Device lease file |
| `persistence.path` | JSON list storage |
| `app_logs.path` | App log SQLite database |
| `analytics.path` | Analytics SQLite database |
| `geo.enabled` | Enable geo lookups |

## Install Dependencies On Raspberry Pi

```sh
./scripts/deploy.sh rpi-install-dependencies
```

This installs the eBPF build toolchain, Go, and Docker.

## Build On Raspberry Pi

```sh
./scripts/deploy.sh rpi-build
```

This flow:

1. Builds the Svelte frontend locally.
2. Copies the source tree to the Pi.
3. Builds the eBPF object on the Pi.
4. Builds the Go binary on the Pi.
5. Copies `dist/`, `config.yaml`, and `tc_filter.bpf.o` into `RPI_DIR`.

Run manually:

```sh
ssh rpi@rpi.local 'cd /home/rpi/ntc && sudo ./ntc'
```

## systemd

Install service:

```sh
./scripts/deploy.sh rpi-install-service
```

Manage service:

```sh
ssh rpi@rpi.local 'sudo systemctl status ntc'
ssh rpi@rpi.local 'sudo systemctl restart ntc'
ssh rpi@rpi.local 'sudo journalctl -u ntc -f'
```

## Monitoring

Start monitoring locally:

```sh
docker compose -f monitoring/docker-compose.yml up -d
```

Install monitoring on the Pi:

```sh
./scripts/deploy.sh rpi-install-stack
```

Services:

| Service | Default URL |
|---|---|
| NTC | `http://rpi.local:8086` |
| Grafana | `http://rpi.local:3000` |
| VictoriaMetrics | `http://rpi.local:8428` |

## Runtime Requirements

Real eBPF mode:

- Linux host.
- TC/eBPF support.
- Root or suitable network capabilities.
- Compiled `tc_filter.bpf.o` next to the binary.

Mock mode:

- No eBPF requirement.
- No root requirement.
- Useful for UI and backend development.

