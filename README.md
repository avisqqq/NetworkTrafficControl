# NetworkTrafficControl

NetworkTrafficControl is a Linux XDP/eBPF traffic monitor and controller. It attaches an XDP program to a network interface, streams packet events to a Go HTTP server, and exposes a web UI plus API endpoints for managing blacklist and whitelist IP maps.

## Features

- XDP packet inspection for IPv4 and IPv6 traffic.
- Blacklist support for dropping packets by source IP.
- Whitelist support for allowing traffic while marking events as skipped.
- SSH traffic bypass on TCP port 22.
- Ring buffer event stream from eBPF to user space.
- Browser UI served from `client/web`.
- HTTP API for event streaming and list management.
- Blacklist and whitelist persisted to JSON file — survives restarts.
- Mock mode (`--mock`) for local development without eBPF or Raspberry Pi.
- YAML config file for port, timezone, interface, and persistence path.

## Repository Layout

```text
.
├── deploy.sh               # Build and deploy script (see targets below)
├── deploy.env              # Local RPi connection config (gitignored, copy from deploy.env.example)
├── deploy.env.example      # Template for deploy.env
├── config.yaml             # Runtime configuration
├── eBPF/
│   └── xdp_ring.bpf.c      # XDP/eBPF program
└── client/
    ├── ntc/main.go          # Go entrypoint
    ├── httpapi/             # HTTP handlers and SSE endpoint
    ├── internal/
    │   ├── bpf/             # eBPF loading, event parsing, map helpers
    │   ├── clock/           # Timestamp conversion
    │   ├── config/          # YAML config loader
    │   ├── mock/            # Synthetic packet generator (mock mode)
    │   ├── model/           # Shared types
    │   └── persist/         # JSON persistence for blacklist/whitelist
    └── web/                 # Static web UI
```

## Configuration

Edit `config.yaml` before running:

```yaml
server:
  port: 8086
  timezone: Europe/Warsaw  # IANA timezone, empty = UTC

network:
  interfaces:
    - wlan0  # interface to attach XDP to

persistence:
  path: ./data/lists.json  # path to blacklist/whitelist JSON file
```

## Local Development (mock mode, no RPi required)

Run with a synthetic packet generator — no eBPF or Linux required:

```sh
cd /path/to/NetworkTrafficControl
go run ./client/ntc --mock
```

Open the web UI at:

```
http://localhost:8086
```

To use a custom config:

```sh
go run ./client/ntc --mock --config /path/to/config.yaml
```

## Raspberry Pi — First Time Setup

**1. Configure connection:**

```sh
cp deploy.env.example deploy.env
# Edit deploy.env with your RPi host, user, and directory
```

**2. Set up SSH key (no password prompts):**

```sh
ssh-keygen -t ed25519   # if you don't have a key yet
ssh-copy-id rpi@rpi.local
```

**3. Install dependencies on RPi:**

```sh
./deploy.sh rpi-install-dependencies
```

This installs: `clang`, `llvm`, `linux-headers`, `libbpf-dev`, `libc6-dev`, and Go.

**4. Build and deploy:**

```sh
./deploy.sh rpi-build
```

Copies sources to RPi and compiles eBPF + Go on the device.

**5. Install systemd service:**

```sh
./deploy.sh rpi-install-service
```

The service starts automatically on boot and restarts on failure.

## Raspberry Pi — Managing the Service

```sh
ssh rpi@rpi.local 'sudo systemctl start ntc'
ssh rpi@rpi.local 'sudo systemctl stop ntc'
ssh rpi@rpi.local 'sudo systemctl restart ntc'
ssh rpi@rpi.local 'sudo journalctl -u ntc -f'   # live logs
```

Open the web UI at:

```
http://rpi.local:8086
```

## Subsequent Deploys

After making changes, rebuild and redeploy:

```sh
./deploy.sh rpi-build
ssh rpi@rpi.local 'sudo systemctl restart ntc'
```

## deploy.sh Targets

| Target | Description |
|---|---|
| `local` | Build eBPF and Go locally, copy to `execute/` |
| `rpi` | Cross-compile on macOS, copy artifacts to RPi |
| `rpi-build` | Copy sources to RPi, build eBPF and Go on device |
| `rpi-install-dependencies` | Install all build dependencies on RPi |
| `rpi-install-service` | Install and enable systemd service on RPi |

## API

### Event Stream

Streams packet events using Server-Sent Events:

```sh
curl http://localhost:8086/events
```

Example event payload:

```json
{
  "time": "12:34:56.789",
  "seq": 42,
  "src": "192.168.0.10",
  "dst": "1.1.1.1",
  "proto": "TCP",
  "action": "PASS"
}
```

Possible actions:

| Action | Description |
|---|---|
| `PASS` | Packet passed normally |
| `DROP` | Packet matched blacklist and was dropped |
| `SKIP` | Packet matched whitelist and was passed |
| `SSH` | TCP port 22 — bypassed |

### Blacklist

```sh
# Add
curl -X POST http://localhost:8086/blacklist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.0.50"}'

# Remove
curl -X DELETE 'http://localhost:8086/blacklist?ip=192.168.0.50'

# List
curl http://localhost:8086/blacklist
```

### Whitelist

```sh
# Add
curl -X POST http://localhost:8086/whitelist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.0.20"}'

# Remove
curl -X DELETE 'http://localhost:8086/whitelist?ip=192.168.0.20'

# List
curl http://localhost:8086/whitelist
```

## Notes

- Blacklist and whitelist are persisted to JSON and restored on restart.
- Both lists support IPv4 and IPv6 addresses.
- eBPF maps allow up to 1024 entries per list.
- The server must be run from the directory containing `web/` and `xdp_ring.bpf.o` (handled automatically by `rpi-install-service`).