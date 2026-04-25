# NetworkTrafficControl

NetworkTrafficControl is a Linux XDP/eBPF traffic monitor and controller. It attaches an XDP program to a network interface, streams packet events to a Go HTTP server, and exposes a small web UI plus API endpoints for managing blacklist and whitelist IP maps.

## Features

- XDP packet inspection for IPv4 and IPv6 traffic.
- Blacklist support for dropping packets by source or destination IP.
- Whitelist support for allowing traffic while marking events as skipped.
- SSH traffic bypass on TCP port 22.
- Ring buffer event stream from eBPF to user space.
- Browser UI served from `client/web`.
- HTTP API for event streaming and list management.

## Repository Layout

```text
.
├── deploy.sh                 # Builds eBPF and Go artifacts, then copies them to execute/ or Raspberry Pi
├── eBPF/
│   └── xdp_ring.bpf.c        # XDP/eBPF program
├── client/
│   ├── ntc/main.go           # Go entrypoint
│   ├── httpapi/              # HTTP handlers and SSE endpoint
│   ├── internal/bpf/         # eBPF loading, event parsing, map helpers
│   └── web/                  # Static web UI
└── execute/                  # Generated runtime artifacts after deploy.sh local
```

## Requirements

- Linux with eBPF/XDP support.
- Root privileges or equivalent capabilities to attach XDP programs.
- Go 1.25 or newer, matching `client/go.mod`.
- `clang` with BPF target support.
- Kernel headers and libbpf headers available to compile the eBPF program.

On Debian/Ubuntu-like systems, the native packages are usually similar to:

```sh
sudo apt install clang llvm linux-headers-$(uname -r) libbpf-dev
```

## Build

Build for the local Linux machine:

```sh
./deploy.sh local
```

This compiles:

- `eBPF/xdp_ring.bpf.o`
- `client/ntc/ntc`

Then copies the runtime files into `execute/`.

Build and copy to the Raspberry Pi target configured in `deploy.sh`:

```sh
./deploy.sh rpi
```

Before using the Raspberry Pi target, update `DEST` in `deploy.sh` to match your username, host, and destination directory.

## Run

After building locally:

```sh
cd execute
sudo ./ntc
```

The server listens on:

```text
http://localhost:8086
```

Open that URL in a browser to use the web UI.

## Network Interface

The Go entrypoint currently attaches XDP to `wlan0`:

```go
mgr, err := bpf.Load("xdp_ring.bpf.o", "wlan0")
```

If your target interface has a different name, update `client/ntc/main.go` before building. Common names include `eth0`, `wlan0`, `enp3s0`, and `wlp2s0`.

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

Possible actions are:

- `PASS`: packet passed normally.
- `DROP`: packet matched the blacklist and was dropped.
- `SKIP`: packet matched the whitelist and was passed.
- `SSH`: packet used TCP port 22 and was bypassed.

### Blacklist

Add an IP to the blacklist:

```sh
curl -X POST http://localhost:8086/blacklist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.0.50"}'
```

Remove an IP from the blacklist:

```sh
curl -X DELETE 'http://localhost:8086/blacklist?ip=192.168.0.50'
```

List blacklisted IPs:

```sh
curl http://localhost:8086/blacklist
```

### Whitelist

Add an IP to the whitelist:

```sh
curl -X POST http://localhost:8086/whitelist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.0.20"}'
```

Remove an IP from the whitelist:

```sh
curl -X DELETE 'http://localhost:8086/whitelist?ip=192.168.0.20'
```

List whitelisted IPs:

```sh
curl http://localhost:8086/whitelist
```

## Notes

- List changes are stored in eBPF maps and are not persisted after the process exits.
- The blacklist and whitelist maps support IPv4 and IPv6 addresses.
- The eBPF maps currently allow up to 1024 entries per list.
- The static web UI is served from `./web`, so run `ntc` from the generated `execute/` directory unless you adjust the file paths.
