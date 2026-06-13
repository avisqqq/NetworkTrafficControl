# Architecture

NTC is organized around a Go backend, a TC eBPF packet source, SQLite persistence, and a Svelte frontend.

## Runtime Flow

```text
tc_filter.bpf.c
  -> eBPF ring buffer
  -> infrastructure/packet reader
  -> application/packetstream dispatcher
       -> HTTP SSE consumer
       -> traffic metrics service
       -> analytics service
  -> HTTP server
       -> Svelte UI
       -> JSON API
       -> Prometheus metrics
```

## Entry Point

Main file:

```text
source/ntc.go
```

Startup sequence:

1. Load YAML config.
2. Open JSON list persistence.
3. Open app log SQLite database.
4. Discover local CIDRs from config or network interface.
5. Start either mock packet runtime or eBPF packet runtime.
6. Start SSE, metrics, analytics, system, inspection, and geo services.
7. Start HTTP server.
8. On shutdown, stop the server with a timeout.

## Backend Packages

| Package | Role |
|---|---|
| `source/config` | YAML config loading and relative path resolution |
| `source/domain/packet` | Packet model, IP helpers, protocol and action types |
| `source/application/packet` | Packet app/runtime startup |
| `source/application/packetstream` | Fan-out dispatcher for packet consumers |
| `source/application/traffic` | Metrics, flow tracking, sliding windows |
| `source/application/analytics` | Persistent analytics aggregation |
| `source/application/inspection` | Packet inspection, endpoint details, geo enrichment |
| `source/application/lists` | Blacklist, whitelist, only-local, persistence wrappers |
| `source/application/logs` | Structured app log service |
| `source/application/network` | Local CIDR and device discovery helpers |
| `source/application/system` | System telemetry service |
| `source/infrastructure/http` | HTTP server, handlers, SSE, metrics output |
| `source/infrastructure/packet` | eBPF loader, reader, and map adapters |
| `source/infrastructure/storage` | SQLite/Gorm DB setup and repositories |
| `source/infrastructure/geo` | `ip-api` provider |
| `source/infrastructure/persist` | JSON persistence store |
| `source/infrastructure/system` | Host system collector |

## Frontend

Frontend source lives in:

```text
web/src
```

Important files:

| File | Role |
|---|---|
| `web/src/App.svelte` | Main app shell |
| `web/src/lib/api.js` | HTTP API client helpers |
| `web/src/lib/sse.js` | Packet event stream client |
| `web/src/lib/EventTable.svelte` | Live packet events |
| `web/src/lib/ListPanel.svelte` | List management |
| `web/src/lib/AnalysisSummary.svelte` | Analytics UI |
| `web/src/lib/AuditLogs.svelte` | App log UI |
| `web/src/lib/SystemMonitor.svelte` | System event stream UI |
| `web/src/lib/MetricsView.svelte` | Prometheus metrics viewer |

Build output is written to `dist/` and served by the Go backend.

## eBPF Layer

Source:

```text
source/infrastructure/packet/c/tc_filter.bpf.c
```

Compiled object:

```text
tc_filter.bpf.o
```

The Go process loads the object and attaches it to the configured interface. The eBPF program emits packet events and consults list maps for policy decisions.

## Persistence

NTC uses three local persistence mechanisms:

| Storage | Default path | Purpose |
|---|---|---|
| JSON | `./data/lists.json` | IP lists and mock mode |
| SQLite | `./data/app_logs.db` | App logs |
| SQLite | `./data/analytics.db` | Aggregated traffic analytics |

SQLite schema details are in [Database Schema](database-schema.md).

