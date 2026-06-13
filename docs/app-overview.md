# App Overview

NetworkTrafficControl, or NTC, is a Raspberry Pi oriented network traffic monitor and controller. It watches packets on a configured Linux network interface using a TC eBPF program, streams live events to the browser, exposes Prometheus metrics, and persists higher-level analytics in SQLite.

## Main Jobs

NTC has four main responsibilities:

1. Observe traffic on ingress and egress.
2. Apply simple IP based policy through blacklist, whitelist, and only-local lists.
3. Summarize traffic for humans and dashboards.
4. Preserve enough local data for later inspection without storing full packet captures.

## User-Facing Parts

The web UI is built with Svelte and served by the Go backend from `dist/`.

Current UI areas include:

- Live packet events.
- IP list management.
- Network device view.
- Analysis summary.
- App audit logs.
- System monitor.
- Metrics view.

## Runtime Modes

Real mode:

- Loads `tc_filter.bpf.o`.
- Attaches the TC eBPF program to the configured interface.
- Requires root or suitable Linux network capabilities.
- Intended for Raspberry Pi deployment.

Mock mode:

- Starts a synthetic packet generator.
- Does not require eBPF, Linux TC, root, or Raspberry Pi hardware.
- Intended for local development and UI work.

Run mock mode:

```sh
go run ./source --mock
```

## Data Model At A High Level

NTC avoids raw packet capture storage. Instead, packet events are processed into:

- Live events sent over SSE.
- 60 second in-memory metrics windows.
- Persistent SQLite counters for analytics.
- Persistent app log rows for auditability.

This matters for Raspberry Pi operation because it keeps disk usage small and makes later reporting straightforward.

## Policy Lists

NTC supports these list types:

| List | Endpoint | Purpose |
|---|---|---|
| Blacklist | `/blacklist` | Drop matching traffic |
| Whitelist | `/whitelist` | Allow/bypass matching traffic |
| Only-local | `/onlylocal` | Restrict matching hosts to local traffic |
| Local CIDRs v4 | `/network/localnets/v4` | Local IPv4 networks |
| Local CIDRs v6 | `/network/localnets/v6` | Local IPv6 networks |

Lists are persisted to `persistence.path`, currently `./data/lists.json` by default.

## Packet Actions

| Action | Meaning |
|---|---|
| `PASS` | Packet allowed normally |
| `DROP` | Packet matched blacklist and was dropped |
| `SKIP` | Packet matched whitelist and was passed |
| `SSH` | TCP port 22 bypass |
| `ONLY_LOCAL_DROP` | Packet blocked by only-local policy |
| `UNKNOWN` | Unrecognized action value |
