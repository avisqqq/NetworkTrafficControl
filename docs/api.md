# HTTP API

The Go backend serves JSON APIs, Server-Sent Events, Prometheus metrics, and the built Svelte frontend.

Default base URL:

```text
http://localhost:8086
```

## Events

### `GET /events`

Live packet events over Server-Sent Events.

Example event body:

```json
{
  "time": "12:34:56.789",
  "seq": 42,
  "src": "192.168.0.10",
  "dst": "1.1.1.1",
  "src_port": 12345,
  "dst_port": 443,
  "pkt_size": 1500,
  "proto": "TCP",
  "action": "PASS",
  "ip_version": 4,
  "direction": "EGRESS",
  "tcp_flags": 16
}
```

### `GET /system/events`

System telemetry over Server-Sent Events. Used by the system monitor UI.

## Lists

The list endpoints use the same method pattern.

| Endpoint | Purpose |
|---|---|
| `/blacklist` | Blacklist IPs |
| `/whitelist` | Whitelist IPs |
| `/onlylocal` | Only-local IPs |

### `GET /blacklist`

Returns the current list.

### `POST /blacklist`

Adds an IP.

```json
{
  "ip": "1.2.3.4"
}
```

### `DELETE /blacklist?ip=1.2.3.4`

Removes an IP.

The same method pattern applies to `/whitelist` and `/onlylocal`.

## Local CIDRs

| Endpoint | Purpose |
|---|---|
| `/network/localnets/v4` | IPv4 local networks |
| `/network/localnets/v6` | IPv6 local networks |

Methods:

- `GET`: list CIDRs.
- `POST`: add CIDR using `{"cidr":"192.168.0.0/24"}`.
- `DELETE`: remove CIDR using `?cidr=192.168.0.0/24`.

## Runtime And Network

### `GET /runtime/state`

Returns runtime state such as mock mode.

### `GET /network/devices`

Returns discovered network devices from the configured lease file or mock data.

## Packet Inspection

### `POST /packet/inspect`

Inspects a packet-shaped JSON payload and returns endpoint metadata, service names, scopes, and optional geo enrichment.

Request:

```json
{
  "seq": 0,
  "time": "2026-06-10T12:00:00Z",
  "src": "192.168.0.10",
  "dst": "1.1.1.1",
  "src_port": 12345,
  "dst_port": 443,
  "pkt_size": 1500,
  "proto": "TCP",
  "action": "PASS",
  "ip_version": 4,
  "direction": "EGRESS",
  "tcp_flags": 16
}
```

Response shape:

```json
{
  "seq": 0,
  "time": "2026-06-10T12:00:00Z",
  "protocol": "TCP",
  "action": "PASS",
  "direction": "EGRESS",
  "ip_version": 4,
  "packet_size": 1500,
  "tcp_flags": 16,
  "source": {
    "ip": "192.168.0.10",
    "port": 12345,
    "endpoint": "192.168.0.10:12345",
    "scope": "private",
    "service": "",
    "geo": {},
    "analysis_hint": ""
  },
  "destination": {
    "ip": "1.1.1.1",
    "port": 443,
    "endpoint": "1.1.1.1:443",
    "scope": "public",
    "service": "HTTPS",
    "geo": {},
    "analysis_hint": ""
  }
}
```

## Analytics

### `GET /analysis/summary?limit=50`

Returns global analytics summary.

### `GET /analysis/host?ip=192.168.0.10&limit=50`

Returns analytics summary filtered to one host.

Summary response:

```json
{
  "peers": [],
  "services": [],
  "countries": [],
  "blocked": [],
  "totals": {
    "hosts": 0,
    "peers": 0,
    "services": 0,
    "countries": 0,
    "blocked": 0,
    "packets": 0,
    "bytes": 0
  }
}
```

`limit` defaults to 20 and is capped to 100 by the repository.

## Logs

### `GET /app/logs?limit=200`

Returns structured app logs.

Response fields:

| Field | Meaning |
|---|---|
| `id` | Log row ID |
| `created_at` | Timestamp |
| `level` | `INFO`, `WARN`, or `ERROR` |
| `category` | Log category |
| `event` | Structured event name |
| `message` | Human-readable message |
| `entity_type` | Optional entity kind |
| `entity_id` | Optional entity identifier |
| `actor` | Actor that caused the event |
| `source` | Source subsystem |
| `metadata_json` | Optional JSON metadata |

## Metrics

### `GET /metrics`

Prometheus text format.

Important metrics:

| Metric | Type |
|---|---|
| `ntc_packets_per_second` | gauge |
| `ntc_bytes_per_second` | gauge |
| `ntc_packets_total{proto}` | counter |
| `ntc_bytes_total{proto}` | counter |
| `ntc_direction_packets_total{direction}` | counter |
| `ntc_direction_bytes_total{direction}` | counter |
| `ntc_action_packets_total{action}` | counter |
| `ntc_action_bytes_total{action}` | counter |
| `ntc_active_ips` | gauge |
| `ntc_active_flows` | gauge |
| `ntc_ip_packets_per_second{ip}` | gauge |
| `ntc_ip_bytes_per_second{ip}` | gauge |
| `ntc_ip_unique_dst_ports{ip}` | gauge |
| `ntc_ip_syn_count{ip}` | gauge |
| `ntc_ip_ack_count{ip}` | gauge |

