# Database Schema

NTC uses SQLite through Gorm. There are two separate databases by default:

| Config key | Default path | Content |
|---|---|---|
| `app_logs.path` | `./data/app_logs.db` | Structured app logs |
| `analytics.path` | `./data/analytics.db` | Aggregated traffic analytics |

The tables are auto-migrated at startup.

## App Log Database

### `app_log`

Source model: `source/infrastructure/storage/gorm/models/appLog.go`

| Column | Type intent | Notes |
|---|---|---|
| `id` | integer primary key | Gorm primary key |
| `created_at` | timestamp | Indexed directly and with several compound indexes |
| `level` | string, max 16 | `INFO`, `WARN`, `ERROR` |
| `category` | string, max 32 | `system`, `list`, `firewall`, `storage`, `network`, `inspect` |
| `event` | string, max 128 | Structured event name |
| `message` | text | Human-readable message |
| `entity_type` | string, max 64 | Optional entity kind |
| `entity_id` | string, max 255 | Optional entity identifier |
| `actor` | string, max 64 | `system`, `api`, `user` |
| `source` | string, max 64 | `startup`, `http`, `ebpf`, `storage`, `list_manager`, `inspection` |
| `metadata_json` | text | Optional JSON metadata |

Important event names:

| Event | Meaning |
|---|---|
| `service.started` | Service startup |
| `config.loaded` | Config loaded |
| `whitelist.added` / `whitelist.removed` | Whitelist changed |
| `blacklist.added` / `blacklist.removed` | Blacklist changed |
| `onlylocal.added` / `onlylocal.removed` | Only-local list changed |
| `localnet.added` / `localnet.removed` | Local CIDR list changed |
| `api.error` | HTTP/API error |
| `storage.error` | Storage error |
| `packet.inspect.requested` | Packet inspection requested |
| `geo.lookup.skipped` | Geo lookup skipped |
| `geo.lookup.succeeded` | Geo lookup succeeded |
| `geo.lookup.failed` | Geo lookup failed |

## Analytics Database

Source models: `source/infrastructure/storage/gorm/models/analytics.go`

The analytics database stores counters, not raw packet captures.

### `hosts`

Represents local hosts observed by NTC.

| Column | Type intent | Notes |
|---|---|---|
| `id` | integer primary key | Internal key |
| `ip` | string, max 64 | Unique host IP |
| `hostname` | string, max 255 | Reserved for hostname enrichment |
| `mac` | string, max 64 | Reserved for MAC enrichment |
| `first_seen` | timestamp | First observation |
| `last_seen` | timestamp | Last observation, indexed |

### `ips`

Represents any observed IP, local or remote.

| Column | Type intent | Notes |
|---|---|---|
| `id` | integer primary key | Internal key |
| `ip` | string, max 64 | Unique IP |
| `scope` | string, max 64 | Scope from inspection logic |
| `first_seen` | timestamp | First observation |
| `last_seen` | timestamp | Last observation, indexed |

### `ip_enrichment`

Stores geo/network enrichment for an IP.

| Column | Type intent | Notes |
|---|---|---|
| `ip_id` | integer primary key | References `ips.id` |
| `provider` | string, max 64 | Example: `ip-api` |
| `country` | string, max 128 | Country name |
| `country_code` | string, max 16 | Indexed |
| `continent` | string, max 128 | Continent name |
| `city` | string, max 128 | City |
| `timezone` | string, max 128 | Timezone |
| `asn` | string, max 128 | Indexed |
| `as_name` | string, max 255 | AS name |
| `isp` | string, max 255 | ISP |
| `org` | string, max 255 | Organization |
| `proxy` | boolean | Indexed |
| `hosting` | boolean | Indexed |
| `mobile` | boolean | Indexed |
| `updated_at` | timestamp | Indexed |

### `services`

Represents protocol and port pairs.

| Column | Type intent | Notes |
|---|---|---|
| `id` | integer primary key | Internal key |
| `proto` | string, max 16 | Unique with `port` |
| `port` | integer | Unique with `proto` |
| `name` | string, max 128 | Service name from inspection |

### `host_peer_counters`

Main host-to-peer traffic counter.

Primary key:

```text
host_ip_id, peer_ip_id, service_id, direction, action
```

| Column | Type intent | Notes |
|---|---|---|
| `host_ip_id` | integer | Local host IP, references `ips.id` |
| `peer_ip_id` | integer | Peer IP, references `ips.id` |
| `service_id` | integer | References `services.id` |
| `direction` | string, max 16 | `INGRESS` or `EGRESS` |
| `action` | string, max 32 | Packet action |
| `packets` | integer counter | Accumulated packets |
| `bytes` | integer counter | Accumulated bytes |
| `first_seen` | timestamp | First observation |
| `last_seen` | timestamp | Last observation, indexed |

This is the most useful table for reports, peer summaries, top talkers, and timeline-style analysis.

### `host_service_counters`

Aggregates traffic by host and service.

Primary key:

```text
host_ip_id, service_id, direction, action
```

| Column | Type intent | Notes |
|---|---|---|
| `host_ip_id` | integer | Local host IP |
| `service_id` | integer | Service |
| `direction` | string, max 16 | `INGRESS` or `EGRESS` |
| `action` | string, max 32 | Packet action |
| `packets` | integer counter | Accumulated packets |
| `bytes` | integer counter | Accumulated bytes |

### `host_country_counters`

Aggregates traffic by host and peer country.

Primary key:

```text
host_ip_id, country_code, direction, action
```

| Column | Type intent | Notes |
|---|---|---|
| `host_ip_id` | integer | Local host IP |
| `country_code` | string, max 16 | Country code or `UNKNOWN` |
| `direction` | string, max 16 | `INGRESS` or `EGRESS` |
| `action` | string, max 32 | Packet action |
| `packets` | integer counter | Accumulated packets |
| `bytes` | integer counter | Accumulated bytes |

### `blocked_peer_counters`

Aggregates blocked peer traffic.

Primary key:

```text
host_ip_id, peer_ip_id, service_id
```

| Column | Type intent | Notes |
|---|---|---|
| `host_ip_id` | integer | Local host IP |
| `peer_ip_id` | integer | Blocked peer IP |
| `service_id` | integer | Service |
| `packets` | integer counter | Accumulated packets |
| `bytes` | integer counter | Accumulated bytes |
| `first_seen` | timestamp | First blocked observation |
| `last_seen` | timestamp | Last blocked observation, indexed |

## Analytics Write Behavior

The analytics service batches packet stats in memory and flushes them periodically.

Important behavior:

- Flush interval is currently 30 seconds.
- Pending stat keys are capped to protect memory.
- Temporary SQLite lock errors are retried by putting records back into the pending map.
- Fatal SQLite disk I/O failures disable analytics writes so the running packet service can continue.

## Summary Queries

Current public summary endpoints read from the counter tables:

| Endpoint | Repository method | Purpose |
|---|---|---|
| `/analysis/summary` | `Summary(limit)` | Global top peers, services, countries, blocked rows, totals |
| `/analysis/host` | `HostSummary(ip, limit)` | Same summary shape filtered to one host |
