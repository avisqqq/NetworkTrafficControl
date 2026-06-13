# NTC Database ERD

NTC uses SQLite through Gorm. By default it has two separate database files:

| Database | Config key | Default path |
|---|---|---|
| App logs | `app_logs.path` | `./data/app_logs.db` |
| Analytics | `analytics.path` | `./data/analytics.db` |

The analytics database stores aggregated counters, not raw packet captures.

## Analytics Database

```mermaid
erDiagram
    ips {
        uint64 id PK
        string ip UK
        string scope
        datetime first_seen
        datetime last_seen
    }

    hosts {
        uint64 id PK
        string ip UK
        string hostname
        string mac
        datetime first_seen
        datetime last_seen
    }

    ip_enrichment {
        uint64 ip_id PK,FK
        string provider
        string country
        string country_code
        string continent
        string city
        string timezone
        string asn
        string as_name
        string isp
        string org
        bool proxy
        bool hosting
        bool mobile
        datetime updated_at
    }

    services {
        uint64 id PK
        string proto UK
        uint16 port UK
        string name
    }

    host_peer_counters {
        uint64 host_ip_id PK,FK
        uint64 peer_ip_id PK,FK
        uint64 service_id PK,FK
        string direction PK
        string action PK
        uint64 packets
        uint64 bytes
        datetime first_seen
        datetime last_seen
    }

    host_service_counters {
        uint64 host_ip_id PK,FK
        uint64 service_id PK,FK
        string direction PK
        string action PK
        uint64 packets
        uint64 bytes
    }

    host_country_counters {
        uint64 host_ip_id PK,FK
        string country_code PK
        string direction PK
        string action PK
        uint64 packets
        uint64 bytes
    }

    blocked_peer_counters {
        uint64 host_ip_id PK,FK
        uint64 peer_ip_id PK,FK
        uint64 service_id PK,FK
        uint64 packets
        uint64 bytes
        datetime first_seen
        datetime last_seen
    }

    ips ||--o| ip_enrichment : enriches
    ips ||--o{ host_peer_counters : host_ip_id
    ips ||--o{ host_peer_counters : peer_ip_id
    services ||--o{ host_peer_counters : service_id
    ips ||--o{ host_service_counters : host_ip_id
    services ||--o{ host_service_counters : service_id
    ips ||--o{ host_country_counters : host_ip_id
    ips ||--o{ blocked_peer_counters : host_ip_id
    ips ||--o{ blocked_peer_counters : peer_ip_id
    services ||--o{ blocked_peer_counters : service_id
```

### Important Keys

`services` has one logical unique key:

```text
proto + port
```

`host_peer_counters` groups traffic by:

```text
host_ip_id + peer_ip_id + service_id + direction + action
```

This powers Top Peers. It answers: which peer IPs did each host talk to, split by service, direction, and firewall action?

`host_service_counters` groups traffic by:

```text
host_ip_id + service_id + direction + action
```

This powers Top Services. It answers: which services did each host use, regardless of peer IP?

`host_country_counters` groups traffic by:

```text
host_ip_id + country_code + direction + action
```

This powers country summaries. Country comes from `ip_enrichment.country_code`; missing enrichment becomes `UNKNOWN`.

`blocked_peer_counters` groups blocked traffic by:

```text
host_ip_id + peer_ip_id + service_id
```

It does not currently split blocked counters by direction or action.

## App Log Database

```mermaid
erDiagram
    app_log {
        uint64 id PK
        datetime created_at
        string level
        string category
        string event
        text message
        string entity_type
        string entity_id
        string actor
        string source
        text metadata_json
    }
```

The app log database is independent from analytics. It has no foreign keys to analytics tables.

## UI Tools For Viewing SQLite

Use any SQLite browser against the two `.db` files on the NTC host:

```text
./data/analytics.db
./data/app_logs.db
```

Good options:

| Tool | Use |
|---|---|
| DB Browser for SQLite | Simple desktop GUI for tables and data |
| DBeaver | Full database UI with diagrams |
| SQLite Viewer VS Code extension | Quick table browsing inside VS Code |

For a quick terminal check:

```bash
sqlite3 ./data/analytics.db ".tables"
sqlite3 ./data/analytics.db ".schema host_peer_counters"
```
