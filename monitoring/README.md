# NTC Monitoring

This directory defines the monitoring stack for NetworkTrafficControl.

## Components

| Component | Port | Purpose |
|---|---:|---|
| NTC Go server | `8086` | Exposes the web UI, API, SSE events, and `/metrics` |
| VictoriaMetrics | `8428` | Scrapes and stores NTC metrics |
| Grafana | `3000` | Displays dashboards using VictoriaMetrics as the datasource |

## Data Flow

```text
NTC Go server
  /metrics on port 8086
        |
        | scrape interval: 10s
        v
VictoriaMetrics
  port 8428
        |
        | Grafana datasource
        v
Grafana
  port 3000
```

## Connection Files

| File | Role |
|---|---|
| `internal/api/server.go` | Registers the `/metrics` HTTP route |
| `internal/api/metrics.go` | Writes NTC metrics in Prometheus text format |
| `monitoring/victoria/scrape.yaml` | Configures VictoriaMetrics to scrape NTC |
| `monitoring/docker-compose.yml` | Runs VictoriaMetrics and Grafana |
| `monitoring/grafana/provisioning/datasources/victoria.yaml` | Configures Grafana to query VictoriaMetrics |
| `monitoring/grafana/provisioning/dashboards/*.json` | Defines Grafana dashboards |

## Runtime URLs

Local development:

| URL | Content |
|---|---|
| `http://localhost:8086/metrics` | Raw NTC metrics |
| `http://localhost:8428/vmui/` | VictoriaMetrics query UI |
| `http://localhost:3000` | Grafana |

Raspberry Pi deployment:

| URL | Content |
|---|---|
| `http://rpi.local:8086/metrics` | Raw NTC metrics |
| `http://rpi.local:8428/vmui/` | VictoriaMetrics query UI |
| `http://rpi.local:3000` | Grafana |

## Scrape Configuration

VictoriaMetrics reads this config:

```yaml
global:
  scrape_interval: 10s

scrape_configs:
  - job_name: ntc
    static_configs:
      - targets:
          - host.docker.internal:8086
    metrics_path: /metrics
```

This resolves to:

```text
http://host.docker.internal:8086/metrics
```

`host.docker.internal` is mapped in Docker Compose:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

## Grafana Datasource

Grafana uses VictoriaMetrics through this datasource:

```yaml
datasources:
  - name: VictoriaMetrics
    type: prometheus
    access: proxy
    url: http://victoriametrics:8428
    isDefault: true
```

`victoriametrics` is the Docker Compose service name.

## Dashboards

| Dashboard file | Grafana title |
|---|---|
| `ntc-overview.json` | `NTC — Overview` |
| `ntc-top-talkers.json` | `NTC — Top Talkers` |
| `ntc-security.json` | `NTC — Security` |

## Overview Dashboard

| Panel | Query | Meaning |
|---|---|---|
| Packets / s | `ntc_packets_per_second` | Packet rate in the 60 second window |
| Throughput | `ntc_bytes_per_second` | Byte rate in the 60 second window |
| Active IPs | `ntc_active_ips` | Source IP count in the 60 second window |
| Active Flows | `ntc_active_flows` | Currently tracked flow count |
| Packets Dropped (total) | `ntc_action_packets_total{action="drop"}` | Dropped packet counter |
| Drop Rate % | `100 * ntc_action_packets_total{action="drop"} / clamp_min(sum(ntc_action_packets_total{action=~"pass\|drop"}), 1)` | Dropped packet percentage |
| Packets/s over time | `ntc_packets_per_second` | Packet rate history |
| Throughput over time | `ntc_bytes_per_second` | Byte rate history |
| Packets by Protocol | `ntc_packets_total{proto=...}` | Packet counters by protocol |
| Bytes by Protocol | `ntc_bytes_total{proto=...}` | Byte counters by protocol |
| Ingress vs Egress - Packets | `ntc_direction_packets_total{direction=...}` | Packet counters by direction |
| Actions Distribution | `ntc_action_packets_total{action=...}` | Packet counters by action |
| Ingress vs Egress - Bytes/s | `rate(ntc_direction_bytes_total{direction="ingress"}[1m]) * 60`, `rate(ntc_direction_bytes_total{direction="egress"}[1m]) * 60` | Byte rate by direction |
| Dropped Bytes/s | `rate(ntc_action_bytes_total{action="drop"}[1m]) * 60` | Dropped byte rate |

## Top Talkers Dashboard

| Panel | Query | Meaning |
|---|---|---|
| Top Talkers - Packets/s (live) | `topk(10, ntc_ip_packets_per_second)` | Top source IPs by packet rate |
| Top Talkers - Bytes/s (live) | `topk(10, ntc_ip_bytes_per_second)` | Top source IPs by byte rate |
| Packets/s per IP - over time | `topk(10, ntc_ip_packets_per_second)` | Packet rate history by source IP |
| Bytes/s per IP - over time | `topk(10, ntc_ip_bytes_per_second)` | Byte rate history by source IP |
| Total Bytes - all time | `sum(ntc_bytes_total)` | Total observed bytes |
| Total Packets - all time | `sum(ntc_packets_total)` | Total observed packets |

## Security Dashboard

| Panel | Query | Meaning |
|---|---|---|
| Blocked Packets (total) | `ntc_action_packets_total{action="drop"}` | Dropped packet counter |
| Drop Rate % | `100 * ntc_action_packets_total{action="drop"} / clamp_min(sum(ntc_action_packets_total{action=~"pass\|drop"}), 1)` | Dropped packet percentage |
| Blocked Bytes (total) | `ntc_action_bytes_total{action="drop"}` | Dropped byte counter |
| SSH Bypass Events | `ntc_action_packets_total{action="ssh"}` | SSH bypass packet counter |
| Whitelist Skipped | `ntc_action_packets_total{action="skip"}` | Whitelist skip packet counter |
| IPs with >20 unique ports | `count(ntc_ip_unique_dst_ports > 20) or vector(0)` | Source IP count above the port threshold |
| Blocked Packets/s - over time | `rate(ntc_action_packets_total{action="drop"}[1m]) * 60` | Dropped packet rate |
| Blocked Bytes/s - over time | `rate(ntc_action_bytes_total{action="drop"}[1m]) * 60` | Dropped byte rate |
| Unique Dst Ports per IP - over time (>5) | `ntc_ip_unique_dst_ports > 5` | Destination port count by source IP |
| SYN count per IP - over time | `ntc_ip_syn_count > 10` | SYN packet count by source IP |
| SYN / ACK ratio per IP | `ntc_ip_syn_count / clamp_min(ntc_ip_ack_count, 1)` | SYN to ACK ratio by source IP |
| IPs ranked by unique ports contacted | `topk(10, ntc_ip_unique_dst_ports)` | Top source IPs by destination port count |
| IPs ranked by SYN count | `topk(10, ntc_ip_syn_count)` | Top source IPs by SYN packet count |

## Labels

| Label | Values | Meaning |
|---|---|---|
| `proto` | `tcp`, `udp`, `icmp`, `other` | Protocol group |
| `direction` | `ingress`, `egress` | Packet direction |
| `action` | `pass`, `drop`, `skip`, `ssh` | Firewall action |
| `ip` | IP address | Source IP address |

## Actions

| Action | Meaning |
|---|---|
| `pass` | Packet allowed normally |
| `drop` | Packet dropped by blacklist logic |
| `skip` | Packet allowed by whitelist logic |
| `ssh` | Packet allowed by the TCP port 22 bypass rule |

`drop` is an NTC firewall action. It means the TC eBPF program returned a drop decision for a packet matched by NTC logic. It does not mean ordinary network packet loss, NIC errors, TCP retransmits, or packets dropped by another firewall outside NTC.

## Metrics

| Metric | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `ntc_packets_per_second` | gauge | packets/s | none | Total packet rate in the 60 second window |
| `ntc_bytes_per_second` | gauge | bytes/s | none | Total byte rate in the 60 second window |
| `ntc_packets_total` | counter | packets | `proto` | Packet counter by protocol |
| `ntc_bytes_total` | counter | bytes | `proto` | Byte counter by protocol |
| `ntc_direction_packets_total` | counter | packets | `direction` | Packet counter by direction |
| `ntc_direction_bytes_total` | counter | bytes | `direction` | Byte counter by direction |
| `ntc_action_packets_total` | counter | packets | `action` | Packet counter by action |
| `ntc_action_bytes_total` | counter | bytes | `action` | Byte counter by action |
| `ntc_active_ips` | gauge | IPs | none | Source IP count in the 60 second window |
| `ntc_active_flows` | gauge | flows | none | Currently tracked flow count |
| `ntc_ip_packets_per_second` | gauge | packets/s | `ip` | Packet rate by source IP |
| `ntc_ip_bytes_per_second` | gauge | bytes/s | `ip` | Byte rate by source IP |
| `ntc_ip_unique_dst_ports` | gauge | ports | `ip` | Unique destination port count by source IP in the 60 second window |
| `ntc_ip_syn_count` | gauge | packets | `ip` | TCP SYN packet count by source IP in the 60 second window |
| `ntc_ip_ack_count` | gauge | packets | `ip` | TCP ACK packet count by source IP in the 60 second window |

## Query Examples

```promql
ntc_packets_per_second
ntc_bytes_per_second
topk(10, ntc_ip_packets_per_second)
topk(10, ntc_ip_bytes_per_second)
ntc_action_packets_total{action="drop"}
rate(ntc_action_packets_total{action="drop"}[1m]) * 60
ntc_ip_unique_dst_ports > 20
ntc_ip_syn_count / clamp_min(ntc_ip_ack_count, 1)
```
