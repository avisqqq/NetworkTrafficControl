package api

import (
	"fmt"
	"net/http"
	"strings"

	"ntc/internal/stats"
)

func metricsHandler(tracker *stats.IPTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := tracker.Snapshot()
		c := snap.Counters

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		var b strings.Builder

		// ── Traffic rate (60s sliding window) ────────────────────────────────
		metric(&b, "gauge", "ntc_packets_per_second",
			"Total packets per second (60s sliding window avg)")
		fmt.Fprintf(&b, "ntc_packets_per_second %.2f\n\n", snap.TotalPktsPerSec)

		metric(&b, "gauge", "ntc_bytes_per_second",
			"Total bytes per second (60s sliding window avg)")
		fmt.Fprintf(&b, "ntc_bytes_per_second %.2f\n\n", snap.TotalBytesPerSec)

		// ── Protocol breakdown (counters) ─────────────────────────────────────
		metric(&b, "counter", "ntc_packets_total",
			"Total packets since start, by protocol")
		fmt.Fprintf(&b, "ntc_packets_total{proto=\"tcp\"} %d\n", c.PktsTCP)
		fmt.Fprintf(&b, "ntc_packets_total{proto=\"udp\"} %d\n", c.PktsUDP)
		fmt.Fprintf(&b, "ntc_packets_total{proto=\"icmp\"} %d\n", c.PktsICMP)
		fmt.Fprintf(&b, "ntc_packets_total{proto=\"other\"} %d\n\n", c.PktsOther)

		metric(&b, "counter", "ntc_bytes_total",
			"Total bytes since start, by protocol")
		fmt.Fprintf(&b, "ntc_bytes_total{proto=\"tcp\"} %d\n", c.BytesTCP)
		fmt.Fprintf(&b, "ntc_bytes_total{proto=\"udp\"} %d\n", c.BytesUDP)
		fmt.Fprintf(&b, "ntc_bytes_total{proto=\"icmp\"} %d\n", c.BytesICMP)
		fmt.Fprintf(&b, "ntc_bytes_total{proto=\"other\"} %d\n\n", c.BytesOther)

		// ── Direction breakdown ───────────────────────────────────────────────
		metric(&b, "counter", "ntc_direction_packets_total",
			"Total packets since start, by direction")
		fmt.Fprintf(&b, "ntc_direction_packets_total{direction=\"ingress\"} %d\n", c.PktsIngress)
		fmt.Fprintf(&b, "ntc_direction_packets_total{direction=\"egress\"} %d\n\n", c.PktsEgress)

		metric(&b, "counter", "ntc_direction_bytes_total",
			"Total bytes since start, by direction")
		fmt.Fprintf(&b, "ntc_direction_bytes_total{direction=\"ingress\"} %d\n", c.BytesIngress)
		fmt.Fprintf(&b, "ntc_direction_bytes_total{direction=\"egress\"} %d\n\n", c.BytesEgress)

		// ── Action breakdown ──────────────────────────────────────────────────
		metric(&b, "counter", "ntc_action_packets_total",
			"Total packets since start, by firewall action")
		fmt.Fprintf(&b, "ntc_action_packets_total{action=\"pass\"} %d\n", c.PktsPass)
		fmt.Fprintf(&b, "ntc_action_packets_total{action=\"drop\"} %d\n", c.PktsDrop)
		fmt.Fprintf(&b, "ntc_action_packets_total{action=\"skip\"} %d\n", c.PktsSkip)
		fmt.Fprintf(&b, "ntc_action_packets_total{action=\"ssh\"} %d\n\n", c.PktsSSH)

		metric(&b, "counter", "ntc_action_bytes_total",
			"Total bytes since start, by firewall action")
		fmt.Fprintf(&b, "ntc_action_bytes_total{action=\"pass\"} %d\n", c.BytesPass)
		fmt.Fprintf(&b, "ntc_action_bytes_total{action=\"drop\"} %d\n\n", c.BytesDrop)

		// ── Session state ─────────────────────────────────────────────────────
		metric(&b, "gauge", "ntc_active_ips",
			"Distinct source IPs seen in the last 60s")
		fmt.Fprintf(&b, "ntc_active_ips %d\n\n", snap.ActiveIPs)

		metric(&b, "gauge", "ntc_active_flows",
			"Currently tracked flows in the flow table")
		fmt.Fprintf(&b, "ntc_active_flows %d\n\n", snap.ActiveFlows)

		// ── Per-IP top-talkers ────────────────────────────────────────────────
		metric(&b, "gauge", "ntc_ip_packets_per_second",
			"Packets per second per source IP (60s avg), top 10")
		for _, t := range snap.TopTalkers {
			fmt.Fprintf(&b, "ntc_ip_packets_per_second{ip=%q} %.2f\n", t.IP, t.PktsPerSec)
		}
		b.WriteByte('\n')

		metric(&b, "gauge", "ntc_ip_bytes_per_second",
			"Bytes per second per source IP (60s avg), top 10")
		for _, t := range snap.TopTalkers {
			fmt.Fprintf(&b, "ntc_ip_bytes_per_second{ip=%q} %.2f\n", t.IP, t.BytesPerSec)
		}
		b.WriteByte('\n')

		// ── Security indicators ───────────────────────────────────────────────
		metric(&b, "gauge", "ntc_ip_unique_dst_ports",
			"Unique destination ports contacted by source IP in last 60s (port scan signal)")
		for ip, ws := range snap.Windows {
			if ws.UniqueDstPorts > 0 {
				fmt.Fprintf(&b, "ntc_ip_unique_dst_ports{ip=%q} %d\n", ip, ws.UniqueDstPorts)
			}
		}
		b.WriteByte('\n')

		metric(&b, "gauge", "ntc_ip_syn_count",
			"TCP SYN packets from source IP in last 60s (SYN flood signal)")
		for ip, ws := range snap.Windows {
			if ws.SynCount > 0 {
				fmt.Fprintf(&b, "ntc_ip_syn_count{ip=%q} %d\n", ip, ws.SynCount)
			}
		}
		b.WriteByte('\n')

		metric(&b, "gauge", "ntc_ip_ack_count",
			"TCP ACK packets from source IP in last 60s")
		for ip, ws := range snap.Windows {
			if ws.AckCount > 0 {
				fmt.Fprintf(&b, "ntc_ip_ack_count{ip=%q} %d\n", ip, ws.AckCount)
			}
		}
		b.WriteByte('\n')

		fmt.Fprint(w, b.String())
	}
}

func metric(b *strings.Builder, typ, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}
