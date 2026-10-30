# 4. nftables enforces, eBPF and NFLOG observe

Status: Accepted — 2026-08-02

## Context

NTC started as a monitor and is growing a management half: block a device,
block a peer, block a port for one host. That half is a firewall, and the
question was whether to grow one inside the existing eBPF program or to drive
the one Linux already has.

### What we have today

`tc_filter.bpf.c` both observes and enforces. It matches a single IP against
hash maps and returns `TC_ACT_SHOT`, emitting an event tagged `ACT_DROP`,
`ACT_SKIP`, `ACT_ONLY_LOCAL_DROP` or `ACT_SSH_BYPASS`. Observation and
enforcement are the same code path, which is why every event carries a verdict.

### What a firewall needs that we do not have

Five-tuple matching, port ranges, CIDR sets, rule ordering with a default
policy, awareness of NAT, rules that survive a reboot, and a ruleset any admin
can read with a standard tool. All of these are work, but all of them are
tractable.

One is not: **connection state**.

A packet arriving from the internet is either a reply to something one of our
devices asked for, or an unsolicited attempt. Told apart, the entire edge
policy is two lines — accept `established,related`, drop `new`. Not told apart,
the best a stateless filter can do is "accept anything from port 443", which an
attacker satisfies by choosing their source port. The kernel tells them apart
because conntrack remembers outgoing connections. Our eBPF program remembers
nothing; it judges each packet alone.

Writing conntrack in eBPF means per-protocol timeouts, expiry of dead entries,
and correct behaviour under NAT. Cilium has done it and it is thousands of
lines. It is not a weekend.

### What the product actually needs

Worth stating honestly, because it nearly changes the answer. Behind NAT,
inbound traffic is already unreachable — not because a firewall blocks it, but
because there is no route in. The rules this product is really about are
outbound and forwarded:

- this device has no internet
- this device may not reach port 25
- this peer is blocked for everyone
- this device is offline after 22:00

**Every one of those is stateless**, and the current eBPF program could grow to
handle them. State becomes necessary only for edge policy and port forwarding —
which is exactly where the product is heading once it is worth trusting.

### The two facts that decided it

**nftables is already running on this Pi.** The gateway needs a `masquerade`
rule for NAT or the LAN has no internet. Someone configured that outside this
repository. So the choice was never "add a firewall or not" — it was "manage
the firewall that is already there, or keep acting beside it without seeing
it".

**Two enforcement planes cannot coexist cleanly**, because the kernel's hook
order is asymmetric:

    inbound:   NIC -> [tc ingress: eBPF] -> [netfilter: nftables] -> routing
    outbound:  routing -> [netfilter: nftables] -> [tc egress: eBPF] -> NIC

Inbound, eBPF wins and an nftables rule never fires. Outbound, nftables wins
and the packet never reaches eBPF — so it vanishes from the live stream and the
metrics. In a tool whose whole value is visibility, silent disappearance is the
worst possible failure. "What dropped this packet?" would have two answers in
two places, and which one applies depends on direction.

## Decision

**One plane enforces. The others only observe.**

### nftables enforces

All drop and accept decisions move to nftables, in a table we own: `inet ntc`.
Driven from Go over netlink with [`google/nftables`](https://github.com/google/nftables)
— pure Go, no cgo, no dependency on the `nft` binary, used in production by
Tailscale since v1.48 for the same job.

We never touch tables we did not create. The NAT rules that make the gateway
work are not ours, and breaking them takes the network down.

### eBPF observes

`tc_filter.bpf.c` keeps its TC attachment and loses `TC_ACT_SHOT`. It becomes
pure telemetry: the live packet stream, per-IP windows, top talkers. This is the
thing no ordinary firewall offers, and it is wasted on a job the kernel has done
well for twenty years.

### NFLOG reports verdicts

Logging in nftables is opt-in per rule: a packet reaches userspace only if the
rule that matched it says `log group N`. Two groups, with distinct meaning:

- **group 1 — denied.** Packets a rule dropped.
- **group 2 — explicitly allowed.** Packets an allow rule let through on
  purpose, as opposed to traffic that merely fell through to the default. This
  is the audit trail for "why was this permitted".

Read with [`florianl/go-nflog`](https://pkg.go.dev/github.com/florianl/go-nflog/v2)
(pure Go, cross-compiles to ARM). Every logging rule carries `prefix` so the
record says which rule fired, and a rate limit so a flood cannot turn the Pi
into a log shipper.

The NFLOG adapter implements the existing `packetstream.Reader`, so it plugs in
beside the eBPF reader and every downstream consumer — SSE, metrics, analytics
— is unchanged. `Dispatcher` grows from one reader to several.

## Consequences

### The event stream changes meaning — this is the big one

Today an eBPF event carries a verdict, because eBPF made it. After this change
it cannot: the verdict happens later, in netfilter. An eBPF event becomes
**"seen at the interface"**, not "passed".

So `ACT_PASS` / `ACT_DROP` / `ACT_SKIP` / `ACT_ONLY_LOCAL_DROP` /
`ACT_SSH_BYPASS` retire from the eBPF path. That reaches further than it
sounds: `domain/packet.Action`, the action counters in metrics, the `action`
column in the analytics counter tables, and the action column in the UI. This
is the migration, and it should be planned as one rather than discovered.

### The same packet legitimately appears twice

An outbound packet that nftables later drops is seen by eBPF at `tc ingress`
(before netfilter) *and* reported in NFLOG group 1. That is not duplication to
be deduplicated — they are two different statements:

- eBPF: *this was attempted*
- NFLOG: *this was denied*

Both are true and both are worth showing. They must not be summed into one
"total packets" figure, and the UI has to present attempt and verdict as
separate columns rather than merging them into a single status.

### Visibility loss is narrower than it first appears

With eBPF attached to the LAN-side interface (`network.interfaces[0]`, `wlan0`):

| traffic | still visible in eBPF despite an nftables drop? |
| --- | --- |
| what our devices attempt outbound | **yes, in full** — eBPF runs before netfilter here |
| inbound traffic nftables dropped | no — NFLOG group 1 covers it |

The first row is the core value of the product and is not affected. This
depends on which interface eBPF is attached to, which is configuration, so the
property is not free — it holds for the LAN-side attachment we use.

### Group 2 is the expensive one

Logging denials is cheap because denials are rare. Logging allows is only cheap
while allow rules match narrowly. A `log` on a broad accept would copy a large
share of all traffic to userspace, which is strictly worse than the eBPF ring
buffer that already reports it. Group 2 stays on specific allow rules, always
rate-limited, and never on a catch-all.

### Costs we are accepting

- **Header parsing in Go.** eBPF hands over a parsed struct; NFLOG hands over a
  raw packet. Roughly a hundred lines of IPv4/IPv6 and TCP/UDP parsing, with
  the usual bounds-checking traps. It needs tests.
- **Field impedance.** `packet.Packet` wants `Seq`, `Ts` (nanoseconds since
  boot), `Direction`. From NFLOG these are synthesised: a local counter, a
  wall-clock timestamp, and the in/out interface. The two sources do not line up
  perfectly and the gaps are filled by decision, not by measurement.
- **Two moving parts instead of one.** A rule now exists in nftables, not in a
  map we own. Debugging spans our table and the kernel's state.

### What we gain

- Connection state, for free and correct, including under NAT.
- Sets with per-element timeouts: `add element inet ntc blocked { 45.10.20.30
  timeout 1h }` and the kernel expires it. This is the enforcement primitive for
  the attack-detection work that motivated the whole question — detect, add
  element, let it lapse. In eBPF we would have written the expiry ourselves.
- Atomic ruleset replacement, which makes apply-then-confirm-or-roll-back
  possible. That is the proper form of the lock-out protection that ADR 0003
  currently implements as a hardcoded port number.
- `nft list ruleset` shows our rules to any admin, with no NTC-specific tooling.
- Per-element counters answer "which blocked address is hammering us" without
  logging a single packet.

### Follow-on, not part of this decision

`application/traffic/flow` reconstructs flows from packets with a 30s idle and
60s flush timeout. The kernel already tracks flows and can stream new/update/
destroy events over netlink ([`ti-mo/conntrack`](https://github.com/ti-mo/conntrack),
pure Go), including per-direction counters and NAT resolution our tracker cannot
see. Replacing `flow.Tracker` with a subscription is attractive and explicitly
out of scope here.

### Relationship to ADR 0003

ADR 0003 records that SSH bypasses the blacklist, implemented as a literal `22`
in the eBPF program. When enforcement moves, that exemption is re-expressed as
an nftables rule and can finally be stateful and narrowed by source. ADR 0003
stands until then, and is superseded by whatever records that rule.

## Alternatives rejected

**Extend eBPF into a full firewall.** Rejected on state. Without conntrack there
is no meaningful inbound policy, ever, and we would additionally be
reimplementing matching semantics — ordering, ranges, sets — that nftables
already has. Attractive because it keeps one plane and gives perfect attribution
(the event knows which rule killed it); not attractive enough.

**Both planes enforce.** Rejected on the hook-order asymmetry above.

**Performance as an argument for eBPF.** Considered and discarded. Benchmarks
showing XDP/eBPF beating nftables under SYN flood are real and irrelevant at
home-gateway scale; a Pi runs nftables with conntrack at line rate here.

**`ngrok/firewall_toolkit`** — a nicer API over `google/nftables`, with sets and
rule identity built in. Rejected for now: it documents poor ARM compatibility
via its `gopacket` dependency, which is precisely our target.

**`coreos/go-iptables` or shelling out to `nft`.** Rejected: shelling out means
parsing text output, and iptables is the legacy interface.

## Assumptions to verify before building on this

Both are load-bearing and neither has been measured on our hardware:

1. **The hook order.** Everything above rests on eBPF-before-netfilter inbound
   and netfilter-before-eBPF outbound. One rule with a counter and one ping
   through the gateway settles it.
2. **`google/nftables` on arm64.** Pure Go should mean it just works. "Should"
   is not a test.

The smallest experiment that answers both: create `inet ntc` with one drop rule
and one `log group 1` from Go, confirm it blocks, read its counter, and watch
what the SSE stream shows for that address in each direction.