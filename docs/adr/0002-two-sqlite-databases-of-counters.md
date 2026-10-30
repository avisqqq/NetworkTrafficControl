# 2. Two SQLite databases, storing counters rather than packets

Status: Accepted — 2026-08-02

## Context

NTC runs on a Raspberry Pi, writing to an SD card. SD cards fail from write
volume, and a Pi has no spare I/O budget. The eBPF program emits an event for
every packet it sees, in both directions, including the ones it passes — tens
to hundreds per second on an idle home network, far more under load.

Two questions had to be answered separately.

**What to store.** Persisting raw packet events is the obvious design and gives
perfect fidelity: any question can be answered later. It also writes unbounded
data to an SD card forever, and the product does not need per-packet history —
the UI and the AI reports ask "who talked to whom, over what service, how
much", which is a small set of aggregates.

**How many databases.** One file is simpler to open, back up and reason about.
But the two workloads have nothing in common. Application logs are low-rate,
written synchronously, one row at a time, and their value is diagnostic —
they are what you read when something is broken. Analytics is high-rate,
buffered in memory for 30s and written as one batched transaction of counter
upserts. SQLite locks per database file, so sharing one file makes the
analytics batch block log writes, exactly when a failing system is trying to
record why it is failing.

## Decision

Two files, opened separately in `infrastructure/storage/db.go`:

- `data/app_logs.db` — one table, append-only application log.
- `data/analytics.db` — hosts, IPs, services, and four counter tables.

Analytics stores **counters, not events**. A row is keyed by
(host, peer, service, direction, action) and updated with
`packets = packets + ?`, so the table grows with the number of distinct
conversations, not with traffic volume. `application/analytics` coalesces in
memory first, so a busy flow costs one row update per flush rather than one per
packet.

## Consequences

- Database size tracks distinct peers and services, which on a home network is
  bounded and small. Write volume is one batched transaction per 30s instead of
  per-packet writes. This is the whole point.
- Questions that need per-packet detail cannot be answered retrospectively.
  There is no "show me that connection at 14:32". Live packet detail exists
  only in the SSE stream, and is gone once seen. Accepting this is the price of
  the design; anyone wanting packet history must add a separate, bounded store
  rather than change these tables.
- Analytics can be disabled at runtime without taking logging down with it: on
  a fatal SQLite write error the analytics service sets `writesDisabled` and
  drops its buffer, so a dying SD card degrades into "no analytics" instead of
  "no service". This is only possible because the databases are separate.
- Two files to back up, migrate and reason about, and two `AutoMigrate` model
  sets. Accepted.
- Both run in SQLite's default rollback-journal mode. If WAL is ever enabled,
  the shutdown path in `run()` becomes load-bearing rather than tidy — see
  `storage.Close`.
