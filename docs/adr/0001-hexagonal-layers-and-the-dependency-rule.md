# 1. Hexagonal layers and the dependency rule

Status: Accepted — 2026-08-02

## Context

NTC mixes things that change at very different rates. The eBPF program, the
ring-buffer reader, the SQLite schema and the HTTP surface all churn; what a
packet *is*, what an action *means*, and how lists are managed barely change at
all. Early on these were interleaved, and the packet reader, the metrics
counters and the HTTP handlers all knew about each other.

Two structures were on the table: package-by-feature (`packets/`, `lists/`,
`analytics/`, each holding its own handler, service and storage), and
package-by-layer with an explicit dependency direction. Package-by-feature
keeps a single change in one directory, which is genuinely useful — but it
gives nothing to enforce, so nothing stops a handler from talking to an eBPF
map again.

## Decision

Three layers, with dependencies pointing one way only:

    domain/          types and rules; imports nothing from this project
    application/     services, orchestration, and the ports they need
    infrastructure/  adapters: eBPF, HTTP, gorm/SQLite, geo, persist

Ports are interfaces, and they live **with the code that calls them**, not in a
shared package. `ListStore` sits in `application/lists` beside its only caller;
`EbpfLoader` in `application/packet`; `Reader` in `application/packetstream`.
Go satisfies interfaces implicitly, so an adapter needs no knowledge that a
port exists.

An earlier attempt put these in `domain/packet/core`. That was wrong twice
over: the interfaces are not domain concepts, and `core` names nothing — it is
`utils` wearing a different hat.

The rule is enforced by `depguard` in `.golangci.yml`, not by memory. `domain`
may import neither of the other two; `application` may not import
`infrastructure`. Breaking it fails the build in CI.

`source/ntc.go` is the composition root and the only place allowed to know
every concrete type at once.

## Consequences

- A single feature is spread across three directories. Adding a field that
  reaches the UI touches `domain`, an application service, and an adapter.
  This is the real cost, paid on every feature.
- The rule cannot rot silently. Anyone can check it in one command, and CI
  checks it on every push. This is why the layered split was worth choosing
  over package-by-feature: it is the option that can be mechanised.
- `infrastructure` **may** import `application` — HTTP handlers and gorm
  repositories consume application services, and that direction is correct.
  What is not correct is importing an application package merely to name a
  constructor's return type; adapters return concrete types
  ("accept interfaces, return structs").
- `EbpfLoader` is a factory interface whose methods return other interfaces, so
  its implementation is forced to import the port package. It also has exactly
  one implementation and no test double. It is a candidate for deletion, with
  `PacketApp.Start` folded into the composition root.
- Mock mode is a whole-layer substitution: `--mock` swaps the reader and list
  manager and nothing downstream notices. That falls out of the rule for free.