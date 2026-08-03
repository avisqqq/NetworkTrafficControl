# Architecture Decision Records

One decision per file, numbered, written when the decision is made.

Code shows *what* the system does and git shows *when* it changed. Neither
shows which alternative was rejected, or what it costs to go back — which is
the question anyone asks before touching load-bearing code.

## When to write one

Only when all three are true:

- the decision is hard or expensive to reverse,
- it is not obvious from reading the code,
- there was a real alternative that got rejected.

Choosing `net/http` over a framework needs no record. Letting SSH traffic skip
the blacklist does.

## Format

Three sections: **Context** → **Decision** → **Consequences**. The consequences
matter most, and the negative ones matter more than the positive ones — those
are what a future reader needs in order to judge whether the decision still
holds.

Records are immutable. A decision that changes is not edited: a new record
supersedes it, and the old one gets `Status: Superseded by NNNN`.

## Index

- [0001](0001-hexagonal-layers-and-the-dependency-rule.md): Hexagonal layers and the dependency rule
- [0002](0002-two-sqlite-databases-of-counters.md): Two SQLite databases, storing counters rather than packets
- [0003](0003-ssh-bypass-precedes-the-blacklist.md): SSH traffic bypasses the blacklist
- [0004](0004-nftables-enforces-ebpf-and-nflog-observe.md): nftables enforces, eBPF and NFLOG observe
- [0005](0005-events-and-webhooks.md): Zdarzenia i webhooki zamiast systemu alertów
