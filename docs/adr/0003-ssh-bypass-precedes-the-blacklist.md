# 3. SSH traffic bypasses the blacklist

Status: Accepted, retrospectively — 2026-08-02. See *Open question*.

## Context

NTC runs headless on a Raspberry Pi. In normal operation the only way in is
SSH. The blacklist is an eBPF map that the HTTP API mutates at runtime, and
that API has no authentication in front of it — anything that can reach port
8086 can add an entry.

The failure this guards against is concrete: add the wrong address, or one
broad enough to cover your own workstation, and the Pi drops the traffic
carrying the only tool that could undo the change. Recovery then means a
keyboard and an HDMI cable, physically.

The alternative — checking the blacklist first, so a block really blocks
everything — was not chosen.

## Decision

In `tc_filter.bpf.c`, both `handle_ipv4` and `handle_ipv6` evaluate in this
order, for ingress and egress alike:

1. `onlylocal` — source listed and destination outside the local nets: **drop**
2. TCP with source or destination port 22: **pass**, tagged `ACT_SSH_BYPASS`
3. `blacklist` hit on source or destination: **drop**
4. `whitelist` hit: **pass**, tagged `ACT_SKIP`
5. otherwise: **pass**

Step 2 sits above step 3 deliberately: SSH survives any blacklist entry. Step 1
stays above step 2, so a host confined by `onlylocal` cannot use SSH to escape
its own confinement.

## Consequences

- The API cannot lock the operator out of the machine that hosts it. This is
  the entire reason for the ordering.
- **A blacklisted address still reaches port 22.** The blacklist is therefore
  not a defence against attacks on SSH, and must not be described as one.
  Protecting SSH is the job of key-only authentication, fail2ban, or moving the
  port — not of this program.
- The port is the literal `22` in the eBPF source. Moving `sshd` to another
  port silently removes the escape hatch and restores the lock-out risk. Any
  such change has to be made in both places.
- The bypass applies to both directions, so it also lets a blacklisted address
  be reached *from* the Pi on port 22.
- Bypassed packets are emitted as events with `ACT_SSH_BYPASS`, so the
  behaviour is visible in the live stream and the metrics rather than silent.

## Open question

This record documents the behaviour in the code and makes its cost explicit; it
is not a reconstruction of the original intent, which is not recorded anywhere.
The gap it describes is real and worth an explicit answer:

- Keep as is, and treat SSH as out of scope for NTC's filtering (current state).
- Narrow it, e.g. bypass only for sources inside the local nets, so a remote
  blacklisted address gets no exemption while a LAN workstation keeps its way
  back in.
- Remove it, and accept the lock-out risk in exchange for a blacklist that
  means what it says.

If the second or third is chosen, supersede this record rather than editing it.