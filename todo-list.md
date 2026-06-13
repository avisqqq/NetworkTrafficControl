# TODO List

## Done

- Load local networks on startup into `local_nets_v4` / `local_nets_v6`.
- Read server address, timezone, interface, lease path, and local CIDRs from `config.yaml`.
- Use `network.cidrs` as an override when provided; scan the configured interface only when it is empty.
- Normalize `HostnameHandler` to use injected interface and lease-file values from config.
- Restore `/runtime/state` wiring in the refactored HTTP server.
- Update the source deploy script to copy runtime artifacts: `ntc`, `tc_filter.bpf.o`, `dist/`, and `config.yaml`.
- Add JSON persistence in the `source/*` path:
  - restore blacklist and whitelist into eBPF maps on startup
  - save blacklist and whitelist after API mutations
  - save `mock_mode` from the `-mock` flag
  - keep `onlylocal` non-persistent, matching old storage behavior
- Port real mock mode into the `source/*` path so `-mock` skips eBPF and emits synthetic packets.

## Next

- Clean up CIDR naming/domain shape: use `CIDR`/`PrefixLen` consistently, normalize parsed CIDRs to the network address, and avoid mixing IP-list handlers with CIDR handlers.
- Fix existing vet issues in `source/infrastructure/storage` where `log.Fatalf` uses `%w`.
- Decide final binary entrypoint: `./source` versus `./cmd/ntc`, then remove or archive the stale path.

## Later

- Decide what to do with closed flows: ignore, log, persist to SQLite, export metrics, or expose in UI.
- Remove old duplicate `internal/*` code after the `source/*` path fully replaces it.
- Run full validation without `-vet=off`: `go test ./source/...`.
- Add script checks for local and RPi deploy modes.

## Keep

- `main.go` only wires services.
- HTTP handlers format requests/responses; they do not own packet, metrics, network, or persistence logic.
- Only the packet dispatcher reads packet events directly.
- Consumers receive packets; they do not read the packet reader.
