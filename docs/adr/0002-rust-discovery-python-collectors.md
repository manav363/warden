# ADR 0002 — Rust for discovery, Python for Windows collectors

- **Status:** Accepted
- **Date:** 2026-09-27

## Context
The sensor does two jobs with different profiles:

1. **Network discovery:** sweeping CIDRs, running many concurrent TCP connects, grabbing banners and doing TLS/SMB/RDP handshakes. This is high fan-out, I/O-bound work where predictable memory, precise rate limiting and (later) raw sockets for SYN/ARP matter.
2. **Credentialed Windows collection:** WinRM, WMI/DCOM, MS-RRP over SMB, and LDAP. These protocols are hard to implement, and the mature, audited implementations are all Python (`impacket`, `pywinrm`, `ldap3`).

## Decision
- `sensor/discovery` is written in **Rust** (tokio; `pnet` for raw sockets later).
- `sensor/collectors/windows` is written in **Python** on impacket/pywinrm/ldap3.
- Both only emit **facts** that conform to JSON Schemas in `packages/schemas/`. Neither contains vulnerability logic (hard rule #4).

## Consequences
- Two toolchains in CI (clippy/cargo test and ruff/mypy/pytest).
- The language boundary is the fact contract, which keeps the collectors replaceable. A Windows collector could later be ported to Rust without touching correlation.
- Python stays at 3.12 for impacket compatibility.
