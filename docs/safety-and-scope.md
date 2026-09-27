# Safety & Scope

Warden is a defensive tool. It only scans networks the operator is authorized to assess.

- Every scan references a **scope**: CIDR allowlist, authorization record (who approved, document ref), expiry.
- The API rejects scans outside an active scope; the sensor re-validates every target before sending traffic.
- Checks are read-only and non-exploiting. No brute force, no payloads, no writes to targets.
- Network activity is rate-limited with conservative defaults.
- Credentials are Vault references only; never logged, never persisted in Postgres or evidence.

## Sensor-side scope guard (`sensor/discovery/src/guard.rs`)
The sensor never trusts the API's check alone. It re-validates every job itself, and fails closed:

- **No scope, no scan.** A job without a scope is rejected by the schema. An expired scope is rejected by the guard. Both exit `2` before any socket is opened.
- **Whole-job rejection.** If any target is not fully inside the (aggregated) scope CIDRs, the job is refused and the offending targets are listed. Targets are never silently trimmed.
- **IP/CIDR literals only.** Hostnames, zone IDs, CIDRs with host bits set, `/0`, and IPv4-mapped or IPv4-compatible IPv6 are all rejected as ambiguous or bypass-prone.
- **Never-scannable addresses**, even inside a scope: `0.0.0.0/8`, `255.255.255.255`, multicast, `::`.
- **Per-connection expiry.** Every connect re-checks `expires_at`. A scan that crosses it stops, reports `status: partial` / `stopped_reason: scope_expired`, and exits `3`.
- **Size caps.** At most 65,536 hosts and 1,048,576 host/port pairs per job.
- **One egress point.** `guard::connect` is the only socket connect in the crate, and it only accepts a scope-issued `AuthorizedTarget`. `clippy.toml` forbids raw TCP/UDP sockets and DNS lookups everywhere else. CI runs clippy with `-D warnings`.
- **Honest failure.** Only `ECONNREFUSED` means closed, and only a timeout means filtered. Local errors (`EMFILE`, `EADDRNOTAVAIL`, …) abort the job with exit `1` and are never reported as a target's state. Concurrency is clamped to the open-file limit at startup.
- **What is sent:** a TCP handshake, a TLS ClientHello and `HEAD / HTTP/1.0`. Nothing else. Servers may log these (Redis answers `-ERR`, Postgres logs an invalid startup packet).
