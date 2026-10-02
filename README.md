# Warden

An **agentless vulnerability and network scanner**, built in the open and still early.

[![CI](https://img.shields.io/github/actions/workflow/status/manav363/warden/ci.yml?style=flat-square&label=CI)](https://github.com/manav363/warden/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/sensor-Rust-DEA584?style=flat-square&logo=rust&logoColor=black)
![Python](https://img.shields.io/badge/api-Python%203.12-3776AB?style=flat-square&logo=python&logoColor=white)
[![License](https://img.shields.io/badge/license-MIT-00D4AA?style=flat-square)](LICENSE)

The goal is a system that inspects Windows machines and networks **without installing an agent on
the targets**: a small sensor inside the target network discovers hosts and services, a central
control plane turns collected facts into CVE findings, and a risk engine ranks them. The full
target design is in [`docs/architecture.md`](docs/architecture.md).

> **Status: early.** The foundation (M0) and the first discovery milestone (M1a) are done; most of the system below is still design. Only part of this exists today. See
> [What works today](#what-works-today) before reading the architecture document as a
> description of the running system.

## What works today

| Piece | State |
|---|---|
| **Discovery sensor** (`sensor/discovery`, Rust) | **Working.** Reads a JSON job, scans only what the job's scope authorizes, writes a JSON result: open / closed / filtered state per port, banner grab, TLS certificate summary. Rate-limited, with a fail-closed scope guard. |
| **Job contracts** (`packages/schemas`) | **Working.** JSON Schemas for `discover_job` and `discover_result`, with an example job. |
| **API** (`services/api`, FastAPI) | **Skeleton.** `GET /health`, typed config, JSON logging, OpenTelemetry hook. No scans, assets or findings yet. |
| **Local infrastructure** (`deploy/docker-compose.yml`) | **Working.** Postgres, Redis, NATS JetStream, MinIO and a dev Vault. Nothing but the sensor's integration test uses them yet. |
| Job transport over NATS, persistence, scope API, dashboard | Planned (M1b–M1d) |
| Windows collection (WinRM / WMI / SMB), CVE correlation, risk scoring, reports | Planned (M2–M5) |

The roadmap with checkboxes is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Safety and scope

Warden is a defensive tool and is designed so that it cannot be pointed at something it has not
been authorized to scan. The sensor does not trust the API's check alone; it re-validates every
job and **fails closed**:

- A job without a scope is rejected by the schema, and an expired scope by the guard. Both exit
  before a socket is opened.
- If any target is outside the scope, the **whole job is refused**; targets are never trimmed.
- Targets are IP / CIDR literals only. Hostnames, ambiguous CIDRs and IPv4-mapped IPv6 are rejected.
- `guard::connect` is the **only** place in the crate that opens a socket, and it only accepts a
  scope-issued target. `clippy.toml` forbids raw sockets and DNS lookups everywhere else, and CI
  runs clippy with `-D warnings`.
- Checks are read-only: a TCP handshake, a TLS ClientHello and `HEAD / HTTP/1.0`. No payloads, no
  brute force, no writes to targets.

The complete rules are in [`docs/safety-and-scope.md`](docs/safety-and-scope.md). **Only scan
systems you own or are explicitly authorized to assess.**

## Try the sensor

Needs a Rust toolchain. This scans a throwaway listener on your own machine:

```bash
cd sensor/discovery && cargo build --release

# something to scan (127.0.0.1 only)
python3 -m http.server 8099 --bind 127.0.0.1 &

cat > /tmp/job.json <<'JSON'
{
  "version": 1,
  "scan_id": "4f5d9a8e-2b1c-4c3d-9e8f-7a6b5c4d3e2f",
  "targets": ["127.0.0.1"],
  "ports": [8099, 8098],
  "scope": {
    "scope_id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
    "cidrs": ["127.0.0.1/32"],
    "expires_at": "2099-01-01T00:00:00Z"
  },
  "limits": { "max_concurrency": 4, "max_rate_per_sec": 20,
              "connect_timeout_ms": 1000, "banner_timeout_ms": 1500 }
}
JSON

./target/release/warden-discovery scan --job /tmp/job.json
```

The result reports port 8099 as `open` with the HTTP banner it returned, counts port 8098 as
`closed`, and `status` is `complete`. Change `targets` to an address outside the scope's CIDRs
(for example `10.0.0.5`) and the sensor refuses the job and exits `2` without sending anything.

Exit codes: `0` complete · `1` runtime error · `2` job rejected, nothing sent · `3` partial
(for example the scope expired mid-scan).

## Development

```bash
make api-test          # FastAPI tests (uv)
make discovery-test    # sensor unit + hermetic tests (cargo)
make lint              # ruff, mypy, clippy
make up                # start local infra
make discovery-it      # scan the local compose stack (127.0.0.1 only)
```

CI (`.github/workflows/ci.yml`) runs ruff, mypy and pytest for the API; clippy and `cargo test`
for the sensor; a compose-based sensor integration test; and a gitleaks scan of the full history.

## Layout

```
sensor/discovery/     Rust discovery engine (scope guard, scan, banner / TLS probes)
services/api/         FastAPI control-plane skeleton
packages/schemas/     JSON Schema contracts for jobs and results
deploy/               docker-compose for local infra (k8s / Argo CD placeholders)
docs/                 architecture, safety and scope, roadmap, ADRs
```

Design decisions are recorded as ADRs in [`docs/adr/`](docs/adr): NATS JetStream over Celery,
Rust for discovery and Python for Windows collectors, and object storage.

## How this was built

Warden is being built with AI coding assistance (Claude Code), one milestone at a time, following
the plan in [`CLAUDE.md`](CLAUDE.md) and the architecture document. What does not depend on trust
is in the repository: a scope guard enforced by a lint rule, tests for it, a roadmap that only
ticks items that landed, and CI that runs on every change.

## License

[MIT](LICENSE)
