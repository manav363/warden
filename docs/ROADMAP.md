# Roadmap

Tick items as they land. One milestone per Claude Code session: plan → build → test → commit.

## M0 — Foundation
- [x] `deploy/docker-compose.yml`: Postgres, Redis, NATS (JetStream), MinIO (Chainguard, see ADR 0003), Vault (dev)
- [x] `services/api`: uv project, FastAPI `/health`, config, structured logging, OTel hook
- [x] `sensor/discovery`: Rust crate skeleton + CLI
- [x] `.github/workflows/ci.yml`: ruff, mypy, pytest, clippy, cargo test, gitleaks
- [x] ADR 0001 (NATS over Celery), ADR 0002 (Rust discovery / Python collectors), ADR 0003 (object storage — Proposed)

## M1 — Discovery
### M1a — Contracts + sensor scan
- [x] `packages/schemas/jobs/`: `discover_job` / `discover_result` JSON Schemas (format validation on)
- [x] Sensor scope guard: sole egress point, fail-closed, per-connection expiry, clippy-enforced
- [x] `warden-discovery scan`: rate-limited connect scan, banner grab, TLS cert summary, partial results
- [x] Hermetic tests + compose integration test (CI job `discovery-integration`)

### M1b — Job transport (NATS)
- [ ] Orchestrator publishes discover jobs; sensor pulls, acks, publishes results; DLQ

### M1c — Persistence + API
- [ ] API models: scopes, scans, scan_jobs, assets, services (Alembic)
- [ ] API-side scope guard; `POST /scans` → 202
- [ ] Discover results → assets/services

### M1d — Dashboard
- [ ] Minimal dashboard: scopes, scans, assets

## M2 — Windows collection
## M3 — Intel + correlation
## M4 — Risk + remediation
## M5 — Production-grade
