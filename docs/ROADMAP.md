# Roadmap

Tick items as they land. One milestone per Claude Code session: plan → build → test → commit.

## M0 — Foundation
- [x] `deploy/docker-compose.yml`: Postgres, Redis, NATS (JetStream), MinIO (Chainguard, see ADR 0003), Vault (dev)
- [x] `services/api`: uv project, FastAPI `/health`, config, structured logging, OTel hook
- [x] `sensor/discovery`: Rust crate skeleton + CLI
- [x] `.github/workflows/ci.yml`: ruff, mypy, pytest, clippy, cargo test, gitleaks
- [x] ADR 0001 (NATS over Celery), ADR 0002 (Rust discovery / Python collectors), ADR 0003 (object storage — Proposed)

## M1 — Discovery
- [ ] Rust async TCP connect scan + rate limiter + banner grab + JSON output
- [ ] Scope guard (CIDR allowlist + expiry) in API and sensor
- [ ] API models: scopes, scans, scan_jobs, assets, services (Alembic)
- [ ] Orchestrator: scan → discover job over NATS → results → assets
- [ ] Minimal dashboard: scopes, scans, assets

## M2 — Windows collection
## M3 — Intel + correlation
## M4 — Risk + remediation
## M5 — Production-grade
