# Warden — agentless vulnerability & network scanner

Flagship project. Remotely inspects Windows machines and networks **without installing an agent on targets**, discovers services/configurations, identifies vulnerabilities, correlates them with known CVEs, prioritizes risk, and produces actionable remediation guidance.

**Read `docs/architecture.md` before any design decision.** Follow it. If you want to deviate, propose an ADR in `docs/adr/NNNN-title.md` first and wait for approval.

## Stack
- `services/*` — Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2, Alembic; managed with **uv**; lint/type/test: ruff, mypy (strict), pytest
- `sensor/discovery` — Rust (tokio); `cargo clippy -- -D warnings`, `cargo test`
- `sensor/collectors/windows` — Python (impacket, pywinrm, ldap3)
- `apps/web` — React + TypeScript (strict), Vite, TanStack Query (server state), Zustand (UI/client state only — never mix the two), CSR app
- Messaging — NATS JetStream (jobs, events, dead-letter)
- Data — PostgreSQL (source of truth), Redis (cache, locks, progress), MinIO/S3 (raw evidence, reports), HashiCorp Vault (credentials)
- Infra — `deploy/docker-compose.yml` for local; k3s + Argo CD + Kyverno later (GitOps)
- Observability — OpenTelemetry → Prometheus / Loki / Tempo / Grafana, wired in from the first service

## Hard rules (non-negotiable)
1. **Read-only, non-exploiting checks only.** No payloads, no brute force, no write operations on targets.
2. **Every scan is validated against an authorized scope** (CIDR allowlist + authorization record + expiry) in the API *and* re-checked in the sensor before sending a packet.
3. **Credentials never touch Postgres, logs, or evidence.** Store only Vault references; sensors get short-lived leases per job.
4. **Sensors collect facts; all vulnerability logic lives in `services/correlation`.** Stored facts can be re-evaluated when new CVEs arrive without re-scanning.
5. **Every pipeline stage is idempotent**, keyed by `(scan_id, host_id, stage)`.
6. **Sync vs async per side-effect:** API calls validate + enqueue and return 202; discovery/collection/correlation/scoring/reporting run as jobs.
7. Rate-limit all network activity; sane defaults (conservative concurrency) per subnet.
8. Services are stateless; no local session state.

## Conventions
- Job/fact contracts live in `packages/schemas/` (JSON Schema) — change the schema first, then producers/consumers.
- Misconfiguration checks are **data** (`checks/**/*.yaml`), evaluated by `services/correlation/rules_engine`.
- Structured JSON logging everywhere; include `scan_id`, `host_id`, `stage`, trace ids.
- Config via env vars prefixed `WARDEN_` (see `.env.example`).
- Tests next to the code they cover; recorded lab fact snapshots go in `services/correlation/tests/fixtures/`.

## Workflow
- Work **one milestone at a time** (see `docs/architecture.md` §9 and `docs/ROADMAP.md`). Plan first, then implement.
- Write tests alongside code; run them (and linters) before saying something is done.
- Small, focused commits with clear messages. Update `docs/ROADMAP.md` checkboxes as milestones land.
- When a new convention is agreed, add it to this file.

## Commands
- `make up` / `make down` — local infra
- `make api-dev`, `make api-test`
- `make discovery-build`, `make discovery-test`
- `make lint`
