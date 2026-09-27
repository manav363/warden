# ADR 0001 — NATS JetStream over Celery for jobs and events

- **Status:** Accepted
- **Date:** 2026-09-27

## Context
Scan work is a pipeline of async stages (discover → fingerprint → collect → correlate → score → report) run by workers in **two languages**: the Rust discovery engine and the Python collectors/services. Sensors sit inside customer networks and may only connect **outbound** to the control plane. Failed jobs must be retried a bounded number of times and then parked for inspection, not lost.

Celery is Python-only, so the Rust sensor would need a separate protocol. It relies on a broker (Redis or RabbitMQ) whose delivery guarantees depend on configuration, and it has no first-class dead-letter concept on Redis.

## Decision
Use **NATS JetStream** for job queues, domain events (`facts.ingested`, `findings.created`), and dead-lettering.

- Durable streams with explicit acks and `max_deliver`. Messages that exceed it are routed to a DLQ stream.
- Sensors hold one outbound (later mTLS) connection and **pull** jobs, so the target network needs no inbound firewall rules.
- Official clients exist for Rust (`async-nats`) and Python (`nats-py`).

## Consequences
- One more piece of infrastructure to run (a single binary; clustering is needed in prod).
- The retry, idempotency and scheduling that Celery provides out of the box are built in the orchestrator instead. Idempotency is required anyway (hard rule #5: keyed by `(scan_id, host_id, stage)`).
- Subject names and payload contracts live in `packages/schemas/` and are versioned there.
