# ADR 0003 — Object storage for evidence and reports

- **Status:** Proposed (dev stack uses Chainguard MinIO; the decision must be final before M2 writes evidence)
- **Date:** 2026-09-27

## Context
Warden needs S3-compatible object storage for raw collection evidence (M2) and generated reports (M4). The architecture names MinIO for local dev and S3 in cloud deployments.

During M0, the official `minio/minio` image turned out to be **no longer anonymously pullable** from Docker Hub or Quay: every tag, including `latest` and the old `RELEASE.*` tags, returns `401`. That follows MinIO's 2025 move away from distributing community binaries and images. Pinning "the last release tag" is therefore not possible.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| **Chainguard `chainguard/minio`** (current dev choice) | Same MinIO server, env vars and S3 API; actively rebuilt (M0 pin = `RELEASE.2026-09-22`); ships `mc` for healthchecks | Free tier publishes only `latest`/`latest-dev`, so we pin by digest and bump by hand; depends on a third-party rebuild of an upstream that no longer ships images |
| RustFS | Apache-2.0, real version tags (`1.0.0`) | Young project; different config and console |
| SeaweedFS (`-s3`) | Mature, very widely used | Heavier config (S3 identities via JSON); few versioned tags on Hub |
| Garage | Small, designed for self-hosting | Commit-SHA tags only on Hub; partial S3 API surface |
| AWS S3 / cloud bucket | No self-hosting | Not usable for an offline lab or on-prem deployments |

## Proposed decision
Code talks only to the **S3 API** (endpoint, bucket and credentials from `WARDEN_S3_*`), never to MinIO-specific APIs, so the backend stays swappable. For local dev, use `chainguard/minio:latest-dev` pinned by digest in `deploy/docker-compose.yml`.

## Open before acceptance (M2)
- Confirm the Chainguard rebuild cadence is acceptable, or switch to RustFS/SeaweedFS.
- Choose the production default for on-prem installs.
- Decide on bucket layout and object-lock/retention for evidence.
