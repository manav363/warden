# Schemas

JSON Schema (draft 2020-12) contracts for jobs and facts exchanged between services and sensors.
**Change the schema first, then producers and consumers.**

| Schema | Producer | Consumer |
|---|---|---|
| `jobs/discover_job.schema.json` | orchestrator | `sensor/discovery` |
| `jobs/discover_result.schema.json` | `sensor/discovery` | orchestrator / correlation |

## Rules
- Every document carries `"version"` (a const). Breaking changes bump it; consumers branch on it.
- `additionalProperties: false` throughout: unknown fields are rejected, not ignored.
- **Turn on format validation.** In 2020-12, `format` (`uuid`, `date-time`, `ipv4`, …) is only an
  annotation unless the validator is told to assert it. Every consumer must enable it:
  - Rust (`jsonschema`): `jsonschema::options().should_validate_formats(true)` (done in `sensor/discovery`).
  - Python (`jsonschema`): pass `format_checker=Draft202012Validator.FORMAT_CHECKER`, and install
    `jsonschema[format]` so that `uuid`/`date-time` checkers are available.
- A schema is only a contract, not a security boundary. The sensor's scope guard re-parses and
  re-checks targets itself and fails closed (see `docs/safety-and-scope.md`).
- Result documents hold **facts only**: no "expired", "weak" or "trusted" flags. Judgment lives in
  `services/correlation`.

Examples in `jobs/examples/` must validate. Tests in `sensor/discovery` check this.
