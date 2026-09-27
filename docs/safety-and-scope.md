# Safety & Scope

Warden is a defensive tool. It only scans networks the operator is authorized to assess.

- Every scan references a **scope**: CIDR allowlist, authorization record (who approved, document ref), expiry.
- The API rejects scans outside an active scope; the sensor re-validates every target before sending traffic.
- Checks are read-only and non-exploiting. No brute force, no payloads, no writes to targets.
- Network activity is rate-limited with conservative defaults.
- Credentials are Vault references only; never logged, never persisted in Postgres or evidence.
