//! Discover job/result contracts. The JSON Schemas in `packages/schemas/jobs/` are the
//! source of truth; incoming jobs are validated against the embedded schema (with
//! format assertion on) before they are deserialized.

use std::net::IpAddr;
use std::sync::LazyLock;

use jsonschema::Validator;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

pub const JOB_SCHEMA: &str =
    include_str!("../../../packages/schemas/jobs/discover_job.schema.json");
#[cfg(test)]
pub const RESULT_SCHEMA: &str =
    include_str!("../../../packages/schemas/jobs/discover_result.schema.json");

pub const DEFAULT_MAX_CONCURRENCY: usize = 16;
pub const DEFAULT_MAX_RATE_PER_SEC: u32 = 50;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1500;
pub const DEFAULT_BANNER_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverJob {
    #[allow(dead_code)] // pinned to 1 by the schema; declared so deny_unknown_fields accepts it
    pub version: u8,
    pub scan_id: String,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub scope: JobScope,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobScope {
    pub scope_id: String,
    pub cidrs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_concurrency: usize,
    pub max_rate_per_sec: u32,
    pub connect_timeout_ms: u64,
    pub banner_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            max_rate_per_sec: DEFAULT_MAX_RATE_PER_SEC,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            banner_timeout_ms: DEFAULT_BANNER_TIMEOUT_MS,
        }
    }
}

static JOB_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(JOB_SCHEMA).expect("embedded job schema is JSON");
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("embedded job schema compiles")
});

/// Parse and validate a job document. Errors are human-readable and list every
/// schema violation (capped) so an operator can fix the job in one pass.
pub fn parse_job(bytes: &[u8]) -> Result<DiscoverJob, String> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("job is not JSON: {e}"))?;
    let errors: Vec<String> = JOB_VALIDATOR
        .iter_errors(&doc)
        .take(20)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect();
    if !errors.is_empty() {
        return Err(format!("job fails schema: {}", errors.join("; ")));
    }
    serde_json::from_value(doc).map_err(|e| format!("job does not deserialize: {e}"))
}

// --- result ---

#[derive(Debug, Serialize)]
pub struct DiscoverResult {
    pub version: u8,
    pub scan_id: String,
    pub scope_id: String,
    pub stage: &'static str,
    pub sensor: Sensor,
    pub status: Status,
    pub stopped_reason: Option<StopReason>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub stats: Stats,
    pub hosts: Vec<HostReport>,
}

#[derive(Debug, Serialize)]
pub struct Sensor {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    ScopeExpired,
    Cancelled,
    Error,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub hosts_targeted: u64,
    pub ports_per_host: u64,
    pub connections_attempted: u64,
    pub open_ports: u64,
    pub closed: u64,
    pub filtered: u64,
    pub unreachable: u64,
    pub other_errors: u64,
}

#[derive(Debug, Serialize)]
pub struct HostReport {
    pub ip: IpAddr,
    pub ports: Vec<PortReport>,
}

#[derive(Debug, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub proto: &'static str,
    pub state: &'static str,
    pub banner: Option<Banner>,
    pub tls: Option<TlsInfo>,
}

#[derive(Debug, Serialize)]
pub struct Banner {
    pub probe: Probe,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    Passive,
    Http,
    Https,
}

#[derive(Debug, Serialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher_suite: String,
    pub cert: CertSummary,
    pub chain_length: usize,
}

#[derive(Debug, Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub sans: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: Option<usize>,
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str =
        include_str!("../../../packages/schemas/jobs/examples/discover_job.example.json");

    fn example() -> Value {
        serde_json::from_str(EXAMPLE).unwrap()
    }

    fn rejects(doc: &Value) -> String {
        parse_job(doc.to_string().as_bytes()).unwrap_err()
    }

    #[test]
    fn both_schemas_are_valid_2020_12() {
        for s in [JOB_SCHEMA, RESULT_SCHEMA] {
            let v: Value = serde_json::from_str(s).unwrap();
            assert!(jsonschema::meta::is_valid(&v));
        }
    }

    #[test]
    fn example_job_parses() {
        let job = parse_job(EXAMPLE.as_bytes()).unwrap();
        assert_eq!(job.version, 1);
        assert_eq!(job.limits.max_concurrency, 4);
    }

    #[test]
    fn limits_default_when_omitted() {
        let mut doc = example();
        doc.as_object_mut().unwrap().remove("limits");
        let job = parse_job(doc.to_string().as_bytes()).unwrap();
        assert_eq!(job.limits.max_concurrency, DEFAULT_MAX_CONCURRENCY);
        assert_eq!(job.limits.max_rate_per_sec, DEFAULT_MAX_RATE_PER_SEC);
    }

    #[test]
    fn rust_defaults_match_schema_defaults() {
        let schema: Value = serde_json::from_str(JOB_SCHEMA).unwrap();
        let props = &schema["properties"]["limits"]["properties"];
        let d = Limits::default();
        assert_eq!(props["max_concurrency"]["default"], d.max_concurrency);
        assert_eq!(props["max_rate_per_sec"]["default"], d.max_rate_per_sec);
        assert_eq!(props["connect_timeout_ms"]["default"], d.connect_timeout_ms);
        assert_eq!(props["banner_timeout_ms"]["default"], d.banner_timeout_ms);
    }

    #[test]
    fn scope_is_required() {
        let mut doc = example();
        doc.as_object_mut().unwrap().remove("scope");
        assert!(rejects(&doc).contains("scope"));
    }

    #[test]
    fn formats_are_asserted() {
        let mut doc = example();
        doc["scan_id"] = "not-a-uuid".into();
        assert!(rejects(&doc).contains("/scan_id"));

        let mut doc = example();
        doc["scope"]["expires_at"] = "next tuesday".into();
        assert!(rejects(&doc).contains("/scope/expires_at"));
    }

    #[test]
    fn caps_and_unknown_fields_are_enforced() {
        let mut doc = example();
        doc["limits"]["max_concurrency"] = 10_000.into();
        assert!(rejects(&doc).contains("/limits/max_concurrency"));

        let mut doc = example();
        doc["skip_scope_check"] = true.into();
        assert!(rejects(&doc).contains("skip_scope_check"));

        let mut doc = example();
        doc["targets"] = serde_json::json!(["example.com"]);
        assert!(rejects(&doc).contains("/targets/0"));
    }
}
