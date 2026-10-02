//! Helpers shared by the integration tests: build jobs, run the real binary, check results.
#![allow(dead_code)] // each test binary uses a different subset

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const BIN: &str = env!("CARGO_BIN_EXE_warden-discovery");
const RESULT_SCHEMA: &str =
    include_str!("../../../../packages/schemas/jobs/discover_result.schema.json");

pub const FAR_FUTURE: &str = "2099-01-01T00:00:00Z";

pub fn rfc3339_in(ms: i64) -> String {
    (OffsetDateTime::now_utc() + time::Duration::milliseconds(ms))
        .format(&Rfc3339)
        .unwrap()
}

pub fn job(targets: &[&str], ports: &[u16], cidrs: &[&str], expires_at: &str) -> Value {
    json!({
        "version": 1,
        "scan_id": "4f5d9a8e-2b1c-4c3d-9e8f-7a6b5c4d3e2f",
        "targets": targets,
        "ports": ports,
        "scope": {
            "scope_id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
            "cidrs": cidrs,
            "expires_at": expires_at,
        },
        "limits": {
            "max_concurrency": 8,
            "max_rate_per_sec": 200,
            "connect_timeout_ms": 500,
            "banner_timeout_ms": 400,
        },
    })
}

/// Ports that were just free: bind them all at once, then release them.
pub fn free_ports(n: usize) -> Vec<u16> {
    let held: Vec<_> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    held.iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
}

pub struct Run {
    pub code: Option<i32>,
    pub result: Option<Value>,
    pub stderr: String,
}

/// A job written to disk plus where its result will go.
pub struct Prepared {
    job_path: PathBuf,
    out_path: PathBuf,
}

static SEQ: AtomicU32 = AtomicU32::new(0);

impl Prepared {
    pub fn new(job: &Value) -> Self {
        let tag = format!(
            "{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir();
        let prepared = Self {
            job_path: dir.join(format!("warden-it-job-{tag}.json")),
            out_path: dir.join(format!("warden-it-out-{tag}.json")),
        };
        std::fs::write(&prepared.job_path, job.to_string()).unwrap();
        prepared
    }

    pub fn args(&self) -> Vec<String> {
        vec![
            "scan".into(),
            "--job".into(),
            self.job_path.display().to_string(),
            "--out".into(),
            self.out_path.display().to_string(),
        ]
    }

    pub fn finish(self, output: &Output) -> Run {
        let result = std::fs::read(&self.out_path)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap());
        let _ = std::fs::remove_file(&self.job_path);
        let _ = std::fs::remove_file(&self.out_path);
        Run {
            code: output.status.code(),
            result,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

pub fn scan(job: &Value) -> Run {
    let prepared = Prepared::new(job);
    let output = Command::new(BIN).args(prepared.args()).output().unwrap();
    prepared.finish(&output)
}

/// Panics with every violation if the result does not match the published contract.
pub fn assert_valid_result(result: &Value) {
    let schema: Value = serde_json::from_str(RESULT_SCHEMA).unwrap();
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    let errors: Vec<String> = validator
        .iter_errors(result)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "result violates schema: {errors:#?}\n{result:#}"
    );
}

pub fn port_entry(result: &Value, ip: &str, port: u16) -> Option<Value> {
    result["hosts"].as_array()?.iter().find(|h| h["ip"] == ip)?["ports"]
        .as_array()?
        .iter()
        .find(|p| p["port"] == port)
        .cloned()
}
