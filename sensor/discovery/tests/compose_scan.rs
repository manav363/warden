//! Scan the local docker-compose stack (127.0.0.1 only). Needs `make up` first:
//!   make discovery-it
//! Postgres/Redis host ports follow WARDEN_PG_PORT / WARDEN_REDIS_PORT like compose does.

mod common;

use common::{FAR_FUTURE, assert_valid_result, free_ports, job, port_entry, scan};
use serde_json::Value;

const NATS: u16 = 4222;
const API: u16 = 8000;
const VAULT: u16 = 8200;
const MINIO: u16 = 9000;

fn env_port(var: &str, default: u16) -> u16 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn banner(entry: &Value) -> (String, String) {
    let field = |k: &str| entry["banner"][k].as_str().unwrap_or_default().to_owned();
    (field("probe"), field("text"))
}

#[test]
#[ignore = "needs the docker compose stack: run `make discovery-it`"]
fn scans_the_local_compose_stack() {
    let pg = env_port("WARDEN_PG_PORT", 5432);
    let redis = env_port("WARDEN_REDIS_PORT", 6379);
    let closed = free_ports(1)[0];
    let ports = [NATS, API, VAULT, MINIO, pg, redis, closed];
    let mut j = job(&["127.0.0.1"], &ports, &["127.0.0.1/32"], FAR_FUTURE);
    j["limits"]["banner_timeout_ms"] = 1500.into();
    j["limits"]["connect_timeout_ms"] = 1000.into();

    let run = scan(&j);

    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let r = run.result.expect("result written");
    assert_valid_result(&r);
    let port = |p| port_entry(&r, "127.0.0.1", p).unwrap_or_else(|| panic!("port {p} not open"));

    let (probe, text) = banner(&port(NATS));
    assert_eq!(probe, "passive");
    assert!(text.starts_with("INFO {"), "nats: {text}");

    let (probe, text) = banner(&port(API));
    assert_eq!(probe, "http");
    assert!(
        text.to_ascii_lowercase().contains("server: uvicorn"),
        "api: {text}"
    );

    let (probe, text) = banner(&port(MINIO));
    assert_eq!(probe, "http");
    assert!(text.contains("MinIO"), "minio: {text}");

    let (probe, text) = banner(&port(VAULT));
    assert_eq!(probe, "http");
    assert!(text.starts_with("HTTP/1."), "vault: {text}");

    let (probe, text) = banner(&port(redis));
    assert_eq!(probe, "http");
    assert!(text.starts_with("-ERR"), "redis: {text}");

    let pg_entry = port(pg);
    assert!(
        pg_entry["banner"].is_null(),
        "postgres sends nothing unprompted: {pg_entry}"
    );
    assert!(pg_entry["tls"].is_null());

    assert!(port_entry(&r, "127.0.0.1", closed).is_none());
    assert_eq!(r["stats"]["open_ports"], 6);
}
