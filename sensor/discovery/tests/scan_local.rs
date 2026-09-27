//! Hermetic end-to-end tests: the real binary against listeners owned by the test.

mod common;

use std::future::Future;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{FAR_FUTURE, Prepared, Run, assert_valid_result, free_ports, job, port_entry};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

struct Server {
    port: u16,
    accepts: Arc<AtomicUsize>,
}

impl Server {
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

async fn serve<F, Fut>(bind: &str, handler: F) -> std::io::Result<Server>
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(bind).await?;
    let port = listener.local_addr()?.port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handler(stream));
        }
    });
    Ok(Server { port, accepts })
}

async fn ssh_like(bind: &str) -> std::io::Result<Server> {
    serve(bind, |mut s| async move {
        let _ = s.write_all(b"SSH-2.0-WardenTest\r\n").await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await
}

const HTTP_REPLY: &[u8] = b"HTTP/1.0 200 OK\r\nServer: warden-test-http\r\n\r\n";
const HTTPS_REPLY: &[u8] = b"HTTP/1.0 200 OK\r\nServer: warden-test-tls\r\n\r\n";

async fn http_like() -> Server {
    serve("127.0.0.1:0", |mut s| async move {
        let mut buf = [0u8; 256];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await {
            if buf[..n].starts_with(b"HEAD ") {
                let _ = s.write_all(HTTP_REPLY).await;
            }
        }
    })
    .await
    .unwrap()
}

async fn tls_like() -> Server {
    let mut params =
        rcgen::CertificateParams::new(vec!["warden.test".into(), "127.0.0.1".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2030, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    serve("127.0.0.1:0", move |s| {
        let acceptor = acceptor.clone();
        async move {
            let Ok(mut tls) = acceptor.accept(s).await else {
                return;
            };
            let mut buf = [0u8; 256];
            if let Ok(n) = tls.read(&mut buf).await {
                if buf[..n].starts_with(b"HEAD ") {
                    let _ = tls.write_all(HTTPS_REPLY).await;
                    let _ = tls.shutdown().await;
                }
            }
        }
    })
    .await
    .unwrap()
}

async fn run(job: serde_json::Value) -> Run {
    tokio::task::spawn_blocking(move || common::scan(&job))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_banners_tls_and_skips_closed_ports() {
    let (ssh, http, tls) = (
        ssh_like("127.0.0.1:0").await.unwrap(),
        http_like().await,
        tls_like().await,
    );
    let closed = free_ports(1)[0];
    let ports = [ssh.port, http.port, tls.port, closed];

    let run = run(job(&["127.0.0.1"], &ports, &["127.0.0.1/32"], FAR_FUTURE)).await;

    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let r = run.result.expect("result written");
    assert_valid_result(&r);
    assert_eq!(
        (r["status"].as_str(), r["stopped_reason"].is_null()),
        (Some("complete"), true)
    );
    assert_eq!(r["stats"]["open_ports"], 3);
    assert_eq!(r["stats"]["closed"], 1);
    assert!(port_entry(&r, "127.0.0.1", closed).is_none());

    let p = port_entry(&r, "127.0.0.1", ssh.port).unwrap();
    assert_eq!(p["banner"]["probe"], "passive");
    assert_eq!(p["banner"]["text"], "SSH-2.0-WardenTest\r\n");
    assert!(p["tls"].is_null());

    let p = port_entry(&r, "127.0.0.1", http.port).unwrap();
    assert_eq!(p["banner"]["probe"], "http");
    assert!(
        p["banner"]["text"]
            .as_str()
            .unwrap()
            .contains("warden-test-http")
    );
    assert!(p["tls"].is_null());

    let p = port_entry(&r, "127.0.0.1", tls.port).unwrap();
    assert_eq!(p["banner"]["probe"], "https");
    assert!(
        p["banner"]["text"]
            .as_str()
            .unwrap()
            .contains("warden-test-tls")
    );
    assert_eq!(p["tls"]["version"], "TLSv1.3");
    assert_eq!(p["tls"]["chain_length"], 1);
    let cert = &p["tls"]["cert"];
    assert_eq!(cert["not_after"], "2030-01-01T00:00:00Z");
    assert_eq!(cert["not_before"], "2025-01-01T00:00:00Z");
    let sans: Vec<&str> = cert["sans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(sans, ["DNS:warden.test", "IP:127.0.0.1"]);
    assert_eq!(cert["public_key_bits"], 256);
}

#[tokio::test(flavor = "multi_thread")]
async fn scans_ipv6_loopback_when_available() {
    let Ok(ssh) = ssh_like("[::1]:0").await else {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    };
    let run = run(job(&["::1"], &[ssh.port], &["::1/128"], FAR_FUTURE)).await;
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let r = run.result.unwrap();
    assert_valid_result(&r);
    assert_eq!(
        port_entry(&r, "::1", ssh.port).unwrap()["banner"]["probe"],
        "passive"
    );
}

/// Every way a job can be rejected must exit 2 without a single connection.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_jobs_send_nothing() {
    let ssh = ssh_like("127.0.0.1:0").await.unwrap();
    let p = [ssh.port];
    let mut no_scope = job(&["127.0.0.1"], &p, &["127.0.0.1/32"], FAR_FUTURE);
    no_scope.as_object_mut().unwrap().remove("scope");

    let cases = [
        (
            "out of scope",
            job(&["127.0.0.1"], &p, &["10.0.0.0/8"], FAR_FUTURE),
        ),
        (
            "partly out of scope",
            job(
                &["127.0.0.1", "127.0.0.2"],
                &p,
                &["127.0.0.1/32"],
                FAR_FUTURE,
            ),
        ),
        (
            "expired scope",
            job(
                &["127.0.0.1"],
                &p,
                &["127.0.0.1/32"],
                "2020-01-01T00:00:00Z",
            ),
        ),
        ("no scope", no_scope),
        (
            "hostname target",
            job(&["localhost"], &p, &["127.0.0.1/32"], FAR_FUTURE),
        ),
        (
            "mapped ipv6 target",
            job(&["::ffff:127.0.0.1"], &p, &["127.0.0.1/32"], FAR_FUTURE),
        ),
    ];
    for (name, j) in cases {
        let run = run(j).await;
        assert_eq!(run.code, Some(2), "{name}: stderr: {}", run.stderr);
        assert!(run.result.is_none(), "{name}: no result for a rejected job");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(ssh.accepts(), 0, "a rejected job reached the network");
}

/// A local resource failure (fd limit) is a runtime error, never a target state.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn too_few_file_descriptors_is_a_runtime_error() {
    let ssh = ssh_like("127.0.0.1:0").await.unwrap();
    let prepared = Prepared::new(&job(
        &["127.0.0.1"],
        &[ssh.port],
        &["127.0.0.1/32"],
        FAR_FUTURE,
    ));
    let args = prepared.args();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("sh")
            .arg("-c")
            .arg(r#"ulimit -n 16 && exec "$0" "$@""#)
            .arg(common::BIN)
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let run = prepared.finish(&output);

    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("open-file limit"),
        "stderr: {}",
        run.stderr
    );
    assert!(run.result.is_none());
    assert_eq!(ssh.accepts(), 0);
}

/// Slow job over closed ports: ~5 connection attempts per second.
fn slow_job(expires_at: &str) -> serde_json::Value {
    let mut j = job(
        &["127.0.0.1"],
        &free_ports(60),
        &["127.0.0.1/32"],
        expires_at,
    );
    j["limits"]["max_rate_per_sec"] = 5.into();
    j
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_expiring_mid_scan_yields_partial_result() {
    let run = run(slow_job(&common::rfc3339_in(1500))).await;

    assert_eq!(run.code, Some(3), "stderr: {}", run.stderr);
    let r = run.result.expect("partial result still written");
    assert_valid_result(&r);
    assert_eq!(r["status"], "partial");
    assert_eq!(r["stopped_reason"], "scope_expired");
    let attempted = r["stats"]["connections_attempted"].as_u64().unwrap();
    assert!((3..30).contains(&attempted), "attempted {attempted}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn sigint_yields_partial_result() {
    let prepared = Prepared::new(&slow_job(FAR_FUTURE));
    let args = prepared.args();
    let output = tokio::task::spawn_blocking(move || {
        let child = Command::new(common::BIN)
            .args(args)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(1000));
        let pid = i32::try_from(child.id()).unwrap();
        // SAFETY: plain kill(2) on our own child process.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    let run = prepared.finish(&output);

    assert_eq!(run.code, Some(3), "stderr: {}", run.stderr);
    let r = run.result.expect("partial result still written");
    assert_valid_result(&r);
    assert_eq!(r["status"], "partial");
    assert_eq!(r["stopped_reason"], "cancelled");
}
