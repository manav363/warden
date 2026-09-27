//! Warden discovery engine: reads a discover job (JSON), scans only what the job's
//! scope authorizes, and writes a discover result (JSON).
//!
//! Exit codes: 0 complete · 1 runtime error · 2 job rejected (nothing sent) · 3 partial.

mod guard;
mod job;
mod probe;
mod scan;

use std::io::{self, Read, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use time::OffsetDateTime;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

use crate::guard::Scope;
use crate::job::{DiscoverResult, Limits, Sensor, Status, StopReason};

const EXIT_RUNTIME: u8 = 1;
const EXIT_REJECTED: u8 = 2;
const EXIT_PARTIAL: u8 = 3;

#[derive(Debug, Parser)]
#[command(name = "warden-discovery", version, about)]
struct Cli {
    /// Log filter (e.g. `info`, `debug`, `warden_discovery=trace`).
    #[arg(long, global = true, env = "WARDEN_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a discover job. There is deliberately no option to skip or widen the scope.
    Scan {
        /// Job JSON path, or `-` for stdin.
        #[arg(long)]
        job: String,
        /// Result JSON path, or `-` for stdout.
        #[arg(long, default_value = "-")]
        out: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .with_current_span(true)
        .with_writer(io::stderr)
        .init();
    match cli.command {
        Command::Scan { job, out } => scan_command(&job, &out).await,
    }
}

async fn scan_command(job_path: &str, out_path: &str) -> ExitCode {
    let bytes = match read_input(job_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, path = job_path, "cannot read job");
            return ExitCode::from(EXIT_RUNTIME);
        }
    };
    let job = match job::parse_job(&bytes) {
        Ok(j) => j,
        Err(reason) => {
            tracing::error!(%reason, "job rejected");
            return ExitCode::from(EXIT_REJECTED);
        }
    };
    let span = tracing::info_span!("scan", scan_id = %job.scan_id, stage = "discover");
    let _enter = span.enter();

    // Scope guard runs before anything touches the network; failure means nothing was sent.
    let now = OffsetDateTime::now_utc();
    let targets = match Scope::new(&job.scope.cidrs, job.scope.expires_at, now)
        .and_then(|scope| scope.expand_targets(&job.targets, job.ports.len(), now))
    {
        Ok(t) => t,
        Err(reason) => {
            tracing::error!(%reason, "job rejected by scope guard");
            return ExitCode::from(EXIT_REJECTED);
        }
    };
    let max_concurrency = match scan::effective_concurrency(job.limits.max_concurrency) {
        Ok(n) => n,
        Err(reason) => {
            tracing::error!(%reason, "refusing to scan");
            return ExitCode::from(EXIT_RUNTIME);
        }
    };
    let limits = Limits {
        max_concurrency,
        ..job.limits
    };
    tracing::info!(
        hosts = targets.len(),
        ports = job.ports.len(),
        ?limits,
        "scan starting"
    );

    drop(_enter);
    let started_at = OffsetDateTime::now_utc();
    let output = scan::run(
        targets,
        job.ports.clone(),
        limits,
        scan::guarded_connector(),
        shutdown(),
    )
    .instrument(span.clone())
    .await;
    let _enter = span.enter();

    if let Some(error) = &output.error {
        tracing::error!(%error, "scan stopped");
    }
    let result = DiscoverResult {
        version: 1,
        scan_id: job.scan_id,
        scope_id: job.scope.scope_id,
        stage: "discover",
        sensor: Sensor {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        status: if output.stop.is_some() {
            Status::Partial
        } else {
            Status::Complete
        },
        stopped_reason: output.stop,
        started_at,
        finished_at: OffsetDateTime::now_utc(),
        stats: output.stats,
        hosts: output.hosts,
    };
    if let Err(e) = write_output(out_path, &result) {
        tracing::error!(error = %e, path = out_path, "cannot write result");
        return ExitCode::from(EXIT_RUNTIME);
    }
    tracing::info!(status = ?result.status, stopped_reason = ?result.stopped_reason,
        open_ports = result.stats.open_ports, "scan finished");
    match result.stopped_reason {
        None => ExitCode::SUCCESS,
        Some(StopReason::Error) => ExitCode::from(EXIT_RUNTIME),
        Some(StopReason::ScopeExpired | StopReason::Cancelled) => ExitCode::from(EXIT_PARTIAL),
    }
}

/// Resolves on SIGINT or SIGTERM. If a handler cannot be installed it never resolves,
/// rather than being mistaken for a cancellation.
async fn shutdown() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => tracing::warn!("SIGINT received; stopping"),
        () = term => tracing::warn!("SIGTERM received; stopping"),
    }
}

fn read_input(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path)
    }
}

fn write_output(path: &str, result: &DiscoverResult) -> io::Result<()> {
    let mut json = serde_json::to_vec_pretty(result).map_err(io::Error::other)?;
    json.push(b'\n');
    if path == "-" {
        io::stdout().lock().write_all(&json)
    } else {
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_scan_with_log_level() {
        let cli = Cli::try_parse_from([
            "warden-discovery",
            "--log-level",
            "debug",
            "scan",
            "--job",
            "job.json",
        ])
        .unwrap();
        assert_eq!(cli.log_level, "debug");
        assert!(matches!(cli.command, Command::Scan { ref out, .. } if out == "-"));
    }

    #[test]
    fn scan_requires_a_job() {
        assert!(Cli::try_parse_from(["warden-discovery", "scan"]).is_err());
    }
}
