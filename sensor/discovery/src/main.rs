//! Warden discovery engine.
//!
//! M0 skeleton: CLI + structured logging only. The `scan` subcommand lands in M1
//! together with the sensor-side scope guard, so no code path can send a packet
//! before the guard exists.

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "warden-discovery", version, about)]
struct Cli {
    /// Log filter (e.g. `info`, `debug`, `warden_discovery=trace`).
    #[arg(long, env = "WARDEN_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .with_writer(std::io::stderr)
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "warden-discovery started");
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
    fn parses_log_level() {
        let cli = Cli::try_parse_from(["warden-discovery", "--log-level", "debug"]).unwrap();
        assert_eq!(cli.log_level, "debug");
    }
}
