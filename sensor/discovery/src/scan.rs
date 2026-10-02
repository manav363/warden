//! Rate-limited, bounded-concurrency TCP connect scan.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Interval, MissedTickBehavior};

use crate::guard::{self, AuthorizedTarget, ConnectError};
use crate::job::{HostReport, Limits, PortReport, Stats, StopReason};
use crate::probe;

pub type ConnectFuture = Pin<Box<dyn Future<Output = Result<TcpStream, ConnectError>> + Send>>;
/// How the engine opens connections. Production uses [`guarded_connector`]; tests may
/// substitute a mock, which still only ever receives an [`AuthorizedTarget`].
pub type ConnectFn = Arc<dyn Fn(AuthorizedTarget, u16, Duration) -> ConnectFuture + Send + Sync>;

pub fn guarded_connector() -> ConnectFn {
    Arc::new(|target, port, timeout| {
        Box::pin(async move { guard::connect(&target, port, timeout).await })
    })
}

/// What a failed connect says about the target — or that it says nothing (`Local`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Closed,
    Filtered,
    Unreachable,
    Other,
    /// Our side ran out of something or was refused by local policy. Never target state.
    Local,
}

pub fn classify(err: &io::Error) -> Class {
    match err.raw_os_error() {
        Some(libc::ECONNREFUSED) => Class::Closed,
        Some(libc::ETIMEDOUT) => Class::Filtered,
        Some(libc::EHOSTUNREACH | libc::ENETUNREACH) => Class::Unreachable,
        Some(
            libc::EMFILE
            | libc::ENFILE
            | libc::EADDRNOTAVAIL
            | libc::ENOBUFS
            | libc::ENOMEM
            | libc::EACCES
            | libc::EPERM,
        ) => Class::Local,
        Some(_) => Class::Other,
        None => match err.kind() {
            io::ErrorKind::ConnectionRefused => Class::Closed,
            io::ErrorKind::TimedOut => Class::Filtered,
            io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                Class::Unreachable
            }
            _ => Class::Other,
        },
    }
}

/// Reasons a task stops the whole job.
#[derive(Debug)]
pub enum Halt {
    ScopeExpired,
    Local(io::Error),
}

/// Map a connect failure to a target class, or to a job-stopping [`Halt`].
pub fn dial_error(err: ConnectError) -> Result<Class, Halt> {
    match err {
        ConnectError::ScopeExpired => Err(Halt::ScopeExpired),
        ConnectError::TimedOut => Ok(Class::Filtered),
        ConnectError::Io(e) => match classify(&e) {
            Class::Local => Err(Halt::Local(e)),
            class => Ok(class),
        },
    }
}

/// Shared by every task: one global rate limiter in front of every connection attempt.
pub struct Dialer {
    connect: ConnectFn,
    limiter: Mutex<Interval>,
    attempted: AtomicU64,
    connect_timeout: Duration,
    pub banner_timeout: Duration,
}

impl Dialer {
    fn new(connect: ConnectFn, limits: &Limits) -> Self {
        let period = Duration::from_secs_f64(1.0 / f64::from(limits.max_rate_per_sec.max(1)));
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay); // never burst to catch up
        Self {
            connect,
            limiter: Mutex::new(interval),
            attempted: AtomicU64::new(0),
            connect_timeout: Duration::from_millis(limits.connect_timeout_ms),
            banner_timeout: Duration::from_millis(limits.banner_timeout_ms),
        }
    }

    pub async fn dial(
        &self,
        target: &AuthorizedTarget,
        port: u16,
    ) -> Result<TcpStream, ConnectError> {
        self.limiter.lock().await.tick().await;
        self.attempted.fetch_add(1, Ordering::Relaxed);
        (self.connect)(*target, port, self.connect_timeout).await
    }
}

enum PortResult {
    Open(Box<PortReport>),
    Not(Class),
}

async fn scan_port(
    dialer: Arc<Dialer>,
    target: AuthorizedTarget,
    port: u16,
) -> Result<(IpAddr, PortResult), Halt> {
    let result = match dialer.dial(&target, port).await {
        Ok(stream) => PortResult::Open(Box::new(
            probe::probe(&dialer, &target, port, stream).await?,
        )),
        Err(e) => PortResult::Not(dial_error(e)?),
    };
    Ok((target.ip(), result))
}

pub struct ScanOutput {
    pub hosts: Vec<HostReport>,
    pub stats: Stats,
    pub stop: Option<StopReason>,
    pub error: Option<String>,
}

#[derive(Default)]
struct Collector {
    open: BTreeMap<IpAddr, Vec<PortReport>>,
    stats: Stats,
    stop: Option<StopReason>,
    error: Option<String>,
}

type TaskResult = Result<Result<(IpAddr, PortResult), Halt>, JoinError>;

impl Collector {
    /// First stop reason wins. Returns true if this call stopped the job.
    fn halt(&mut self, reason: StopReason, error: Option<String>) -> bool {
        if self.stop.is_some() {
            return false;
        }
        self.stop = Some(reason);
        self.error = error;
        true
    }

    fn record(&mut self, result: TaskResult) -> bool {
        match result {
            Ok(Ok((ip, PortResult::Open(report)))) => {
                self.stats.open_ports += 1;
                self.open.entry(ip).or_default().push(*report);
            }
            Ok(Ok((_, PortResult::Not(class)))) => match class {
                Class::Closed => self.stats.closed += 1,
                Class::Filtered => self.stats.filtered += 1,
                Class::Unreachable => self.stats.unreachable += 1,
                Class::Other => self.stats.other_errors += 1,
                Class::Local => unreachable!("dial_error turns Local into Halt"),
            },
            Ok(Err(Halt::ScopeExpired)) => return self.halt(StopReason::ScopeExpired, None),
            Ok(Err(Halt::Local(e))) => {
                let msg = format!("local resource error, not a target state: {e}");
                return self.halt(StopReason::Error, Some(msg));
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => return self.halt(StopReason::Error, Some(format!("scan task failed: {e}"))),
        }
        false
    }

    fn finish(mut self, attempted: u64) -> ScanOutput {
        self.stats.connections_attempted = attempted;
        let hosts = self
            .open
            .into_iter()
            .map(|(ip, mut ports)| {
                ports.sort_by_key(|p| p.port);
                HostReport { ip, ports }
            })
            .collect();
        ScanOutput {
            hosts,
            stats: self.stats,
            stop: self.stop,
            error: self.error,
        }
    }
}

/// Scan every (target, port) pair. Stops early — keeping what was found — on scope
/// expiry, a local error, or when `cancel` resolves.
pub async fn run(
    targets: Vec<AuthorizedTarget>,
    ports: Vec<u16>,
    limits: Limits,
    connect: ConnectFn,
    cancel: impl Future<Output = ()>,
) -> ScanOutput {
    let dialer = Arc::new(Dialer::new(connect, &limits));
    let permits = Arc::new(Semaphore::new(limits.max_concurrency.max(1)));
    let mut tasks = JoinSet::new();
    let mut c = Collector::default();
    c.stats.hosts_targeted = targets.len() as u64;
    c.stats.ports_per_host = ports.len() as u64;
    tokio::pin!(cancel);

    'schedule: for target in &targets {
        for &port in &ports {
            // Backpressure: wait for a free slot before spawning, so memory stays
            // O(max_concurrency) however large the job is.
            let permit = tokio::select! {
                biased;
                () = &mut cancel => {
                    c.halt(StopReason::Cancelled, None);
                    break 'schedule;
                }
                p = permits.clone().acquire_owned() => p.expect("semaphore is never closed"),
            };
            while let Some(done) = tasks.try_join_next() {
                c.record(done);
            }
            if c.stop.is_some() {
                break 'schedule;
            }
            let (dialer, target) = (dialer.clone(), *target);
            tasks.spawn(async move {
                let _permit = permit;
                scan_port(dialer, target, port).await
            });
        }
    }

    if c.stop.is_some() {
        tasks.abort_all();
    }
    loop {
        tokio::select! {
            biased;
            () = &mut cancel, if c.stop.is_none() => {
                c.halt(StopReason::Cancelled, None);
                tasks.abort_all();
            }
            done = tasks.join_next() => match done {
                None => break,
                Some(done) => {
                    if c.record(done) {
                        tasks.abort_all();
                    }
                }
            },
        }
    }
    c.finish(dialer.attempted.load(Ordering::Relaxed))
}

/// Headroom kept for stdio, the runtime and logging.
const FD_HEADROOM: u64 = 64;
/// We never need more than this, and macOS refuses soft limits above OPEN_MAX.
const FD_TARGET: u64 = 4096;

/// Raise the soft open-file limit if we can, then clamp concurrency to fit it. Each
/// task holds at most one socket at a time (probes re-dial sequentially).
pub fn effective_concurrency(requested: usize) -> Result<usize, String> {
    let soft = raise_nofile_limit().map_err(|e| format!("cannot read RLIMIT_NOFILE: {e}"))?;
    let usable = usize::try_from(soft.saturating_sub(FD_HEADROOM)).unwrap_or(usize::MAX);
    if usable == 0 {
        return Err(format!(
            "open-file limit is {soft}; need more than {FD_HEADROOM} to scan safely"
        ));
    }
    if usable < requested {
        tracing::warn!(
            requested,
            clamped_to = usable,
            soft_limit = soft,
            "max_concurrency clamped to fit RLIMIT_NOFILE"
        );
    }
    Ok(requested.min(usable))
}

#[cfg(unix)]
fn raise_nofile_limit() -> io::Result<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes into the provided, correctly sized struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let want = rl.rlim_max.min(FD_TARGET);
    if rl.rlim_cur < want {
        let raised = libc::rlimit {
            rlim_cur: want,
            rlim_max: rl.rlim_max,
        };
        // SAFETY: setrlimit only reads the struct; on failure the limit is unchanged.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            rl.rlim_cur = want;
        }
    }
    Ok(rl.rlim_cur)
}

#[cfg(not(unix))]
fn raise_nofile_limit() -> io::Result<u64> {
    Ok(FD_TARGET)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::Scope;
    use time::OffsetDateTime;

    fn os(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    #[test]
    fn only_refused_is_closed_and_only_timeout_is_filtered() {
        assert_eq!(classify(&os(libc::ECONNREFUSED)), Class::Closed);
        assert_eq!(classify(&os(libc::ETIMEDOUT)), Class::Filtered);
        assert_eq!(dial_error(ConnectError::TimedOut).unwrap(), Class::Filtered);
        assert_eq!(classify(&os(libc::ECONNRESET)), Class::Other);
    }

    #[test]
    fn unreachable_is_its_own_class() {
        assert_eq!(classify(&os(libc::EHOSTUNREACH)), Class::Unreachable);
        assert_eq!(classify(&os(libc::ENETUNREACH)), Class::Unreachable);
    }

    #[test]
    fn local_resource_errors_are_never_target_state() {
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::EADDRNOTAVAIL,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EACCES,
            libc::EPERM,
        ] {
            assert_eq!(classify(&os(errno)), Class::Local, "errno {errno}");
            assert!(matches!(
                dial_error(ConnectError::Io(os(errno))),
                Err(Halt::Local(_))
            ));
        }
    }

    #[test]
    fn errors_without_errno_fall_back_to_kind() {
        let e = |k| io::Error::new(k, "synthetic");
        assert_eq!(
            classify(&e(io::ErrorKind::ConnectionRefused)),
            Class::Closed
        );
        assert_eq!(classify(&e(io::ErrorKind::TimedOut)), Class::Filtered);
        assert_eq!(
            classify(&e(io::ErrorKind::HostUnreachable)),
            Class::Unreachable
        );
        assert_eq!(classify(&e(io::ErrorKind::Other)), Class::Other);
    }

    fn targets(n: usize) -> Vec<AuthorizedTarget> {
        let now = OffsetDateTime::now_utc();
        let scope = Scope::new(&["10.0.0.0/24".into()], now + time::Duration::HOUR, now).unwrap();
        let t: Vec<String> = (1..=n).map(|i| format!("10.0.0.{i}")).collect();
        scope.expand_targets(&t, 3, now).unwrap()
    }

    fn fast_limits() -> Limits {
        Limits {
            max_concurrency: 4,
            max_rate_per_sec: 1000,
            ..Limits::default()
        }
    }

    fn failing(make: fn() -> ConnectError) -> ConnectFn {
        Arc::new(move |_, _, _| Box::pin(async move { Err(make()) }))
    }

    async fn run_with(connect: ConnectFn) -> ScanOutput {
        run(
            targets(2),
            vec![1, 2, 3],
            fast_limits(),
            connect,
            std::future::pending(),
        )
        .await
    }

    #[tokio::test]
    async fn emfile_aborts_the_job_instead_of_reporting_filtered() {
        let out = run_with(failing(|| ConnectError::Io(os(libc::EMFILE)))).await;
        assert_eq!(out.stop, Some(StopReason::Error));
        assert!(out.error.unwrap().contains("local resource error"));
        assert_eq!(
            (out.stats.filtered, out.stats.closed, out.stats.open_ports),
            (0, 0, 0)
        );
        assert!(out.hosts.is_empty());
    }

    #[tokio::test]
    async fn refused_everywhere_completes_with_closed_counts() {
        let out = run_with(failing(|| ConnectError::Io(os(libc::ECONNREFUSED)))).await;
        assert_eq!(out.stop, None);
        assert_eq!(out.stats.closed, 6);
        assert_eq!(out.stats.connections_attempted, 6);
    }

    #[tokio::test]
    async fn unreachable_and_timeouts_are_counted_separately() {
        let out = run_with(failing(|| ConnectError::Io(os(libc::EHOSTUNREACH)))).await;
        assert_eq!(
            (out.stats.unreachable, out.stats.filtered, out.stop),
            (6, 0, None)
        );
        let out = run_with(failing(|| ConnectError::TimedOut)).await;
        assert_eq!(
            (out.stats.filtered, out.stats.unreachable, out.stop),
            (6, 0, None)
        );
    }

    #[tokio::test]
    async fn scope_expiry_mid_job_stops_as_partial() {
        let out = run_with(failing(|| ConnectError::ScopeExpired)).await;
        assert_eq!(out.stop, Some(StopReason::ScopeExpired));
        assert_eq!(
            (out.stats.closed, out.stats.filtered, out.stats.open_ports),
            (0, 0, 0)
        );
    }

    #[tokio::test]
    async fn cancel_stops_as_partial() {
        let never_connects: ConnectFn = Arc::new(|_, _, _| Box::pin(std::future::pending()));
        let out = run(
            targets(2),
            vec![1, 2, 3],
            fast_limits(),
            never_connects,
            async {},
        )
        .await;
        assert_eq!(out.stop, Some(StopReason::Cancelled));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_spaces_connection_attempts() {
        let limits = Limits {
            max_concurrency: 16,
            max_rate_per_sec: 10,
            ..Limits::default()
        };
        let start = tokio::time::Instant::now();
        let connect = failing(|| ConnectError::Io(os(libc::ECONNREFUSED)));
        let out = run(
            targets(1),
            vec![1, 2, 3],
            limits,
            connect,
            std::future::pending(),
        )
        .await;
        // First tick is immediate; 3 attempts at 10/s take at least 200ms.
        assert!(start.elapsed() >= Duration::from_millis(200));
        assert_eq!(out.stats.closed, 3);
    }

    #[test]
    fn concurrency_is_clamped_not_raised() {
        assert_eq!(effective_concurrency(1).unwrap(), 1);
        assert!(effective_concurrency(16).unwrap() <= 16);
    }
}
