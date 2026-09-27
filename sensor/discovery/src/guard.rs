//! Scope guard — the sensor's only egress point.
//!
//! Every outbound connection goes through [`connect`], which only accepts an
//! [`AuthorizedTarget`]. That type has private fields and can only be produced by
//! [`Scope::authorize`] / [`Scope::expand_targets`], so an unchecked address cannot
//! reach the network. `clippy.toml` forbids raw socket/DNS APIs everywhere else, and
//! CI runs clippy with `-D warnings`.
//!
//! Everything here fails closed: ambiguous input is rejected, not normalised.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use ipnet::IpNet;
use time::OffsetDateTime;
use tokio::net::TcpStream;

/// Upper bound on distinct hosts in one job.
pub const MAX_HOSTS: u128 = 65_536;
/// Upper bound on (host, port) pairs in one job.
pub const MAX_WORK_UNITS: u128 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    Empty,
    Invalid(String),
    HostBitsSet(String),
    TooBroad(String),
    Ipv4InIpv6(String),
    Expired,
    OutOfScope(Vec<String>),
    Forbidden(IpAddr),
    TooManyHosts(u128),
    TooMuchWork(u128),
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "scope has no CIDRs"),
            Self::Invalid(s) => write!(f, "not an IP or CIDR literal: {s:?}"),
            Self::HostBitsSet(s) => write!(f, "CIDR has host bits set (ambiguous): {s}"),
            Self::TooBroad(s) => write!(f, "/0 is never a valid scope or target: {s}"),
            Self::Ipv4InIpv6(s) => write!(f, "IPv4-mapped/compatible IPv6 is not allowed: {s}"),
            Self::Expired => write!(f, "scope has expired"),
            Self::OutOfScope(t) => write!(f, "targets outside scope: {}", t.join(", ")),
            Self::Forbidden(ip) => write!(f, "address class is never scannable: {ip}"),
            Self::TooManyHosts(n) => write!(f, "{n} hosts exceeds the per-job cap of {MAX_HOSTS}"),
            Self::TooMuchWork(n) => {
                write!(
                    f,
                    "{n} host/port pairs exceeds the per-job cap of {MAX_WORK_UNITS}"
                )
            }
        }
    }
}

impl std::error::Error for ScopeError {}

/// An authorized, not-yet-expired scope. Only constructible via [`Scope::new`].
#[derive(Debug)]
pub struct Scope {
    nets: Vec<IpNet>,
    expires_at: OffsetDateTime,
}

/// An address proven to be inside a [`Scope`]. Fields are private: the only way to
/// obtain one is through the scope, and [`connect`] only accepts this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorizedTarget {
    ip: IpAddr,
    expires_at: OffsetDateTime,
}

impl AuthorizedTarget {
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
}

impl Scope {
    pub fn new(
        cidrs: &[String],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Self, ScopeError> {
        if cidrs.is_empty() {
            return Err(ScopeError::Empty);
        }
        if now >= expires_at {
            return Err(ScopeError::Expired);
        }
        let nets = cidrs
            .iter()
            .map(|s| parse_net(s))
            .collect::<Result<Vec<_>, _>>()?;
        // Union of overlapping/adjacent ranges, so containment checks see the whole scope.
        Ok(Self {
            nets: IpNet::aggregate(&nets),
            expires_at,
        })
    }

    /// Admit a single address, or refuse it.
    pub fn authorize(
        &self,
        ip: IpAddr,
        now: OffsetDateTime,
    ) -> Result<AuthorizedTarget, ScopeError> {
        if now >= self.expires_at {
            return Err(ScopeError::Expired);
        }
        if is_forbidden(ip) {
            return Err(ScopeError::Forbidden(ip));
        }
        if !self.nets.iter().any(|n| n.contains(&ip)) {
            return Err(ScopeError::OutOfScope(vec![ip.to_string()]));
        }
        Ok(AuthorizedTarget {
            ip,
            expires_at: self.expires_at,
        })
    }

    /// Expand job targets into authorized hosts. The whole job is rejected if any target
    /// is not fully inside the scope; no partial scans.
    pub fn expand_targets(
        &self,
        targets: &[String],
        port_count: usize,
        now: OffsetDateTime,
    ) -> Result<Vec<AuthorizedTarget>, ScopeError> {
        let nets = targets
            .iter()
            .map(|s| parse_net(s))
            .collect::<Result<Vec<_>, _>>()?;
        let outside: Vec<String> = targets
            .iter()
            .zip(&nets)
            .filter(|(_, t)| !self.nets.iter().any(|n| n.contains(*t)))
            .map(|(s, _)| s.clone())
            .collect();
        if !outside.is_empty() {
            return Err(ScopeError::OutOfScope(outside));
        }
        // Bound the expansion before doing it: sum of sizes is an upper bound on distinct hosts.
        let upper: u128 = nets.iter().map(host_count).sum();
        if upper > MAX_HOSTS {
            return Err(ScopeError::TooManyHosts(upper));
        }
        let hosts: BTreeSet<IpAddr> = nets.iter().flat_map(IpNet::hosts).collect();
        let work = hosts.len() as u128 * port_count as u128;
        if work > MAX_WORK_UNITS {
            return Err(ScopeError::TooMuchWork(work));
        }
        hosts
            .into_iter()
            .map(|ip| self.authorize(ip, now))
            .collect()
    }
}

#[derive(Debug)]
pub enum ConnectError {
    ScopeExpired,
    TimedOut,
    Io(io::Error),
}

/// The crate's only outbound TCP connect. Re-checks expiry on every call, so a long
/// scan stops at `expires_at` even mid-job.
pub async fn connect(
    target: &AuthorizedTarget,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, ConnectError> {
    if OffsetDateTime::now_utc() >= target.expires_at {
        return Err(ConnectError::ScopeExpired);
    }
    let addr = SocketAddr::new(target.ip, port);
    #[allow(clippy::disallowed_methods)] // the one sanctioned egress point
    let attempt = TcpStream::connect(addr);
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(ConnectError::Io(e)),
        Err(_) => Err(ConnectError::TimedOut),
    }
}

/// Strict IP/CIDR literal parser shared by scopes and targets.
fn parse_net(s: &str) -> Result<IpNet, ScopeError> {
    let net = if s.contains('/') {
        IpNet::from_str(s).map_err(|_| ScopeError::Invalid(s.to_owned()))?
    } else {
        IpNet::from(IpAddr::from_str(s).map_err(|_| ScopeError::Invalid(s.to_owned()))?)
    };
    if net.prefix_len() == 0 {
        return Err(ScopeError::TooBroad(s.to_owned()));
    }
    if net.trunc() != net {
        return Err(ScopeError::HostBitsSet(s.to_owned()));
    }
    if let IpNet::V6(v6) = net {
        if is_ipv4_in_ipv6(v6.network()) {
            return Err(ScopeError::Ipv4InIpv6(s.to_owned()));
        }
    }
    Ok(net)
}

fn host_count(net: &IpNet) -> u128 {
    let bits = u32::from(net.max_prefix_len() - net.prefix_len());
    let size = 1u128 << bits; // prefix 0 is rejected, so bits <= 127
    match net {
        IpNet::V4(_) if net.prefix_len() < 31 => size - 2,
        _ => size,
    }
}

/// `::ffff:a.b.c.d` (mapped) and `::a.b.c.d` (deprecated compatible, excluding `::`/`::1`).
fn is_ipv4_in_ipv6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    let mapped = seg[..5] == [0; 5] && seg[5] == 0xffff;
    let compatible = seg[..6] == [0; 6] && !ip.is_unspecified() && !ip.is_loopback();
    mapped || compatible
}

/// Addresses that are never scannable, even inside an authorized scope.
fn is_forbidden(ip: IpAddr) -> bool {
    match ip {
        // 0.0.0.0/8 ("this network") can reach the local host on some stacks.
        IpAddr::V4(v4) => v4.octets()[0] == 0 || v4.is_multicast() || v4 == Ipv4Addr::BROADCAST,
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast() || is_ipv4_in_ipv6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-01-01 00:00 UTC);
    const LATER: OffsetDateTime = datetime!(2026-02-01 00:00 UTC);

    fn scope(cidrs: &[&str]) -> Scope {
        Scope::new(&strings(cidrs), LATER, NOW).expect("valid scope")
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn allowed(s: &Scope, addr: &str) -> bool {
        s.authorize(ip(addr), NOW).is_ok()
    }

    fn expand(s: &Scope, targets: &[&str]) -> Result<Vec<IpAddr>, ScopeError> {
        s.expand_targets(&strings(targets), 1, NOW)
            .map(|v| v.iter().map(|t| t.ip()).collect())
    }

    // --- scope construction ---

    #[test]
    fn rejects_empty_scope() {
        assert_eq!(Scope::new(&[], LATER, NOW).unwrap_err(), ScopeError::Empty);
    }

    #[test]
    fn rejects_expired_scope_and_expiry_is_exclusive() {
        let cidrs = strings(&["10.0.0.0/8"]);
        assert_eq!(
            Scope::new(&cidrs, NOW, NOW).unwrap_err(),
            ScopeError::Expired
        );
        let one_sec = NOW + time::Duration::SECOND;
        assert!(Scope::new(&cidrs, one_sec, NOW).is_ok());
        let s = Scope::new(&cidrs, one_sec, NOW).unwrap();
        assert_eq!(
            s.authorize(ip("10.0.0.1"), one_sec).unwrap_err(),
            ScopeError::Expired
        );
    }

    #[test]
    fn rejects_slash_zero() {
        for c in ["0.0.0.0/0", "::/0"] {
            assert!(matches!(
                Scope::new(&strings(&[c]), LATER, NOW),
                Err(ScopeError::TooBroad(_))
            ));
        }
    }

    #[test]
    fn rejects_host_bits_set() {
        for c in ["10.0.0.5/24", "2001:db8::1/64"] {
            let err = Scope::new(&strings(&[c]), LATER, NOW).unwrap_err();
            assert!(matches!(err, ScopeError::HostBitsSet(_)), "{c}: {err:?}");
        }
    }

    #[test]
    fn rejects_unparseable_literals() {
        for c in [
            "example.com",
            "localhost",
            "fe80::1%eth0",
            "10.0.0.0/33",
            "2001:db8::/129",
            "010.0.0.1", // leading zeros are octal in inet_aton; ambiguous
            "10.0.0",
            " 10.0.0.1",
            "",
        ] {
            let err = Scope::new(&strings(&[c]), LATER, NOW).unwrap_err();
            assert!(matches!(err, ScopeError::Invalid(_)), "{c:?}: {err:?}");
        }
    }

    #[test]
    fn rejects_ipv4_mapped_and_compatible_ipv6() {
        for c in ["::ffff:10.0.0.1", "::ffff:10.0.0.0/120", "::10.0.0.1"] {
            let err = Scope::new(&strings(&[c]), LATER, NOW).unwrap_err();
            assert!(matches!(err, ScopeError::Ipv4InIpv6(_)), "{c}: {err:?}");
        }
    }

    // --- single-address authorization ---

    #[test]
    fn slash_32_admits_exactly_one_address() {
        let s = scope(&["192.0.2.10/32"]);
        assert!(allowed(&s, "192.0.2.10"));
        assert!(!allowed(&s, "192.0.2.9"));
        assert!(!allowed(&s, "192.0.2.11"));
    }

    #[test]
    fn bare_ip_equals_host_route() {
        let s = scope(&["192.0.2.10"]);
        assert!(allowed(&s, "192.0.2.10"));
        assert!(!allowed(&s, "192.0.2.11"));
    }

    #[test]
    fn slash_31_admits_both_addresses() {
        let s = scope(&["192.0.2.10/31"]);
        assert!(allowed(&s, "192.0.2.10"));
        assert!(allowed(&s, "192.0.2.11"));
        assert!(!allowed(&s, "192.0.2.12"));
        assert_eq!(expand(&s, &["192.0.2.10/31"]).unwrap().len(), 2);
    }

    #[test]
    fn slash_128_admits_exactly_one_address() {
        let s = scope(&["2001:db8::10/128"]);
        assert!(allowed(&s, "2001:db8::10"));
        assert!(!allowed(&s, "2001:db8::f"));
        assert!(!allowed(&s, "2001:db8::11"));
    }

    #[test]
    fn families_never_cross() {
        let v4 = scope(&["10.0.0.0/8"]);
        assert!(!allowed(&v4, "2001:db8::1"));
        assert!(!allowed(&v4, "::ffff:10.0.0.1")); // mapped form of an in-scope v4 address
        let v6 = scope(&["2001:db8::/32"]);
        assert!(!allowed(&v6, "10.0.0.1"));
    }

    #[test]
    fn forbidden_classes_refused_even_inside_scope() {
        let s = scope(&[
            "224.0.0.0/4",
            "255.255.255.255/32",
            "1.0.0.0/8",
            "ff00::/8",
            "::/96",
        ]);
        for a in ["224.0.0.1", "239.1.2.3", "255.255.255.255", "ff02::1", "::"] {
            assert!(
                matches!(s.authorize(ip(a), NOW), Err(ScopeError::Forbidden(_))),
                "{a}"
            );
        }
        let zero_net = Scope::new(&strings(&["0.0.0.0/8"]), LATER, NOW).unwrap();
        assert!(matches!(
            zero_net.authorize(ip("0.0.0.1"), NOW),
            Err(ScopeError::Forbidden(_))
        ));
    }

    #[test]
    fn loopback_only_if_in_scope() {
        let s = scope(&["127.0.0.1/32", "::1/128"]);
        assert!(allowed(&s, "127.0.0.1"));
        assert!(allowed(&s, "::1"));
        assert!(!allowed(&s, "127.0.0.2"));
        assert!(!allowed(&scope(&["10.0.0.0/8"]), "127.0.0.1"));
    }

    // --- target expansion ---

    #[test]
    fn overlapping_scopes_form_a_union() {
        let s = scope(&["10.0.0.0/8", "10.1.0.0/16"]);
        assert!(expand(&s, &["10.1.2.0/24", "10.200.0.0/24"]).is_ok());
        assert!(!allowed(&s, "11.0.0.1"));
    }

    #[test]
    fn adjacent_scopes_aggregate_for_spanning_targets() {
        let s = scope(&["10.0.0.0/24", "10.0.1.0/24"]);
        let hosts = expand(&s, &["10.0.0.0/23"]).unwrap();
        assert_eq!(hosts.len(), 510);
        assert_eq!(hosts.first(), Some(&ip("10.0.0.1")));
        assert_eq!(hosts.last(), Some(&ip("10.0.1.254")));
    }

    #[test]
    fn target_spanning_a_gap_rejects_whole_job() {
        let s = scope(&["10.0.0.0/24", "10.0.2.0/24"]);
        let err = expand(&s, &["10.0.0.5", "10.0.0.0/22"]).unwrap_err();
        assert_eq!(err, ScopeError::OutOfScope(vec!["10.0.0.0/22".into()]));
    }

    #[test]
    fn partially_outside_target_rejects_whole_job_and_names_offenders() {
        let s = scope(&["10.0.0.0/25"]);
        let err = expand(&s, &["10.0.0.1", "10.0.0.0/24", "192.0.2.1"]).unwrap_err();
        assert_eq!(
            err,
            ScopeError::OutOfScope(vec!["10.0.0.0/24".into(), "192.0.2.1".into()])
        );
    }

    #[test]
    fn overlapping_targets_are_deduplicated() {
        let s = scope(&["10.0.0.0/24"]);
        let hosts = expand(&s, &["10.0.0.0/30", "10.0.0.1", "10.0.0.2/31"]).unwrap();
        assert_eq!(hosts, vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")]);
    }

    #[test]
    fn ipv6_small_target_inside_slash_64() {
        let s = scope(&["2001:db8:0:1::/64"]);
        assert_eq!(expand(&s, &["2001:db8:0:1::100/120"]).unwrap().len(), 256);
        assert!(expand(&s, &["2001:db8:0:2::1"]).is_err());
    }

    #[test]
    fn size_caps() {
        let s = scope(&["10.0.0.0/8", "2001:db8::/32"]);
        assert!(expand(&s, &["10.0.0.0/16"]).is_ok()); // 65534 hosts
        assert!(matches!(
            expand(&s, &["10.0.0.0/15"]),
            Err(ScopeError::TooManyHosts(_))
        ));
        assert!(matches!(
            expand(&s, &["2001:db8::/64"]),
            Err(ScopeError::TooManyHosts(_))
        ));
        let work = s
            .expand_targets(&strings(&["10.0.0.0/20"]), 1000, NOW)
            .unwrap_err();
        assert!(matches!(work, ScopeError::TooMuchWork(_)));
    }

    #[test]
    fn target_containing_forbidden_address_rejects_whole_job() {
        let s = scope(&["224.0.0.0/4"]);
        assert!(matches!(
            expand(&s, &["224.0.0.0/30"]),
            Err(ScopeError::Forbidden(_))
        ));
    }

    #[test]
    fn expired_scope_refuses_expansion() {
        let s = scope(&["10.0.0.0/8"]);
        let err = s
            .expand_targets(&strings(&["10.0.0.1"]), 1, LATER)
            .unwrap_err();
        assert_eq!(err, ScopeError::Expired);
    }

    // --- property: authorize agrees with plain containment, minus forbidden classes ---

    fn arb_v4_net() -> impl Strategy<Value = IpNet> {
        (any::<u32>(), 1u8..=32).prop_map(|(a, p)| {
            IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::from(a), p).unwrap().trunc())
        })
    }

    fn arb_v6_net() -> impl Strategy<Value = IpNet> {
        (any::<u128>(), 1u8..=128).prop_map(|(a, p)| {
            IpNet::V6(ipnet::Ipv6Net::new(Ipv6Addr::from(a), p).unwrap().trunc())
        })
    }

    fn arb_ip_near(net: IpNet) -> impl Strategy<Value = IpAddr> {
        // Mix of addresses inside, at the edges of, and far from the net.
        let (lo, hi) = match net {
            IpNet::V4(n) => (
                u128::from(u32::from(n.network())),
                u128::from(u32::from(n.broadcast())),
            ),
            IpNet::V6(n) => (u128::from(n.network()), u128::from(n.broadcast())),
        };
        let v4 = matches!(net, IpNet::V4(_));
        prop_oneof![
            (lo..=hi).boxed(),
            Just(lo.wrapping_sub(1)).boxed(),
            Just(hi.wrapping_add(1)).boxed(),
            any::<u128>().boxed(),
        ]
        .prop_map(move |x| {
            if v4 {
                IpAddr::V4(Ipv4Addr::from(x as u32))
            } else {
                IpAddr::V6(Ipv6Addr::from(x))
            }
        })
    }

    proptest! {
        #[test]
        fn authorize_matches_containment(
            (net, addr) in prop_oneof![arb_v4_net(), arb_v6_net()]
                .prop_flat_map(|n| (Just(n), arb_ip_near(n)))
        ) {
            let s = Scope::new(&[net.to_string()], LATER, NOW);
            prop_assume!(s.is_ok()); // nets in mapped/compat space are refused up front
            let expected = net.contains(&addr) && !is_forbidden(addr);
            prop_assert_eq!(s.unwrap().authorize(addr, NOW).is_ok(), expected);
        }
    }

    // --- egress ---

    #[tokio::test]
    async fn connect_refuses_after_expiry_without_touching_the_network() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let now = OffsetDateTime::now_utc();
        let s = Scope::new(
            &strings(&["127.0.0.1/32"]),
            now + Duration::from_millis(200),
            now,
        )
        .unwrap();
        let target = s.authorize(ip("127.0.0.1"), now).unwrap();

        assert!(connect(&target, port, Duration::from_secs(1)).await.is_ok());
        let _ = listener.accept().await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        let err = connect(&target, port, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectError::ScopeExpired));
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "no connection may reach the listener after expiry"
        );
    }
}
