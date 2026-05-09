use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use ipnet::IpNet;

/// Parse a string into an IP address (v4 or v6).
pub fn parse_ip(s: &str) -> Result<IpAddr> {
    s.trim()
        .parse::<IpAddr>()
        .with_context(|| format!("Invalid IP address: '{}'", s))
}

/// Parse a CIDR notation string (e.g. "10.0.0.0/8") into an IpNet.
pub fn parse_cidr(s: &str) -> Result<IpNet> {
    s.trim()
        .parse::<IpNet>()
        .with_context(|| format!("Invalid CIDR notation: '{}'", s))
}

/// Collapse an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) down to its bare
/// IPv4 form, leaving all other addresses untouched.
///
/// Dual-stack sockets on Linux (Java's default, plus many other runtimes)
/// cause `/proc/net/tcp6` to report IPv4 peers as `::ffff:a.b.c.d`. Without
/// canonicalization those addresses slip past every IPv4-based safety check
/// — `is_private`'s loopback branch (`Ipv6Addr::is_loopback()` only matches
/// literal `::1`), `is_whitelisted` (IPv4 CIDRs can't contain IPv6), and the
/// v2.6.0 Bucket-A safety pin (same issue). That's the bug class that caused
/// the 2026-04-10 loopback outage, plus silent false-blocking of
/// Cloudflare/Google/CloudFront CIDRs across the same period.
///
/// Call this at module boundaries when an IP crosses from a parser or
/// network source into any logic that inspects address semantics.
pub fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Check whether an IP address belongs to a private/reserved range.
///
/// Covers RFC 1918 (IPv4), loopback, link-local, and IPv6 equivalents.
///
/// Canonicalizes IPv4-mapped IPv6 first so `::ffff:127.0.0.1` is correctly
/// classified as loopback (see `canonicalize`).
pub fn is_private(ip: &IpAddr) -> bool {
    match canonicalize(*ip) {
        IpAddr::V4(v4) => is_private_v4(&v4),
        IpAddr::V6(v6) => is_private_v6(&v6),
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 0.0.0.0/8 (current network)
    if octets[0] == 0 {
        return true;
    }
    // 255.255.255.255 broadcast
    if ip.is_broadcast() {
        return true;
    }
    false
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    // ::1 loopback
    if ip.is_loopback() {
        return true;
    }
    let segments = ip.segments();
    // fe80::/10 link-local
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // fc00::/7 unique local address (ULA)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // :: unspecified
    if ip.is_unspecified() {
        return true;
    }
    false
}

/// Check if an IP address falls within any of the given CIDR whitelist ranges.
///
/// Canonicalizes IPv4-mapped IPv6 before the containment check so that, e.g.,
/// `::ffff:127.0.0.1` correctly matches a `127.0.0.0/8` whitelist entry and
/// `::ffff:104.18.19.12` correctly matches a Cloudflare safety-pin CIDR.
/// Without this, `ipnet::IpNet::contains` is family-strict and silently
/// returns false across IPv4/IPv6 family boundaries — the exact bug that
/// let the v2.6.0 safety pin fail in production.
pub fn is_whitelisted(ip: &IpAddr, whitelist: &[IpNet]) -> bool {
    let canonical = canonicalize(*ip);
    whitelist.iter().any(|net| net.contains(&canonical))
}

/// Parse a list of CIDR strings into IpNet values, skipping any that fail to parse.
pub fn parse_whitelist(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| {
            parse_cidr(s).ok().or_else(|| {
                tracing::warn!(cidr = %s, "Skipping invalid whitelist CIDR");
                None
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_v4() {
        let ip = parse_ip("192.168.1.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_parse_ip_v6() {
        let ip = parse_ip("::1").unwrap();
        assert!(ip.is_loopback());
    }

    #[test]
    fn test_parse_ip_with_whitespace() {
        let ip = parse_ip("  10.0.0.1  ").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_ip_invalid() {
        assert!(parse_ip("not-an-ip").is_err());
        assert!(parse_ip("256.1.1.1").is_err());
    }

    #[test]
    fn test_parse_cidr() {
        let net = parse_cidr("10.0.0.0/8").unwrap();
        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!net.contains(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn test_parse_cidr_v6() {
        let net = parse_cidr("::1/128").unwrap();
        assert!(net.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("invalid").is_err());
    }

    #[test]
    fn test_is_private_v4() {
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));

        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    #[test]
    fn test_is_private_v6() {
        assert!(is_private(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        // fe80::1 link-local
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private(&link_local));

        // fd00::1 unique local
        let ula: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private(&ula));

        // 2001:db8::1 documentation prefix - not private by our definition
        let doc: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_private(&doc));
    }

    #[test]
    fn test_is_whitelisted() {
        let whitelist = vec![
            parse_cidr("10.0.0.0/8").unwrap(),
            parse_cidr("192.168.0.0/16").unwrap(),
        ];

        assert!(is_whitelisted(
            &IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            &whitelist
        ));
        assert!(is_whitelisted(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &whitelist
        ));
        assert!(!is_whitelisted(
            &IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &whitelist
        ));
    }

    #[test]
    fn test_is_whitelisted_empty() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!is_whitelisted(&ip, &[]));
    }

    #[test]
    fn test_parse_whitelist() {
        let cidrs = vec!["10.0.0.0/8".into(), "invalid".into(), "::1/128".into()];
        let nets = parse_whitelist(&cidrs);
        assert_eq!(nets.len(), 2);
    }

    // -----------------------------------------------------------------------
    // IPv4-mapped IPv6 canonicalization — regression tests for the 2026-04-10
    // incident where dual-stack sockets produced `::ffff:127.0.0.1` addresses
    // that bypassed every IPv4-based safety check.
    // -----------------------------------------------------------------------

    #[test]
    fn test_canonicalize_ipv4_mapped_loopback() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let canonical = canonicalize(mapped);
        assert_eq!(canonical, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_canonicalize_ipv4_mapped_public() {
        // 104.18.19.12 is a real Cloudflare IP that was false-blocked in production.
        let mapped: IpAddr = "::ffff:104.18.19.12".parse().unwrap();
        let canonical = canonicalize(mapped);
        assert_eq!(canonical, IpAddr::V4(Ipv4Addr::new(104, 18, 19, 12)));
    }

    #[test]
    fn test_canonicalize_pure_ipv6_unchanged() {
        // A real IPv6 address is not IPv4-mapped and must not be rewritten.
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonicalize(v6), v6);

        // ::1 is not IPv4-mapped either.
        let localhost6: IpAddr = "::1".parse().unwrap();
        assert_eq!(canonicalize(localhost6), localhost6);
    }

    #[test]
    fn test_canonicalize_ipv4_unchanged() {
        let v4: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(canonicalize(v4), v4);
    }

    #[test]
    fn test_is_private_recognizes_ipv4_mapped_loopback() {
        // THE incident bug: `Ipv6Addr::is_loopback()` only matches `::1`, so
        // `::ffff:127.0.0.1` used to skate past the private-range check in
        // every network detector. This test is the regression guard.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            is_private(&mapped),
            "::ffff:127.0.0.1 must be treated as loopback"
        );
    }

    #[test]
    fn test_is_private_recognizes_ipv4_mapped_rfc1918() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_private(&mapped));
        let mapped: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_private(&mapped));
    }

    #[test]
    fn test_is_whitelisted_matches_ipv4_mapped_across_family_boundary() {
        // The v2.6.0 safety pin was defeated by this: loopback is in the
        // whitelist as `127.0.0.0/8` (IPv4), but the incoming IP was an
        // IPv4-mapped IPv6 which `IpNet::contains` rejects due to family
        // mismatch. Canonicalization fixes both loopback AND public CDN IPs.
        let whitelist = vec![
            parse_cidr("127.0.0.0/8").unwrap(),
            parse_cidr("104.18.0.0/16").unwrap(), // Cloudflare-ish
        ];
        let loopback_mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let cdn_mapped: IpAddr = "::ffff:104.18.19.12".parse().unwrap();
        let unrelated: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(is_whitelisted(&loopback_mapped, &whitelist));
        assert!(is_whitelisted(&cdn_mapped, &whitelist));
        assert!(!is_whitelisted(&unrelated, &whitelist));
    }
}
