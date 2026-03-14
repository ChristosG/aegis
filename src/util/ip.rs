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

/// Check whether an IP address belongs to a private/reserved range.
///
/// Covers RFC 1918 (IPv4), loopback, link-local, and IPv6 equivalents.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
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
pub fn is_whitelisted(ip: &IpAddr, whitelist: &[IpNet]) -> bool {
    whitelist.iter().any(|net| net.contains(ip))
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
}
