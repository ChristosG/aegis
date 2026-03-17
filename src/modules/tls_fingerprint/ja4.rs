#![cfg(feature = "tls-fingerprint")]

/// Compute a JA4 fingerprint from TLS ClientHello parameters.
///
/// JA4 is a more modern fingerprinting algorithm that includes:
/// - Protocol version
/// - SNI presence
/// - Number of cipher suites
/// - Number of extensions
/// - ALPN first value
///
/// This is a simplified implementation.
pub fn compute_ja4(
    tls_version: u16,
    has_sni: bool,
    cipher_count: usize,
    extension_count: usize,
    alpn: Option<&str>,
) -> String {
    let version_char = match tls_version {
        0x0304 => 't', // TLS 1.3
        0x0303 => 's', // TLS 1.2
        0x0302 => 'r', // TLS 1.1
        0x0301 => 'q', // TLS 1.0
        _ => 'x',
    };

    let sni_char = if has_sni { 'd' } else { 'i' };
    let alpn_str = alpn.unwrap_or("00");

    format!(
        "{}{}{}_{:02}_{:02}_{}",
        version_char,
        sni_char,
        if cipher_count > 0 { 'c' } else { '0' },
        cipher_count.min(99),
        extension_count.min(99),
        &alpn_str[..2.min(alpn_str.len())]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ja4() {
        let fp = compute_ja4(0x0303, true, 15, 10, Some("h2"));
        assert!(fp.starts_with("sdc"));
        assert!(fp.contains("15"));
        assert!(fp.contains("10"));
    }
}
