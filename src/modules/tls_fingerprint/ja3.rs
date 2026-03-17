#![cfg(feature = "tls-fingerprint")]

use sha2::{Digest, Sha256};

/// Compute a JA3 hash from TLS ClientHello parameters.
///
/// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
///
/// Each field is a dash-separated list of decimal values.
pub fn compute_ja3(
    ssl_version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    point_formats: &[u8],
) -> String {
    let ja3_string = format!(
        "{},{},{},{},{}",
        ssl_version,
        join_u16(ciphers),
        join_u16(extensions),
        join_u16(curves),
        join_u8(point_formats),
    );

    let mut hasher = Sha256::new();
    hasher.update(ja3_string.as_bytes());
    // JA3 uses MD5, but we use SHA-256 for security
    hex::encode(hasher.finalize())
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ja3() {
        let hash = compute_ja3(
            0x0303, // TLS 1.2
            &[0xc02c, 0xc02b, 0xc030],
            &[0x0000, 0x000a],
            &[0x001d, 0x0017],
            &[0x00],
        );
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }
}
