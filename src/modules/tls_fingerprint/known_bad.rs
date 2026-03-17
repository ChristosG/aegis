#![cfg(feature = "tls-fingerprint")]

use std::collections::HashSet;
use std::fs;

use crate::config::defaults::resolve_path;

/// Load known-bad TLS fingerprints from a JSON file.
/// Returns an empty set if the file doesn't exist.
pub fn load_known_bad(path: &str) -> HashSet<String> {
    let resolved = resolve_path(path);
    let content = match fs::read_to_string(&resolved) {
        Ok(c) => c,
        Err(_) => return default_known_bad(),
    };

    match serde_json::from_str::<Vec<KnownBadEntry>>(&content) {
        Ok(entries) => entries.into_iter().map(|e| e.fingerprint).collect(),
        Err(_) => default_known_bad(),
    }
}

#[derive(serde::Deserialize)]
struct KnownBadEntry {
    fingerprint: String,
    #[allow(dead_code)]
    description: String,
}

/// Default known-bad fingerprints (common malware/C2 tools).
fn default_known_bad() -> HashSet<String> {
    let mut set = HashSet::new();
    // These are well-known JA3 hashes for common malware/C2 frameworks
    // Cobalt Strike default
    set.insert("72a589da586844d7f0818ce684948eea".to_string());
    // Metasploit Meterpreter
    set.insert("5d65ea3fb1d4aa7d826733d2f2cbf7df".to_string());
    // Trickbot
    set.insert("6734f37431670b3ab4292b8f60f29984".to_string());
    set
}
