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

/// Default known-bad fingerprints.
/// Empty by default — Aegis uses SHA-256 (not MD5) for JA3 hashes,
/// so standard MD5-based databases are incompatible. Populate
/// ~/.aegis/ja3_bad.json with SHA-256 fingerprints for your environment.
fn default_known_bad() -> HashSet<String> {
    HashSet::new()
}
