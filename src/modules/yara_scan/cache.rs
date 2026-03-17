#![cfg(feature = "yara")]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::config::defaults::resolve_path;

/// Cache of SHA-256 hashes for known-good binaries.
/// Avoids re-scanning files that haven't changed.
pub struct KnownGoodCache {
    cache: HashMap<String, String>, // path -> sha256
    cache_path: PathBuf,
}

impl KnownGoodCache {
    pub fn new() -> Self {
        let cache_path = resolve_path("~/.aegis/yara_cache.json");
        let cache = Self::load(&cache_path).unwrap_or_default();
        Self { cache, cache_path }
    }

    /// Check if a file path is in the known-good cache with matching hash.
    pub fn is_known_good(&self, path: &str, sha256: &str) -> bool {
        self.cache.get(path).map(|h| h == sha256).unwrap_or(false)
    }

    /// Add a file to the known-good cache.
    pub fn mark_good(&mut self, path: String, sha256: String) {
        self.cache.insert(path, sha256);
    }

    /// Save the cache to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.cache)?;
        fs::write(&self.cache_path, json)?;
        Ok(())
    }

    fn load(path: &PathBuf) -> anyhow::Result<HashMap<String, String>> {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}
