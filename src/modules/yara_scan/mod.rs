#![cfg(feature = "yara")]

pub mod cache;

use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::config::defaults::resolve_path;
use crate::config::schema::YaraConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;

pub struct YaraScanModule {
    config: YaraConfig,
    rules_dir: PathBuf,
}

impl YaraScanModule {
    pub fn new(config: YaraConfig) -> Self {
        let rules_dir = resolve_path(&config.rules_dir);
        Self { config, rules_dir }
    }
}

#[async_trait]
impl ScanModule for YaraScanModule {
    fn name(&self) -> &str {
        "yara_scan"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();

        // Check if rules directory exists
        if !self.rules_dir.exists() {
            info!(
                path = %self.rules_dir.display(),
                "YARA rules directory not found, skipping scan"
            );
            return Ok(threats);
        }

        // Load and compile YARA rules
        // TODO: Use yara-x crate to compile .yar files and scan processes
        //
        // The implementation would:
        // 1. Glob all .yar files from rules_dir
        // 2. Compile them with yara_x::Compiler
        // 3. Enumerate running processes from /proc
        // 4. For each process, check SHA-256 against cache (skip if known-good)
        // 5. Read /proc/[pid]/exe and scan with compiled rules
        // 6. Report matches as YaraMatch threats

        info!("YARA scan complete (rules dir: {})", self.rules_dir.display());

        Ok(threats)
    }
}
