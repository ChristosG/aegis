#![cfg(feature = "tls-fingerprint")]

pub mod ja3;
pub mod ja4;
pub mod known_bad;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::config::schema::TlsFingerprintConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;

pub struct TlsFingerprintModule {
    config: TlsFingerprintConfig,
}

impl TlsFingerprintModule {
    pub fn new(config: TlsFingerprintConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ScanModule for TlsFingerprintModule {
    fn name(&self) -> &str {
        "tls_fingerprint"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        // TLS fingerprinting is watch-only (continuous capture).
        // In scan mode, return empty.
        Ok(Vec::new())
    }

    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        info!(
            interface = %self.config.interface,
            "Starting TLS fingerprint capture"
        );

        // Load known-bad fingerprints
        let bad_fingerprints = known_bad::load_known_bad(&self.config.known_bad_file);
        info!(
            count = bad_fingerprints.len(),
            "Loaded known-bad TLS fingerprints"
        );

        // TODO: Use pnet to capture TCP:443 SYN packets with BPF filter,
        // parse TLS ClientHello, compute JA3/JA4 hashes, and match against DB.
        //
        // For now, wait for cancellation.
        cancel.cancelled().await;
        Ok(())
    }

    fn supports_watch(&self) -> bool {
        true
    }
}
