pub mod anomaly;
pub mod audit;
pub mod auth;
pub mod cert;
pub mod dns;
pub mod ebpf;
pub mod enrichment;
pub mod file_integrity;
pub mod forensic;
pub mod honeypot;
pub mod network;
pub mod process;
pub mod rootkit;
pub mod ssh_session;
pub mod threat_intel;
pub mod web;

#[cfg(feature = "tls-fingerprint")]
pub mod tls_fingerprint;
#[cfg(feature = "yara")]
pub mod yara_scan;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::schema::AegisConfig;
use crate::core::threat::ThreatEvent;

/// Trait that all security scanning modules must implement.
///
/// Each module can perform a one-shot scan (returning a list of threats)
/// and/or run a continuous watch loop (for daemon mode).
#[async_trait]
pub trait ScanModule: Send + Sync {
    /// The human-readable name of this module (e.g., "network", "process").
    fn name(&self) -> &str;

    /// Run a one-shot scan and return any detected threats.
    async fn scan(&self) -> Result<Vec<ThreatEvent>>;

    /// Start a continuous watch loop. The default implementation simply
    /// calls `scan()` once, since not all modules support watch mode.
    /// Modules that support real-time monitoring (e.g., file_integrity with inotify)
    /// should override this.
    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        // Default: run a single scan and forward results
        let threats = self.scan().await?;
        for threat in threats {
            let _ = tx.send(threat).await;
        }

        // Then wait for cancellation
        cancel.cancelled().await;
        Ok(())
    }

    /// Whether this module supports continuous watch mode.
    fn supports_watch(&self) -> bool {
        false
    }
}

/// Create all enabled modules based on configuration.
/// Returns Arc-wrapped modules so they can be shared with daemon watch tasks.
pub fn create_modules(config: &AegisConfig) -> Vec<Arc<dyn ScanModule>> {
    let mut modules: Vec<Arc<dyn ScanModule>> = Vec::new();

    for module_name in &config.general.modules {
        match module_name.as_str() {
            "network" if config.network.enabled => {
                modules.push(Arc::new(network::NetworkModule::new(
                    config.network.clone(),
                )));
            }
            "process" if config.process.enabled => {
                modules.push(Arc::new(process::ProcessModule::new(
                    config.process.clone(),
                )));
            }
            "file_integrity" if config.file_integrity.enabled => {
                modules.push(Arc::new(file_integrity::FileIntegrityModule::new(
                    config.file_integrity.clone(),
                )));
            }
            "auth" if config.auth.enabled => {
                let data_dir = crate::config::defaults::resolve_path(&config.general.data_dir);
                modules.push(Arc::new(auth::AuthModule::new(
                    config.auth.clone(),
                    data_dir,
                )));
            }
            "web" if config.web.enabled => {
                let data_dir = crate::config::defaults::resolve_path(&config.general.data_dir);
                modules.push(Arc::new(web::WebModule::new(config.web.clone(), data_dir)));
            }
            "threat_intel" if config.threat_intel.enabled => {
                modules.push(Arc::new(threat_intel::ThreatIntelModule::new(
                    config.threat_intel.clone(),
                )));
            }
            "honeypot" if config.honeypot.enabled => {
                modules.push(Arc::new(honeypot::HoneypotModule::new(
                    config.honeypot.clone(),
                )));
            }
            "anomaly" if config.anomaly.enabled => {
                let data_dir = crate::config::defaults::resolve_path(&config.general.data_dir);
                modules.push(Arc::new(anomaly::AnomalyModule::new(
                    config.anomaly.clone(),
                    data_dir,
                )));
            }
            "cert" if config.cert.enabled => {
                modules.push(Arc::new(cert::CertModule::new(config.cert.clone())));
            }
            "dns" if config.dns.enabled => {
                let data_dir = crate::config::defaults::resolve_path(&config.general.data_dir);
                modules.push(Arc::new(dns::DnsModule::new(config.dns.clone(), data_dir)));
            }
            "rootkit" if config.rootkit.enabled => {
                modules.push(Arc::new(rootkit::RootkitModule::new(
                    config.rootkit.clone(),
                )));
            }
            "ssh_session" if config.ssh_session.enabled => {
                let data_dir = crate::config::defaults::resolve_path(&config.general.data_dir);
                modules.push(Arc::new(ssh_session::SshSessionModule::new(
                    config.ssh_session.clone(),
                    data_dir,
                )));
            }
            #[cfg(feature = "tls-fingerprint")]
            "tls_fingerprint" if config.tls_fingerprint.enabled => {
                modules.push(Arc::new(tls_fingerprint::TlsFingerprintModule::new(
                    config.tls_fingerprint.clone(),
                )));
            }
            #[cfg(feature = "yara")]
            "yara_scan" if config.yara.enabled => {
                modules.push(Arc::new(yara_scan::YaraScanModule::new(
                    config.yara.clone(),
                )));
            }
            name => {
                tracing::warn!(module = name, "Unknown or disabled module, skipping");
            }
        }
    }

    modules
}
