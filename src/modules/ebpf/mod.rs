pub mod events;
pub mod fallback;
#[cfg(feature = "ebpf")]
pub mod probes;

use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use crate::config::schema::EbpfConfig;
use crate::core::threat::ThreatEvent;
use crate::modules::ScanModule;

pub struct EbpfModule {
    config: EbpfConfig,
}

impl EbpfModule {
    pub fn new(config: EbpfConfig) -> Self {
        Self { config }
    }

    /// Check if the kernel supports eBPF with BTF (BPF Type Format).
    #[allow(dead_code)]
    fn has_btf_support() -> bool {
        std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
    }
}

#[async_trait]
impl ScanModule for EbpfModule {
    fn name(&self) -> &str {
        "ebpf"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        // In scan mode, fall back to polling (same as current behavior).
        // eBPF is primarily useful in watch/daemon mode.
        fallback::poll_scan().await
    }

    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        #[cfg(feature = "ebpf")]
        {
            if Self::has_btf_support() {
                info!("eBPF: BTF support detected, loading probes");
                match probes::run_ebpf_probes(&self.config, tx.clone(), cancel.clone()).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!(error = %e, "eBPF probe loading failed, falling back to polling");
                    }
                }
            } else {
                info!("eBPF: No BTF support, using polling fallback");
            }
        }

        #[cfg(not(feature = "ebpf"))]
        {
            info!("eBPF: feature not compiled, using polling fallback");
        }

        // Fallback: polling loop
        let interval = std::time::Duration::from_secs(self.config.fallback_poll_secs);
        fallback::poll_watch(tx, cancel, interval).await
    }

    fn supports_watch(&self) -> bool {
        true
    }
}
