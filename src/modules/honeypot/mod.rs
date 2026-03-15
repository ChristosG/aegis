use anyhow::Result;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::config::schema::HoneypotConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;

/// SSH honeypot module.
///
/// Opens TCP listeners on configured decoy ports, sends a fake SSH banner,
/// lingers briefly, and emits a High-severity threat for any connection.
pub struct HoneypotModule {
    config: HoneypotConfig,
}

impl HoneypotModule {
    pub fn new(config: HoneypotConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ScanModule for HoneypotModule {
    fn name(&self) -> &str {
        "honeypot"
    }

    /// Scan is a no-op for the honeypot; it operates via watch().
    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        Ok(Vec::new())
    }

    /// Run TCP listeners on all configured honeypot ports.
    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        if self.config.ports.is_empty() {
            info!("Honeypot: no ports configured, watch is idle");
            cancel.cancelled().await;
            return Ok(());
        }

        let mut handles = Vec::new();

        for port in &self.config.ports {
            let port = *port;
            let tx = tx.clone();
            let cancel = cancel.clone();
            let linger = self.config.linger_seconds;
            let auto_block = self.config.auto_block;

            let handle = tokio::spawn(async move {
                let bind_addr = format!("0.0.0.0:{}", port);
                let listener = match TcpListener::bind(&bind_addr).await {
                    Ok(l) => {
                        info!(port = port, "Honeypot listener started");
                        l
                    }
                    Err(e) => {
                        error!(
                            port = port,
                            error = %e,
                            "Failed to bind honeypot port (may need root/CAP_NET_BIND_SERVICE)"
                        );
                        return;
                    }
                };

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            info!(port = port, "Honeypot listener shutting down");
                            break;
                        }
                        accept_result = listener.accept() => {
                            match accept_result {
                                Ok((mut stream, addr)) => {
                                    let source_ip = addr.ip();
                                    info!(
                                        port = port,
                                        source = %addr,
                                        "Honeypot connection received"
                                    );

                                    // Send fake SSH banner
                                    let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
                                    let _ = stream.write_all(banner).await;

                                    // Emit threat event
                                    let mut event = ThreatEvent::new(
                                        ThreatType::HoneypotConnection,
                                        "honeypot",
                                        format!(
                                            "Connection to honeypot port {} from {}",
                                            port, source_ip
                                        ),
                                    )
                                    .with_source_ip(source_ip)
                                    .with_target(format!("port:{}", port))
                                    .with_detail("honeypot_port", port.to_string())
                                    .with_detail("source_port", addr.port().to_string());

                                    if auto_block {
                                        event = event.with_detail("recommend_block", "true".to_string());
                                    }

                                    let _ = tx.send(event).await;

                                    // Linger to waste attacker time
                                    tokio::time::sleep(
                                        std::time::Duration::from_secs(linger),
                                    )
                                    .await;

                                    // Gracefully close
                                    let _ = stream.shutdown().await;
                                    debug!(
                                        port = port,
                                        source = %addr,
                                        "Honeypot connection closed after linger"
                                    );
                                }
                                Err(e) => {
                                    warn!(port = port, error = %e, "Honeypot accept error");
                                }
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for cancellation
        cancel.cancelled().await;

        // Wait for all listener tasks to finish
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    fn supports_watch(&self) -> bool {
        true
    }
}
