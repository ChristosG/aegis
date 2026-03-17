use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::core::threat::ThreatEvent;

/// Fallback scan when eBPF is not available.
/// Delegates to the existing process and network scanning logic.
pub async fn poll_scan() -> Result<Vec<ThreatEvent>> {
    // In fallback mode, the existing process and network modules
    // handle threat detection. The eBPF module returns empty here
    // to avoid duplicate detections.
    Ok(Vec::new())
}

/// Fallback watch loop when eBPF is not available.
/// Uses periodic polling at the configured interval.
pub async fn poll_watch(
    _tx: tokio::sync::mpsc::Sender<ThreatEvent>,
    cancel: CancellationToken,
    interval: std::time::Duration,
) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                // In fallback mode, the existing modules do the actual scanning.
                // This loop just keeps the watch task alive.
            }
        }
    }

    Ok(())
}
