//! eBPF probe loader using aya.
//! This module is only compiled with the `ebpf` feature flag.

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::schema::EbpfConfig;
use crate::core::threat::ThreatEvent;

/// Load and run eBPF probes using aya.
/// This is a placeholder for the full eBPF implementation.
pub async fn run_ebpf_probes(
    config: &EbpfConfig,
    _tx: tokio::sync::mpsc::Sender<ThreatEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    info!(
        probe_execve = config.probe_execve,
        probe_connect = config.probe_connect,
        probe_open = config.probe_open,
        "Loading eBPF probes"
    );

    // TODO: Load BPF programs compiled from src/ebpf/*.c
    // using aya::Bpf::load() and attach tracepoints/kprobes.
    //
    // For now, this returns an error to trigger the fallback path.
    // When eBPF programs are compiled and included, this will:
    // 1. Load the BPF bytecode
    // 2. Attach to tracepoints (sys_enter_execve, sys_enter_connect, sys_enter_open)
    // 3. Read events from ring buffers
    // 4. Convert events to ThreatEvents and send via tx

    anyhow::bail!("eBPF programs not yet compiled - using fallback");
}
