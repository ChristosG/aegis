use serde::{Deserialize, Serialize};

/// Event emitted when a process calls execve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecveEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub timestamp_ns: u64,
}

/// Event emitted when a process calls connect().
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub dest_addr: String,
    pub dest_port: u16,
    pub timestamp_ns: u64,
}

/// Event emitted when a process opens a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub flags: u32,
    pub timestamp_ns: u64,
}

/// Unified eBPF event type for the broadcast channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EbpfEvent {
    Execve(ExecveEvent),
    Connect(ConnectEvent),
    Open(OpenEvent),
}
