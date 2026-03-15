use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info};

use crate::config::schema::ProcessConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};
use crate::modules::ScanModule;
use crate::util::proc_parse::{list_pids, read_proc_info, ProcInfo};

/// Known shell binary names used for reverse shell detection.
const SHELL_NAMES: &[&str] = &[
    "bash", "sh", "zsh", "dash", "fish", "python", "python2", "python3", "perl", "ruby", "php",
    "nc", "ncat", "socat",
];

/// Suspicious cmdline patterns that indicate a reverse shell.
const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "/dev/tcp/",
    "bash -i",
    "bash%20-i",
    "nc -e",
    "ncat -e",
    "nc -c",
    "socat exec:",
    "socat tcp:",
    "import socket",
    "import pty",
    "pty.spawn",
    "subprocess.call",
    "os.dup2",
    "fsockopen",
    "exec(/bin/",
    "perl -e",
    "ruby -rsocket",
    "php -r",
];

/// Suspicious cmdline flags/patterns that indicate crypto mining.
const MINER_CMDLINE_PATTERNS: &[&str] = &[
    "--algo",
    "--pool",
    "stratum+tcp://",
    "stratum+ssl://",
    "-o pool.",
    "--donate-level",
    "--coin",
    "--randomx",
    "-o stratum",
    "--threads",
    "--cpu-priority",
    "cryptonight",
    "randomx",
    "kawpow",
    "ethash",
];

/// Process scanning module: detects crypto miners, reverse shells, and
/// suspicious binaries running from temp directories.
pub struct ProcessModule {
    config: ProcessConfig,
}

impl ProcessModule {
    pub fn new(config: ProcessConfig) -> Self {
        Self { config }
    }

    /// Enumerate all processes and return their ProcInfo, skipping any that
    /// fail to read (e.g., because the process exited).
    fn enumerate_processes(&self) -> Vec<ProcInfo> {
        let pids = list_pids();
        let mut procs = Vec::with_capacity(pids.len());

        for pid in pids {
            match read_proc_info(pid) {
                Ok(info) => procs.push(info),
                Err(e) => {
                    debug!(pid = pid, error = %e, "Failed to read proc info, process may have exited");
                }
            }
        }

        procs
    }

    /// Estimate CPU usage percentage for a process by reading /proc/[pid]/stat.
    /// Uses total CPU time (utime + stime) relative to system uptime.
    fn estimate_cpu_percent(&self, pid: u32) -> Option<f64> {
        // Read /proc/[pid]/stat
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = match std::fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => return None,
        };

        // The stat file format has the comm field in parens which can contain spaces.
        // Find the closing paren and parse fields after it.
        let close_paren = stat_content.rfind(')')?;
        let after_comm = &stat_content[close_paren + 2..]; // skip ") "
        let fields: Vec<&str> = after_comm.split_whitespace().collect();

        // Fields after comm (0-indexed from after the closing paren):
        // 0=state, 1=ppid, ..., 11=utime, 12=stime, 13=cutime, 14=cstime, ...19=starttime
        if fields.len() < 20 {
            return None;
        }

        let utime: u64 = fields[11].parse().ok()?;
        let stime: u64 = fields[12].parse().ok()?;
        let starttime: u64 = fields[19].parse().ok()?;

        // Read system uptime
        let uptime_content = std::fs::read_to_string("/proc/uptime").ok()?;
        let uptime_secs: f64 = uptime_content.split_whitespace().next()?.parse().ok()?;

        // Get clock ticks per second (typically 100 on Linux)
        let clk_tck: f64 = 100.0; // sysconf(_SC_CLK_TCK) is almost always 100 on Linux

        let total_time = utime + stime;
        let process_start_secs = starttime as f64 / clk_tck;
        let elapsed_secs = uptime_secs - process_start_secs;

        if elapsed_secs <= 0.0 {
            return None;
        }

        let cpu_percent = (total_time as f64 / clk_tck) / elapsed_secs * 100.0;
        Some(cpu_percent)
    }

    /// Detect crypto miner processes by name, cmdline patterns, and CPU usage.
    fn detect_crypto_miners(&self, processes: &[ProcInfo]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for proc in processes {
            let name_lower = proc.name.to_lowercase();
            let cmdline_joined = proc.cmdline.join(" ");
            let cmdline_lower = cmdline_joined.to_lowercase();

            let mut is_miner = false;
            let mut reason = String::new();

            // Check process name against known miner names (case-insensitive substring)
            for miner_name in &self.config.miner_names {
                let miner_lower = miner_name.to_lowercase();
                if name_lower.contains(&miner_lower) {
                    is_miner = true;
                    reason = format!(
                        "Process name '{}' matches known miner '{}'",
                        proc.name, miner_name
                    );
                    break;
                }
            }

            // Check cmdline for miner-related flags
            if !is_miner {
                for pattern in MINER_CMDLINE_PATTERNS {
                    if cmdline_lower.contains(&pattern.to_lowercase()) {
                        is_miner = true;
                        reason = format!(
                            "Command line contains miner pattern '{}': {}",
                            pattern,
                            truncate_string(&cmdline_joined, 200)
                        );
                        break;
                    }
                }
            }

            // Check CPU usage if above threshold
            if !is_miner {
                if let Some(cpu_pct) = self.estimate_cpu_percent(proc.pid) {
                    if cpu_pct >= self.config.miner_cpu_threshold {
                        // High CPU alone isn't a miner, but combined with suspicious traits
                        // we should check more carefully. For now, only flag if it has some
                        // miner-like characteristics we might have missed.
                        debug!(
                            pid = proc.pid,
                            name = %proc.name,
                            cpu_percent = cpu_pct,
                            "High CPU process detected but no miner signature found"
                        );
                    }
                }
            }

            if is_miner {
                let cpu_str = self
                    .estimate_cpu_percent(proc.pid)
                    .map(|c| format!("{:.1}%", c))
                    .unwrap_or_else(|| "unknown".to_string());

                let exe_str = proc.exe.as_deref().unwrap_or("unknown");

                let description = format!(
                    "Crypto miner detected: PID {} ({}) - {}",
                    proc.pid, proc.name, reason
                );

                let event = ThreatEvent::new(ThreatType::CryptoMiner, "process", &description)
                    .with_severity(ThreatSeverity::High)
                    .with_detail("pid", proc.pid.to_string())
                    .with_detail("name", &proc.name)
                    .with_detail("exe", exe_str)
                    .with_detail("cpu_usage", &cpu_str)
                    .with_detail("uid", proc.uid.to_string())
                    .with_detail("cmdline", truncate_string(&cmdline_joined, 500));

                debug!(
                    pid = proc.pid,
                    name = %proc.name,
                    cpu = %cpu_str,
                    "Crypto miner detected"
                );

                threats.push(event);
            }
        }

        threats
    }

    /// Check if a process has network socket file descriptors.
    fn has_socket_fds(&self, pid: u32) -> bool {
        let fd_dir = format!("/proc/{}/fd", pid);
        let entries = match std::fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => return false,
        };

        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy();
                if target_str.starts_with("socket:") {
                    return true;
                }
            }
        }

        false
    }

    /// Get the remote IP of any socket connection for a process by reading
    /// /proc/[pid]/net/tcp and matching inodes from /proc/[pid]/fd.
    fn get_process_remote_ips(&self, pid: u32) -> Vec<String> {
        let mut remote_addrs = Vec::new();

        // Collect socket inodes from fd
        let fd_dir = format!("/proc/{}/fd", pid);
        let mut socket_inodes: Vec<String> = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&fd_dir) {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let target_str = target.to_string_lossy().to_string();
                    if let Some(inode) = target_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        socket_inodes.push(inode.to_string());
                    }
                }
            }
        }

        if socket_inodes.is_empty() {
            return remote_addrs;
        }

        // Read /proc/net/tcp and /proc/net/tcp6 to find connections matching inodes
        for tcp_path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            let content = match std::fs::read_to_string(tcp_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    continue;
                }

                // Field 9 (0-indexed) is the inode
                let inode = fields[9];
                if socket_inodes.contains(&inode.to_string()) {
                    // Parse the remote address
                    if let Ok((_, _, remote_ip, remote_port, state)) =
                        crate::util::proc_parse::parse_tcp_line(line)
                    {
                        if state == crate::util::proc_parse::tcp_state::ESTABLISHED
                            && !crate::util::ip::is_private(&remote_ip)
                        {
                            remote_addrs.push(format!("{}:{}", remote_ip, remote_port));
                        }
                    }
                }
            }
        }

        remote_addrs
    }

    /// Detect reverse shell processes: shells with network socket FDs or
    /// suspicious cmdline patterns.
    fn detect_reverse_shells(&self, processes: &[ProcInfo]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        if !self.config.detect_reverse_shells {
            return threats;
        }

        for proc in processes {
            let name_lower = proc.name.to_lowercase();
            let cmdline_joined = proc.cmdline.join(" ");
            let cmdline_lower = cmdline_joined.to_lowercase();

            // First check: cmdline pattern match (fast, doesn't require fd access)
            let mut cmdline_match = false;
            let mut matched_pattern = String::new();

            for pattern in REVERSE_SHELL_PATTERNS {
                if cmdline_lower.contains(&pattern.to_lowercase()) {
                    cmdline_match = true;
                    matched_pattern = pattern.to_string();
                    break;
                }
            }

            if cmdline_match {
                let description = format!(
                    "Reverse shell pattern in cmdline: PID {} ({}) matched '{}'",
                    proc.pid, proc.name, matched_pattern
                );

                let event = ThreatEvent::new(ThreatType::ReverseShell, "process", &description)
                    .with_severity(ThreatSeverity::Critical)
                    .with_detail("pid", proc.pid.to_string())
                    .with_detail("name", &proc.name)
                    .with_detail("matched_pattern", &matched_pattern)
                    .with_detail("cmdline", truncate_string(&cmdline_joined, 500))
                    .with_detail("detection_method", "cmdline_pattern");

                debug!(
                    pid = proc.pid,
                    name = %proc.name,
                    pattern = %matched_pattern,
                    "Reverse shell detected via cmdline pattern"
                );

                threats.push(event);
                continue;
            }

            // Second check: shell process with network socket FDs
            let is_shell = SHELL_NAMES
                .iter()
                .any(|s| name_lower == *s || name_lower.starts_with(&format!("{}.", s)));

            if !is_shell {
                continue;
            }

            // Check if this shell has socket file descriptors
            if self.has_socket_fds(proc.pid) {
                // Try to find the remote IP it's connected to
                let remote_ips = self.get_process_remote_ips(proc.pid);

                if !remote_ips.is_empty() {
                    let remotes_str = remote_ips.join(", ");
                    let description = format!(
                        "Reverse shell detected: PID {} ({}) connected to {}",
                        proc.pid, proc.name, remotes_str
                    );

                    let event = ThreatEvent::new(ThreatType::ReverseShell, "process", &description)
                        .with_severity(ThreatSeverity::Critical)
                        .with_detail("pid", proc.pid.to_string())
                        .with_detail("name", &proc.name)
                        .with_detail("remote_addresses", &remotes_str)
                        .with_detail("uid", proc.uid.to_string())
                        .with_detail("cmdline", truncate_string(&cmdline_joined, 500))
                        .with_detail("detection_method", "socket_fd");

                    debug!(
                        pid = proc.pid,
                        name = %proc.name,
                        remotes = %remotes_str,
                        "Reverse shell detected via socket FD"
                    );

                    threats.push(event);
                } else {
                    // Shell has sockets but none connected to public IPs -
                    // could be local, skip
                    debug!(
                        pid = proc.pid,
                        name = %proc.name,
                        "Shell with sockets but no public remote connections"
                    );
                }
            }
        }

        threats
    }

    /// Detect binaries running from suspicious directories or with deleted executables.
    ///
    /// Deleted binaries in standard system paths (/usr/bin, /usr/sbin, etc.) are
    /// normal after a package update — the old process keeps the deleted binary in
    /// memory until restarted. We only flag deleted binaries in non-standard paths.
    fn detect_suspicious_binaries(&self, processes: &[ProcInfo]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        /// Standard system directories where a "(deleted)" exe is normal
        /// (package upgrades replace the binary while the old process runs).
        const SAFE_DELETED_PREFIXES: &[&str] = &[
            "/usr/bin/",
            "/usr/sbin/",
            "/usr/lib/",
            "/usr/libexec/",
            "/bin/",
            "/sbin/",
            "/lib/",
            "/snap/",
        ];

        for proc in processes {
            let exe_path = match &proc.exe {
                Some(e) => e,
                None => continue,
            };

            let mut suspicious = false;
            let mut reason = String::new();

            // Check if binary has been deleted
            if exe_path.ends_with(" (deleted)") {
                let clean_path = exe_path.strip_suffix(" (deleted)").unwrap_or(exe_path);

                // Deleted binaries in standard system paths are normal after
                // package updates (e.g., python3.12 upgraded by unattended-upgrades).
                let in_safe_dir = SAFE_DELETED_PREFIXES
                    .iter()
                    .any(|prefix| clean_path.starts_with(prefix));

                if !in_safe_dir {
                    suspicious = true;
                    reason = format!("Binary has been deleted from disk: {}", exe_path);
                } else {
                    debug!(
                        pid = proc.pid,
                        name = %proc.name,
                        exe = %exe_path,
                        "Ignoring deleted binary in standard path (likely package update)"
                    );
                }
            }

            // Check if exe path starts with any suspicious directory
            if !suspicious {
                // Strip " (deleted)" suffix if present for path checking
                let clean_path = exe_path.strip_suffix(" (deleted)").unwrap_or(exe_path);

                for dir in &self.config.suspicious_dirs {
                    if clean_path.starts_with(dir.as_str()) {
                        suspicious = true;
                        reason = format!(
                            "Binary running from suspicious directory '{}': {}",
                            dir, exe_path
                        );
                        break;
                    }
                }
            }

            if suspicious {
                let cmdline_joined = proc.cmdline.join(" ");

                let description = format!(
                    "Suspicious binary: PID {} ({}) - {}",
                    proc.pid, proc.name, reason
                );

                let event = ThreatEvent::new(ThreatType::SuspiciousBinary, "process", &description)
                    .with_severity(ThreatSeverity::High)
                    .with_target(exe_path)
                    .with_detail("pid", proc.pid.to_string())
                    .with_detail("name", &proc.name)
                    .with_detail("exe", exe_path)
                    .with_detail("uid", proc.uid.to_string())
                    .with_detail("cmdline", truncate_string(&cmdline_joined, 500))
                    .with_detail("reason", &reason);

                debug!(
                    pid = proc.pid,
                    name = %proc.name,
                    exe = %exe_path,
                    "Suspicious binary detected"
                );

                threats.push(event);
            }
        }

        threats
    }
}

/// Truncate a string to the given max length, appending "..." if truncated.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a valid UTF-8 char boundary at or before max_len to avoid panic.
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[async_trait]
impl ScanModule for ProcessModule {
    fn name(&self) -> &str {
        "process"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        info!(
            "Running process scan (miner_cpu_threshold={:.1}%)",
            self.config.miner_cpu_threshold
        );

        let my_pid = std::process::id();
        let my_exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()));
        let processes: Vec<ProcInfo> = self
            .enumerate_processes()
            .into_iter()
            .filter(|p| {
                // Skip our own PID.
                if p.pid == my_pid {
                    return false;
                }
                // Skip other instances of the aegis binary (e.g. daemon vs scan).
                if let (Some(ref my), Some(ref proc_exe)) = (&my_exe, &p.exe) {
                    let clean = proc_exe.strip_suffix(" (deleted)").unwrap_or(proc_exe);
                    if clean == my.as_str() {
                        return false;
                    }
                }
                true
            })
            .collect();
        debug!(
            process_count = processes.len(),
            "Enumerated running processes"
        );

        let mut threats = Vec::new();

        // Run all three detectors
        threats.extend(self.detect_crypto_miners(&processes));
        threats.extend(self.detect_reverse_shells(&processes));
        threats.extend(self.detect_suspicious_binaries(&processes));

        info!(count = threats.len(), "Process scan complete");
        Ok(threats)
    }
}
