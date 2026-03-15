use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use ipnet::IpNet;
use tracing::{error, info, warn};

use crate::config::schema::ResponseConfig;
use crate::core::scheduler::Scheduler;
use crate::core::state::{AppState, BlockEntry};
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::util::ip;

// ---------------------------------------------------------------------------
// FirewallBackend trait and implementations
// ---------------------------------------------------------------------------

/// Abstraction over the system firewall for blocking/unblocking IPs.
#[allow(dead_code)]
trait FirewallBackend: Send + Sync {
    /// One-time initialisation (create chains, tables, etc.).
    fn init(&self) -> Result<()>;
    /// Add a DROP rule for the given IP.
    fn block_ip(&self, ip: &IpAddr) -> Result<()>;
    /// Remove the DROP rule for the given IP.
    fn unblock_ip(&self, ip: &IpAddr) -> Result<()>;
}

// -- iptables ---------------------------------------------------------------

struct IptablesBackend;

impl FirewallBackend for IptablesBackend {
    fn init(&self) -> Result<()> {
        // Create the AEGIS_BLOCK chain (ignore error if it already exists).
        let _ = Command::new("iptables")
            .arg("-N")
            .arg("AEGIS_BLOCK")
            .output();

        // Check whether INPUT already jumps to AEGIS_BLOCK.
        let check = Command::new("iptables")
            .arg("-C")
            .arg("INPUT")
            .arg("-j")
            .arg("AEGIS_BLOCK")
            .output()
            .context("Failed to execute iptables -C")?;

        if !check.status.success() {
            // Jump rule does not exist yet -- insert it.
            let insert = Command::new("iptables")
                .arg("-I")
                .arg("INPUT")
                .arg("-j")
                .arg("AEGIS_BLOCK")
                .output()
                .context("Failed to execute iptables -I")?;

            if !insert.status.success() {
                let stderr = String::from_utf8_lossy(&insert.stderr);
                anyhow::bail!("iptables -I INPUT -j AEGIS_BLOCK failed: {}", stderr);
            }
        }

        Ok(())
    }

    fn block_ip(&self, ip: &IpAddr) -> Result<()> {
        // Check if rule already exists (prevents duplicate rules).
        let check = Command::new("iptables")
            .args(["-C", "AEGIS_BLOCK", "-s", &ip.to_string(), "-j", "DROP"])
            .output()
            .context("Failed to check iptables rule")?;
        if check.status.success() {
            return Ok(()); // already blocked
        }

        let output = Command::new("iptables")
            .arg("-A")
            .arg("AEGIS_BLOCK")
            .arg("-s")
            .arg(ip.to_string())
            .arg("-j")
            .arg("DROP")
            .output()
            .context("Failed to execute iptables block command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables block failed for {}: {}", ip, stderr);
        }
        Ok(())
    }

    fn unblock_ip(&self, ip: &IpAddr) -> Result<()> {
        let output = Command::new("iptables")
            .arg("-D")
            .arg("AEGIS_BLOCK")
            .arg("-s")
            .arg(ip.to_string())
            .arg("-j")
            .arg("DROP")
            .output()
            .context("Failed to execute iptables unblock command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables unblock failed for {}: {}", ip, stderr);
        }
        Ok(())
    }
}

// -- nftables ---------------------------------------------------------------

struct NftablesBackend;

impl FirewallBackend for NftablesBackend {
    fn init(&self) -> Result<()> {
        // Ensure the aegis table and input chain exist. Errors ignored if
        // they already exist.
        let _ = Command::new("nft")
            .arg("add")
            .arg("table")
            .arg("inet")
            .arg("aegis")
            .output();

        let _ = Command::new("nft")
            .arg("add")
            .arg("chain")
            .arg("inet")
            .arg("aegis")
            .arg("input")
            .arg("{ type filter hook input priority 0; policy accept; }")
            .output();

        Ok(())
    }

    fn block_ip(&self, ip: &IpAddr) -> Result<()> {
        // Check if a rule for this IP already exists to prevent duplicates.
        let list = Command::new("nft")
            .args(["list", "chain", "inet", "aegis", "input"])
            .output();
        if let Ok(ref out) = list {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ip_str = ip.to_string();
            if stdout
                .lines()
                .any(|line| line.contains(&ip_str) && line.contains("drop"))
            {
                return Ok(()); // already blocked
            }
        }

        let saddr_expr = match ip {
            IpAddr::V4(_) => format!("ip saddr {}", ip),
            IpAddr::V6(_) => format!("ip6 saddr {}", ip),
        };

        let output = Command::new("nft")
            .arg("add")
            .arg("rule")
            .arg("inet")
            .arg("aegis")
            .arg("input")
            .arg(&saddr_expr)
            .arg("drop")
            .output()
            .context("Failed to execute nft block command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft block failed for {}: {}", ip, stderr);
        }
        Ok(())
    }

    fn unblock_ip(&self, ip: &IpAddr) -> Result<()> {
        // nftables doesn't have a simple "delete by match" -- we need to find
        // the handle. For now we use `nft -a list chain` and parse it. This
        // is best-effort; a production system would track handles.
        let list = Command::new("nft")
            .arg("-a")
            .arg("list")
            .arg("chain")
            .arg("inet")
            .arg("aegis")
            .arg("input")
            .output()
            .context("Failed to list nft chain")?;

        let list_str = String::from_utf8_lossy(&list.stdout);
        let ip_str = ip.to_string();

        for line in list_str.lines() {
            if line.contains(&ip_str) && line.contains("drop") {
                // Try to extract handle number: "... # handle <N>"
                if let Some(handle) = line
                    .rsplit("handle ")
                    .next()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                {
                    let del = Command::new("nft")
                        .arg("delete")
                        .arg("rule")
                        .arg("inet")
                        .arg("aegis")
                        .arg("input")
                        .arg("handle")
                        .arg(handle.to_string())
                        .output()
                        .context("Failed to delete nft rule")?;

                    if !del.status.success() {
                        let stderr = String::from_utf8_lossy(&del.stderr);
                        warn!(ip = %ip, "nft delete rule failed: {}", stderr);
                    }
                    return Ok(());
                }
            }
        }

        warn!(ip = %ip, "Could not find nft rule to delete");
        Ok(())
    }
}

// -- ufw --------------------------------------------------------------------

struct UfwBackend;

impl FirewallBackend for UfwBackend {
    fn init(&self) -> Result<()> {
        // ufw manages its own chains; nothing special needed.
        Ok(())
    }

    fn block_ip(&self, ip: &IpAddr) -> Result<()> {
        // Check if a deny rule for this IP already exists to prevent duplicates.
        let status = Command::new("ufw").arg("status").output();
        if let Ok(ref out) = status {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ip_str = ip.to_string();
            if stdout
                .lines()
                .any(|line| line.contains(&ip_str) && line.contains("DENY"))
            {
                return Ok(()); // already blocked
            }
        }

        let output = Command::new("ufw")
            .arg("deny")
            .arg("from")
            .arg(ip.to_string())
            .output()
            .context("Failed to execute ufw deny command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ufw deny failed for {}: {}", ip, stderr);
        }
        Ok(())
    }

    fn unblock_ip(&self, ip: &IpAddr) -> Result<()> {
        let output = Command::new("ufw")
            .arg("delete")
            .arg("deny")
            .arg("from")
            .arg(ip.to_string())
            .output()
            .context("Failed to execute ufw delete command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ufw delete deny failed for {}: {}", ip, stderr);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ResponseAction
// ---------------------------------------------------------------------------

/// Actions the response engine can take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    /// Just log the event.
    Log,
    /// Send an alert (terminal, email, webhook).
    Alert,
    /// Block the source IP via firewall.
    Block,
    /// Kill the offending process.
    Kill,
    /// Block the IP and kill the process.
    BlockAndKill,
    /// Quarantine a file (move or copy to quarantine directory).
    Quarantine,
}

impl std::str::FromStr for ResponseAction {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "log" => Self::Log,
            "alert" => Self::Alert,
            "block" => Self::Block,
            "kill" => Self::Kill,
            "block+kill" | "block_kill" | "blockandkill" => Self::BlockAndKill,
            "quarantine" => Self::Quarantine,
            _ => Self::Log,
        })
    }
}

impl std::fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseAction::Log => write!(f, "log"),
            ResponseAction::Alert => write!(f, "alert"),
            ResponseAction::Block => write!(f, "block"),
            ResponseAction::Kill => write!(f, "kill"),
            ResponseAction::BlockAndKill => write!(f, "block+kill"),
            ResponseAction::Quarantine => write!(f, "quarantine"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResponseEngine
// ---------------------------------------------------------------------------

/// The response engine determines what automated action to take for a given
/// threat event based on the configuration (severity-based defaults and
/// per-threat-type overrides).
pub struct ResponseEngine {
    config: ResponseConfig,
    /// Parsed whitelist CIDRs for fast containment checks.
    whitelist: Vec<IpNet>,
    /// Firewall backend (iptables, nftables, or ufw).
    firewall: Box<dyn FirewallBackend>,
    /// Parsed default block duration.
    block_duration: Duration,
    /// Sliding window of recent block timestamps for rate-limiting.
    recent_blocks: std::sync::Mutex<VecDeque<Instant>>,
    /// Data directory for quarantine storage and other persistent data.
    data_dir: PathBuf,
    /// Optional GeoIP lookup engine.
    geoip: Option<crate::util::geoip::GeoIpLookup>,
}

impl ResponseEngine {
    pub fn new(config: ResponseConfig, data_dir: PathBuf) -> Self {
        // Parse whitelist CIDRs at construction time.
        let whitelist = ip::parse_whitelist(&config.whitelist);

        // Select firewall backend based on configuration.
        let firewall: Box<dyn FirewallBackend> = match config.firewall_backend.as_str() {
            "nftables" => Box::new(NftablesBackend),
            "ufw" => Box::new(UfwBackend),
            _ => Box::new(IptablesBackend), // default to iptables
        };

        // Initialise the firewall backend (best-effort; failure is logged but
        // not fatal so non-root test runs still work).
        if let Err(e) = firewall.init() {
            warn!(error = %e, "Firewall backend initialisation failed (may need root)");
        }

        // Parse default block duration; fall back to 24 hours.
        let block_duration = Scheduler::parse_duration(&config.default_block_duration)
            .unwrap_or_else(|_| {
                warn!(
                    duration = %config.default_block_duration,
                    "Invalid block duration, defaulting to 24h"
                );
                Duration::from_secs(86400)
            });

        // Initialize GeoIP lookup if configured.
        let geoip = if config.geoip.enabled {
            match crate::util::geoip::GeoIpLookup::new(&config.geoip) {
                Ok(lookup) => Some(lookup),
                Err(e) => {
                    warn!(error = %e, "GeoIP initialization failed, GeoIP blocking disabled");
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            whitelist,
            firewall,
            block_duration,
            recent_blocks: std::sync::Mutex::new(VecDeque::new()),
            data_dir,
            geoip,
        }
    }

    /// Determine the appropriate response action for a threat event.
    pub fn determine_action(&self, event: &ThreatEvent) -> ResponseAction {
        if !self.config.enabled {
            return ResponseAction::Log;
        }

        // GeoIP: if an event has a source IP from a blocked country, escalate to Block.
        if let Some(ref geoip) = self.geoip {
            if let Some(source_ip) = event.source_ip {
                if let Some(_country) = geoip.should_block(&source_ip) {
                    return ResponseAction::Block;
                }
            }
        }

        // Check per-threat-type overrides first.
        let threat_key = threat_type_to_config_key(&event.threat_type);
        if let Some(action_str) = self.config.overrides.get(&threat_key) {
            return action_str.parse::<ResponseAction>().unwrap();
        }

        // Fall back to severity-based defaults.
        match event.severity {
            crate::core::threat::ThreatSeverity::Info => ResponseAction::Log,
            crate::core::threat::ThreatSeverity::Low => ResponseAction::Log,
            crate::core::threat::ThreatSeverity::Medium => ResponseAction::Alert,
            crate::core::threat::ThreatSeverity::High => ResponseAction::Block,
            crate::core::threat::ThreatSeverity::Critical => ResponseAction::BlockAndKill,
        }
    }

    /// Execute the automated response for a threat event.
    /// Returns a description of what was done.
    pub async fn respond(&self, event: &ThreatEvent, state: &mut AppState) -> Result<String> {
        let action = self.determine_action(event);

        if self.config.dry_run {
            let msg = format!(
                "[DRY RUN] Would execute: {} for {}",
                action, event.threat_type
            );
            info!("{}", msg);
            return Ok(msg);
        }

        match action {
            ResponseAction::Log => {
                let msg = format!("Logged: {}", event.description);
                Ok(msg)
            }
            ResponseAction::Alert => {
                let msg = format!("Alert raised: {}", event.description);
                info!("{}", msg);
                Ok(msg)
            }
            ResponseAction::Block => {
                if let Some(source_ip) = event.source_ip {
                    self.block_ip(source_ip, &event.description, state)?;
                    Ok(format!("Blocked IP {}", source_ip))
                } else {
                    Ok(format!("Alert (no IP to block): {}", event.description))
                }
            }
            ResponseAction::Kill => {
                let msg = self.kill_process(event)?;
                Ok(msg)
            }
            ResponseAction::BlockAndKill => {
                let mut msg = String::new();
                if let Some(source_ip) = event.source_ip {
                    self.block_ip(source_ip, &event.description, state)?;
                    msg.push_str(&format!("Blocked IP {}; ", source_ip));
                }
                let kill_msg = self.kill_process(event)?;
                msg.push_str(&kill_msg);
                Ok(msg)
            }
            ResponseAction::Quarantine => {
                let msg = self.quarantine_file(event)?;
                Ok(msg)
            }
        }
    }

    /// Block an IP address via the configured firewall backend.
    fn block_ip(&self, ip_addr: IpAddr, reason: &str, state: &mut AppState) -> Result<()> {
        // Validate by round-tripping through IpAddr (already guaranteed by
        // the type system, but we re-parse for defence-in-depth if the IP
        // somehow came from an untrusted string somewhere).
        let validated: IpAddr = ip_addr
            .to_string()
            .parse()
            .context("IP address validation failed")?;

        // Skip if this IP is already blocked (prevents duplicate iptables rules).
        if state.is_ip_blocked(&validated) {
            info!(ip = %validated, "IP already blocked, skipping duplicate");
            return Ok(());
        }

        // Check whitelist.
        if ip::is_whitelisted(&validated, &self.whitelist) {
            info!(ip = %validated, "IP is whitelisted, skipping block");
            return Ok(());
        }

        // Rate limiting: prune entries older than 60 seconds, then check
        // whether we've exceeded the configured maximum.
        {
            let mut recent = self.recent_blocks.lock().unwrap();
            let cutoff = Instant::now() - Duration::from_secs(60);
            while recent.front().is_some_and(|t| *t < cutoff) {
                recent.pop_front();
            }

            if recent.len() as u32 >= self.config.max_blocks_per_minute {
                warn!(
                    ip = %validated,
                    blocks_in_window = recent.len(),
                    max = self.config.max_blocks_per_minute,
                    "Rate limit exceeded, skipping block"
                );
                return Ok(());
            }

            recent.push_back(Instant::now());
        }

        // Execute the firewall block.
        info!(ip = %validated, reason = reason, "Blocking IP address");
        if let Err(e) = self.firewall.block_ip(&validated) {
            error!(ip = %validated, error = %e, "Firewall block failed");
            // Still record in state so the application knows it was attempted.
        }

        // Compute expiry time.
        let expires_at = Some(
            Utc::now()
                + chrono::Duration::from_std(self.block_duration)
                    .unwrap_or_else(|_| chrono::Duration::hours(24)),
        );

        let entry = BlockEntry {
            ip: validated,
            blocked_at: Utc::now(),
            expires_at,
            reason: reason.to_string(),
            auto: true,
        };
        state.block_ip(entry);

        Ok(())
    }

    /// Block an IP address via the configured firewall backend (manual/CLI use).
    pub fn block_ip_firewall(&self, ip: &IpAddr) -> Result<()> {
        let validated: IpAddr = ip
            .to_string()
            .parse()
            .context("IP address validation failed")?;
        info!(ip = %validated, "Blocking IP address via firewall");
        self.firewall.block_ip(&validated)
    }

    /// Remove an IP address from the firewall block list.
    pub fn unblock_ip_firewall(&self, ip: &IpAddr) -> Result<()> {
        let validated: IpAddr = ip
            .to_string()
            .parse()
            .context("IP address validation failed")?;
        info!(ip = %validated, "Unblocking IP address from firewall");
        self.firewall.unblock_ip(&validated)
    }

    /// Quarantine a file associated with a file integrity threat event.
    ///
    /// - **FileAdded**: moves the file into the quarantine directory (genuinely
    ///   protective — malware dropped in /usr/bin is removed from the filesystem).
    /// - **FileModified**: copies the file to quarantine for forensic analysis
    ///   (original left untouched — could be a legitimate package update).
    /// - **FileDeleted**: no-op, the file is already gone.
    ///
    /// A `.meta.json` sidecar is written alongside each quarantined file with
    /// the original path, timestamp, threat type, event details, and action.
    fn quarantine_file(&self, event: &ThreatEvent) -> Result<String> {
        use crate::core::threat::ThreatType;

        let file_path = match &event.target {
            Some(p) => std::path::Path::new(p),
            None => {
                let msg = format!(
                    "Quarantine requested but no target path in event: {}",
                    event.description
                );
                warn!("{}", msg);
                return Ok(msg);
            }
        };

        // FileDeleted — nothing to quarantine.
        if event.threat_type == ThreatType::FileDeleted {
            let msg = format!(
                "File already deleted, nothing to quarantine: {}",
                file_path.display()
            );
            info!("{}", msg);
            return Ok(msg);
        }

        // Race condition guard: file may have vanished since detection.
        if !file_path.exists() {
            let msg = format!(
                "File no longer exists, skipping quarantine: {}",
                file_path.display()
            );
            warn!("{}", msg);
            return Ok(msg);
        }

        // Ensure quarantine directory exists.
        let quarantine_dir = self.data_dir.join("quarantine");
        std::fs::create_dir_all(&quarantine_dir).with_context(|| {
            format!(
                "Failed to create quarantine dir: {}",
                quarantine_dir.display()
            )
        })?;

        // Build a unique quarantine filename: TIMESTAMP_originalname
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let original_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let quarantine_name = format!("{}_{}", timestamp, original_name);
        let quarantine_path = quarantine_dir.join(&quarantine_name);

        let action_taken = match event.threat_type {
            ThreatType::FileAdded => {
                // Move the file: try rename first, fall back to copy+remove
                // for cross-device moves.
                info!(
                    src = %file_path.display(),
                    dst = %quarantine_path.display(),
                    "Moving added file to quarantine"
                );
                if std::fs::rename(file_path, &quarantine_path).is_err() {
                    std::fs::copy(file_path, &quarantine_path).with_context(|| {
                        format!("Failed to copy {} to quarantine", file_path.display())
                    })?;
                    std::fs::remove_file(file_path).with_context(|| {
                        format!("Failed to remove original file {}", file_path.display())
                    })?;
                }
                "moved"
            }
            _ => {
                // FileModified (or any other file integrity type): copy only.
                info!(
                    src = %file_path.display(),
                    dst = %quarantine_path.display(),
                    "Copying modified file to quarantine for analysis"
                );
                std::fs::copy(file_path, &quarantine_path).with_context(|| {
                    format!("Failed to copy {} to quarantine", file_path.display())
                })?;
                "copied"
            }
        };

        // Write metadata sidecar.
        let meta_path = quarantine_dir.join(format!("{}.meta.json", quarantine_name));
        let meta = serde_json::json!({
            "original_path": file_path.to_string_lossy(),
            "quarantine_path": quarantine_path.to_string_lossy(),
            "timestamp": Utc::now().to_rfc3339(),
            "threat_type": format!("{}", event.threat_type),
            "action": action_taken,
            "severity": format!("{}", event.severity),
            "description": event.description,
            "details": event.details,
        });
        if let Err(e) = std::fs::write(
            &meta_path,
            serde_json::to_string_pretty(&meta).unwrap_or_default(),
        ) {
            warn!(error = %e, "Failed to write quarantine metadata");
        }

        let msg = format!(
            "Quarantined ({}) {} → {}",
            action_taken,
            file_path.display(),
            quarantine_path.display()
        );
        info!("{}", msg);
        Ok(msg)
    }

    /// Attempt to kill a process identified by the "pid" key in the threat
    /// event details. Sends SIGTERM first, waits briefly, then SIGKILL.
    fn kill_process(&self, event: &ThreatEvent) -> Result<String> {
        let pid_str = match event.details.get("pid") {
            Some(p) => p,
            None => {
                let msg = format!(
                    "Kill action requested but no PID in event details: {}",
                    event.description
                );
                warn!("{}", msg);
                return Ok(msg);
            }
        };

        let raw_pid: i32 = pid_str
            .parse()
            .with_context(|| format!("Invalid PID value: '{}'", pid_str))?;

        let pid = nix::unistd::Pid::from_raw(raw_pid);

        // Send SIGTERM.
        info!(pid = raw_pid, "Sending SIGTERM to process");
        match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
            Ok(()) => {}
            Err(nix::errno::Errno::ESRCH) => {
                return Ok(format!("Process {} already exited", raw_pid));
            }
            Err(e) => {
                anyhow::bail!("Failed to send SIGTERM to PID {}: {}", raw_pid, e);
            }
        }

        // Wait 2 seconds, then check if process is still alive.
        std::thread::sleep(Duration::from_secs(2));

        // Check if process is still alive by sending signal 0.
        match nix::sys::signal::kill(pid, None) {
            Ok(()) => {
                // Process still alive -- escalate to SIGKILL.
                info!(
                    pid = raw_pid,
                    "Process still alive after SIGTERM, sending SIGKILL"
                );
                match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL) {
                    Ok(()) => Ok(format!("Killed process {} (SIGTERM then SIGKILL)", raw_pid)),
                    Err(nix::errno::Errno::ESRCH) => {
                        Ok(format!("Process {} exited after SIGTERM", raw_pid))
                    }
                    Err(e) => {
                        anyhow::bail!("Failed to send SIGKILL to PID {}: {}", raw_pid, e);
                    }
                }
            }
            Err(nix::errno::Errno::ESRCH) => {
                Ok(format!("Process {} terminated via SIGTERM", raw_pid))
            }
            Err(e) => {
                // Could be EPERM or similar; report but don't fail hard.
                warn!(pid = raw_pid, error = %e, "Could not confirm process status after SIGTERM");
                Ok(format!(
                    "Sent SIGTERM to process {} (status check failed: {})",
                    raw_pid, e
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a ThreatType to the config key used in response.overrides.
fn threat_type_to_config_key(tt: &ThreatType) -> String {
    match tt {
        ThreatType::SynFlood => "syn_flood".into(),
        ThreatType::PortScan => "port_scan".into(),
        ThreatType::SuspiciousConnection => "suspicious_connection".into(),
        ThreatType::C2Beacon => "c2_beacon".into(),
        ThreatType::CryptoMiner => "crypto_miner".into(),
        ThreatType::ReverseShell => "reverse_shell".into(),
        ThreatType::SuspiciousBinary => "suspicious_binary".into(),
        ThreatType::BruteForce => "brute_force".into(),
        ThreatType::RootLogin => "root_login".into(),
        ThreatType::LoginAnomaly => "login_anomaly".into(),
        ThreatType::FileModified => "file_modified".into(),
        ThreatType::FileAdded => "file_added".into(),
        ThreatType::FileDeleted => "file_deleted".into(),
        ThreatType::ScannerProbe => "scanner_probe".into(),
        ThreatType::WebDdos => "web_ddos".into(),
        ThreatType::SqlInjection => "sqli_attempt".into(),
        ThreatType::PathTraversal => "path_traversal".into(),
        ThreatType::ThreatIntelMatch => "threat_intel_match".into(),
        ThreatType::TorExit => "tor_exit".into(),
        ThreatType::UnusualLoginTime => "unusual_login_time".into(),
        ThreatType::CronModified => "cron_modified".into(),
        ThreatType::SudoersModified => "sudoers_modified".into(),
        ThreatType::NewUserCreated => "new_user_created".into(),
        ThreatType::HoneypotConnection => "honeypot_connection".into(),
    }
}
