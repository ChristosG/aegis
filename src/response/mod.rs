use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use ipnet::IpNet;
use tracing::{debug, error, info, warn};

use crate::config::schema::ResponseConfig;
use crate::core::scheduler::Scheduler;
use crate::core::state::{AppState, BlockEntry};
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::util::ip;

pub mod notify;

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
    /// Enumerate all IPs currently blocked by this backend's managed chain.
    /// Used by the drift-detection reconciliation task (v2.6.0 Bucket D) to
    /// diff against `AppState.blocked_ips`.
    ///
    /// Returns an empty Vec on failure (e.g. iptables not available) rather
    /// than an error, so drift detection degrades gracefully on restricted
    /// test environments. Default impl returns empty for backward compat.
    fn list_blocked_ips(&self) -> Result<Vec<IpAddr>> {
        Ok(Vec::new())
    }
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

        // ------------------------------------------------------------------
        // Loopback safeguard (post-2026-04-10 incident).
        //
        // A bug in the detector path caused `-s 127.0.0.1 -j DROP` to be
        // installed in this chain, which cut all loopback traffic and broke
        // systemd, dbus, IPC, and localhost services on Chris's workstation.
        // Fixing the detector bug at the Rust level is necessary but not
        // sufficient — a future refactor could reintroduce the same class
        // of bug. Installing unconditional RETURN rules at the top of the
        // chain means loopback packets can NEVER be dropped here, regardless
        // of what any later DROP rule says. The guards are idempotent
        // (checked with -C first) so startup reruns are safe.
        // ------------------------------------------------------------------
        let loopback_guards: &[&[&str]] = &[
            &["AEGIS_BLOCK", "-i", "lo", "-j", "RETURN"],
            &["AEGIS_BLOCK", "-s", "127.0.0.0/8", "-j", "RETURN"],
            &["AEGIS_BLOCK", "-d", "127.0.0.0/8", "-j", "RETURN"],
        ];
        for guard in loopback_guards {
            let check_guard = Command::new("iptables")
                .arg("-C")
                .args(*guard)
                .output()
                .context("Failed to execute iptables -C for loopback guard")?;
            if !check_guard.status.success() {
                let insert_guard = Command::new("iptables")
                    .arg("-I")
                    .args(*guard)
                    .output()
                    .context("Failed to execute iptables -I for loopback guard")?;
                if !insert_guard.status.success() {
                    let stderr = String::from_utf8_lossy(&insert_guard.stderr);
                    warn!(
                        rule = ?guard,
                        stderr = %stderr,
                        "Failed to install loopback guard rule; continuing"
                    );
                }
            }
        }

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

    fn list_blocked_ips(&self) -> Result<Vec<IpAddr>> {
        // `iptables -S AEGIS_BLOCK` produces one line per rule:
        //   -N AEGIS_BLOCK
        //   -A AEGIS_BLOCK -s 1.2.3.4/32 -j DROP
        //   -A AEGIS_BLOCK -s 2001:db8::/64 -j DROP
        // We only care about -A lines with a -s source clause.
        //
        // NOTE: no `-n` flag here. Modern iptables-nft (e.g. Ubuntu 22.04+,
        // v1.8.10) rejects `-n` with `-S` as "Illegal option", which made
        // this function silently return an empty list for days — the
        // v2.6.0 drift detector thought the firewall was empty when it
        // actually held thousands of rules. `-S` emits numeric addresses
        // natively, so `-n` was never needed.
        let output = match Command::new("iptables")
            .args(["-S", "AEGIS_BLOCK"])
            .output()
        {
            Ok(out) => out,
            Err(e) => {
                // iptables may not be installed, or the chain may not exist
                // yet (first daemon start). Treat as "no rules" rather than error.
                debug!(error = %e, "iptables -S AEGIS_BLOCK failed; returning empty list");
                return Ok(Vec::new());
            }
        };

        if !output.status.success() {
            debug!(
                stderr = %String::from_utf8_lossy(&output.stderr),
                "iptables -S AEGIS_BLOCK returned non-zero; returning empty list"
            );
            return Ok(Vec::new());
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let ips = parse_iptables_list_output(&text);
        Ok(ips)
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

        // Loopback safeguards — same rationale as IptablesBackend::init.
        // `nft insert rule` prepends, so these land at the top of the chain
        // and execute before any DROP rule that might be added later.
        // `inet` family rules cover both IPv4 and IPv6, so `iif "lo"` is
        // enough to protect ::1 alongside 127.0.0.0/8. We still add the
        // explicit address-family rules as belt-and-suspenders.
        let nft_guards: &[&[&str]] = &[
            &[
                "insert", "rule", "inet", "aegis", "input", "iif", "lo", "return",
            ],
            &[
                "insert",
                "rule",
                "inet",
                "aegis",
                "input",
                "ip",
                "saddr",
                "127.0.0.0/8",
                "return",
            ],
            &[
                "insert", "rule", "inet", "aegis", "input", "ip6", "saddr", "::1", "return",
            ],
        ];
        for guard in nft_guards {
            // nft has no -C equivalent; we check for presence by listing
            // the chain and grepping for the rule's distinguishing tokens.
            let list = Command::new("nft")
                .args(["list", "chain", "inet", "aegis", "input"])
                .output();
            let already_present = list
                .ok()
                .map(|out| {
                    let s = String::from_utf8_lossy(&out.stdout).into_owned();
                    // Match by the tail of the guard args (the rule body), e.g.
                    // `iif "lo" return`, `ip saddr 127.0.0.0/8 return`.
                    let tail: Vec<&str> = guard.iter().skip(5).copied().collect();
                    tail.iter().all(|t| s.contains(t))
                        && s.contains("return")
                        && (s.contains("iif") || s.contains("saddr"))
                })
                .unwrap_or(false);
            if !already_present {
                let out = Command::new("nft").args(*guard).output();
                if let Ok(out) = out {
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        warn!(
                            rule = ?guard,
                            stderr = %stderr,
                            "Failed to install nft loopback guard; continuing"
                        );
                    }
                }
            }
        }

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

    fn list_blocked_ips(&self) -> Result<Vec<IpAddr>> {
        // `nft list chain inet aegis input` produces lines like:
        //   ip saddr 1.2.3.4 drop
        //   ip6 saddr 2001:db8::1 drop
        let output = match Command::new("nft")
            .args(["list", "chain", "inet", "aegis", "input"])
            .output()
        {
            Ok(out) => out,
            Err(e) => {
                debug!(error = %e, "nft list chain failed; returning empty list");
                return Ok(Vec::new());
            }
        };

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let ips = parse_nft_list_output(&text);
        Ok(ips)
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

    fn list_blocked_ips(&self) -> Result<Vec<IpAddr>> {
        // `ufw status` produces lines like:
        //   Anywhere                   DENY IN     1.2.3.4
        //   Anywhere (v6)              DENY IN     2001:db8::1
        let output = match Command::new("ufw").arg("status").output() {
            Ok(out) => out,
            Err(e) => {
                debug!(error = %e, "ufw status failed; returning empty list");
                return Ok(Vec::new());
            }
        };
        if !output.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let ips = parse_ufw_status_output(&text);
        Ok(ips)
    }
}

// -- firewall list parsers (v2.6.0 Bucket D) --------------------------------
//
// Pulled out as free functions so we can unit-test them without spawning
// subprocesses. Each parser is tolerant of format variations — unparseable
// lines are silently skipped, which is safer than failing on unexpected
// output and losing all drift visibility.

/// Parse `iptables -S AEGIS_BLOCK -n` output into a list of IPs.
/// Ignores the `-N` chain-create line and any malformed entries.
fn parse_iptables_list_output(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("-A AEGIS_BLOCK") {
            continue;
        }
        // Find the `-s <addr>/<mask>` token.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for i in 0..tokens.len() {
            if tokens[i] == "-s" {
                if let Some(addr) = tokens.get(i + 1) {
                    // Strip /32 or /128 if present
                    let ip_str = addr.split('/').next().unwrap_or(addr);
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
                break;
            }
        }
    }
    out
}

/// Parse `nft list chain inet aegis input` output into a list of IPs.
fn parse_nft_list_output(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Look for `ip saddr <addr>` or `ip6 saddr <addr>` followed by `drop`
        if !line.contains("saddr") || !line.contains("drop") {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for i in 0..tokens.len() {
            if tokens[i] == "saddr" {
                if let Some(addr) = tokens.get(i + 1) {
                    let ip_str = addr.split('/').next().unwrap_or(addr);
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
                break;
            }
        }
    }
    out
}

/// Parse `ufw status` output into a list of denied IPs.
fn parse_ufw_status_output(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("DENY") {
            continue;
        }
        // The last whitespace-separated token is usually the source IP.
        if let Some(last) = line.split_whitespace().last() {
            if let Ok(ip) = last.parse::<IpAddr>() {
                out.push(ip);
            }
        }
    }
    out
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
// BlockOutcome
// ---------------------------------------------------------------------------

/// Outcome of an attempted `block_ip()` call. The caller uses this to build
/// an accurate human-readable response message and to decide whether the
/// threat event was "handled" for purposes of the auto_responded flag.
///
/// Introduced in v2.6.0 Bucket A so we can distinguish "actually blocked"
/// from "would-have-blocked-but-skipped-for-X-reason" in the threat log,
/// fixing the ambiguity where `respond()` used to return
/// `"Blocked IP X"` even when the IP was whitelisted or rate-limited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Firewall rule installed and block entry added to state.
    Blocked,
    /// IP was already in state.blocked_ips; no-op.
    AlreadyBlocked,
    /// IP matched `response.whitelist` (user-curated allow list); skipped.
    Whitelisted,
    /// IP matched `response.well_known_destinations` (v2.6.0 safety pin).
    /// The string contains a short human-readable reason, e.g.
    /// `"Cloudflare CDN range"`.
    SafetyPinInfrastructure(String),
    /// Rate limit `max_blocks_per_minute` was hit; skipped.
    RateLimited,
    /// Zero-tolerance policy kicked in — this block is permanent
    /// (`expires_at = None`) regardless of strike count.
    /// Contains the threat type key that triggered it.
    BlockedPermanentZeroTolerance(String),
}

impl BlockOutcome {
    /// Whether this outcome represents a successfully-installed firewall rule.
    /// Used by callers to set `auto_responded = true` on the threat event.
    pub fn did_install_rule(&self) -> bool {
        matches!(
            self,
            BlockOutcome::Blocked | BlockOutcome::BlockedPermanentZeroTolerance(_)
        )
    }

    /// A short human-readable description of the outcome, for logs and
    /// the threat event's `response_outcome` detail field.
    pub fn describe(&self, ip: IpAddr) -> String {
        match self {
            BlockOutcome::Blocked => format!("Blocked IP {}", ip),
            BlockOutcome::AlreadyBlocked => format!("IP {} was already blocked", ip),
            BlockOutcome::Whitelisted => {
                format!("IP {} is whitelisted, block skipped", ip)
            }
            BlockOutcome::SafetyPinInfrastructure(reason) => {
                format!(
                    "Safety pin: IP {} is in well_known_destinations ({}), block skipped",
                    ip, reason
                )
            }
            BlockOutcome::RateLimited => {
                format!("Rate limit exceeded, block of {} deferred", ip)
            }
            BlockOutcome::BlockedPermanentZeroTolerance(threat_key) => {
                format!(
                    "Blocked IP {} PERMANENTLY (zero-tolerance threat: {})",
                    ip, threat_key
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReconcileReport (v2.6.0 Bucket D)
// ---------------------------------------------------------------------------

/// Report from `ResponseEngine::reconcile_firewall_state()`. Contains a diff
/// between the persisted block list (`AppState.blocked_ips`) and the live
/// kernel firewall state (enumerated via `FirewallBackend::list_blocked_ips`).
///
/// Used by the daemon housekeeping loop to surface drift, and optionally
/// to auto-repair. See docs/specs/2026-04-05-aegis-v2-design.md §5.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconcileReport {
    /// How many entries are in `block_list.json` (the persisted state).
    pub persisted_count: usize,
    /// How many DROP rules are in the live firewall chain.
    pub firewall_count: usize,
    /// IPs that are persisted but NOT in the firewall chain — will be
    /// re-added if auto_reconcile_firewall is enabled. Typical causes:
    /// daemon restart, `apt remove aegis` followed by reinstall, manual
    /// `iptables -F AEGIS_BLOCK`.
    pub missing_from_firewall: Vec<IpAddr>,
    /// IPs that are in the firewall chain but NOT persisted — will be
    /// removed if auto_reconcile is enabled. Typical causes: stale rules
    /// from an older Aegis version, manual `iptables -A AEGIS_BLOCK` by
    /// the admin, or bugs in older Aegis that added rules without
    /// persisting the block entry.
    pub orphaned_in_firewall: Vec<IpAddr>,
    /// Whether this reconciliation actually applied firewall changes.
    /// False in warn-only mode (auto_reconcile_firewall = false) or when
    /// drift exceeds the safety threshold.
    pub auto_reconciled: bool,
}

impl ReconcileReport {
    /// Total drift: missing + orphaned.
    pub fn total_drift(&self) -> usize {
        self.missing_from_firewall.len() + self.orphaned_in_firewall.len()
    }

    /// Whether the persisted state and firewall state are fully in sync.
    pub fn is_in_sync(&self) -> bool {
        self.total_drift() == 0
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
    /// Parsed well_known_destinations CIDRs (v2.6.0 safety pin). Unlike
    /// `whitelist`, these are "don't auto-block infrastructure" ranges
    /// shipped by the project and updated on each release. See
    /// docs/specs/2026-04-05-aegis-v2-design.md §2 for rationale.
    well_known_destinations: Vec<IpNet>,
    /// Set of threat type config keys that should trigger first-offense
    /// permanent ban (v2.6.0 Bucket B). HashSet for O(1) lookup.
    zero_tolerance_threats: HashSet<String>,
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
        Self::new_with_extra_safety_pin(config, data_dir, &[])
    }

    /// v2.6.1: like `new`, but the caller supplies additional CIDR strings
    /// to merge into the safety-pin list (typically
    /// `[network] excluded_destinations`). The merged list is treated
    /// uniformly: any block attempt against an IP in the merged list returns
    /// `BlockOutcome::SafetyPinInfrastructure` and never installs a firewall
    /// rule. Reusing the safety-pin mechanism rather than introducing a
    /// parallel "loopback skip" path means there is exactly one place in
    /// `block_ip()` that can let a never-block CIDR through.
    pub fn new_with_extra_safety_pin(
        config: ResponseConfig,
        data_dir: PathBuf,
        extra_safety_pin_cidrs: &[String],
    ) -> Self {
        // Parse whitelist CIDRs at construction time.
        let whitelist = ip::parse_whitelist(&config.whitelist);

        // Parse well_known_destinations CIDRs (v2.6.0 safety pin). Reuses the
        // same parser as whitelist — invalid entries are logged and skipped,
        // never fail the startup. See docs/specs/2026-04-05-aegis-v2-design.md §2.
        let mut well_known_destinations = ip::parse_whitelist(&config.well_known_destinations);
        let extra = ip::parse_whitelist(extra_safety_pin_cidrs);
        if !extra.is_empty() {
            info!(
                count = extra.len(),
                "Merging [network] excluded_destinations into safety pin (loopback/link-local)"
            );
            well_known_destinations.extend(extra);
        }
        info!(
            count = well_known_destinations.len(),
            "Loaded well_known_destinations safety pin CIDR list"
        );

        // Build the zero-tolerance threat type set (v2.6.0 Bucket B).
        let zero_tolerance_threats: HashSet<String> =
            config.zero_tolerance_threats.iter().cloned().collect();
        if !zero_tolerance_threats.is_empty() {
            info!(
                types = ?zero_tolerance_threats,
                "Zero-tolerance threat types enabled (first offense = permanent ban)"
            );
        }

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
            well_known_destinations,
            zero_tolerance_threats,
            firewall,
            block_duration,
            recent_blocks: std::sync::Mutex::new(VecDeque::new()),
            data_dir,
            geoip,
        }
    }

    /// Accessor for the safety pin CIDR list (for tests and the drift
    /// detection task).
    pub fn well_known_destinations(&self) -> &[IpNet] {
        &self.well_known_destinations
    }

    /// Check whether an IP falls in any of the project-shipped "don't
    /// auto-block" CIDR ranges. This is the v2.6.0 Bucket A safety pin.
    ///
    /// Separate from `ip::is_whitelisted` because the semantics differ:
    /// - `whitelist` = "never block this IP, user decision, full bypass"
    /// - `well_known_destinations` = "don't auto-block this, but still log
    ///   the detection so admin has visibility. User can still manually
    ///   `aegis block` this IP if they want."
    pub fn is_well_known_destination(&self, ip: &IpAddr) -> bool {
        ip::is_whitelisted(ip, &self.well_known_destinations)
    }

    /// Best-effort human-readable description of why an IP is in the safety
    /// pin list. Used to build the BlockOutcome::SafetyPinInfrastructure
    /// variant. Only used in logging/display paths — if we can't match a
    /// specific provider, we return "well-known infrastructure CIDR".
    fn describe_well_known_destination(&self, ip: &IpAddr) -> String {
        // Small lookup table mapping well-known CIDR prefixes to provider
        // names. Not exhaustive; when the IP matches a CIDR not in this
        // table we fall back to a generic label. Extended lookup via whois
        // is in Bucket C's ASN module.
        const KNOWN_PROVIDERS: &[(&str, &str)] = &[
            // v2.6.1: loopback + link-local labels for the
            // [network] excluded_destinations defaults. Helps operators
            // distinguish "Aegis refused to block 127.0.0.1" from a
            // legitimate CDN safety-pin trip in the threat log.
            ("127.0.0.0/8", "loopback (IPv4)"),
            ("::1/128", "loopback (IPv6)"),
            ("169.254.0.0/16", "link-local (IPv4)"),
            ("fe80::/10", "link-local (IPv6)"),
            ("160.79.104.0/21", "Anthropic API"),
            ("104.16.0.0/13", "Cloudflare"),
            ("104.24.0.0/14", "Cloudflare"),
            ("172.64.0.0/13", "Cloudflare"),
            ("162.158.0.0/15", "Cloudflare"),
            ("198.41.128.0/17", "Cloudflare"),
            ("140.82.112.0/20", "GitHub"),
            ("185.199.108.0/22", "GitHub Pages"),
            ("192.30.252.0/22", "GitHub"),
            ("13.224.0.0/14", "AWS CloudFront"),
            ("13.32.0.0/15", "AWS CloudFront"),
            ("13.35.0.0/16", "AWS CloudFront"),
            ("52.84.0.0/15", "AWS CloudFront"),
            ("54.192.0.0/16", "AWS CloudFront"),
            ("54.230.0.0/16", "AWS CloudFront"),
            ("99.84.0.0/16", "AWS CloudFront"),
            ("108.138.0.0/15", "AWS CloudFront"),
            ("108.156.0.0/14", "AWS CloudFront"),
            ("143.204.0.0/16", "AWS CloudFront"),
            ("66.102.0.0/20", "Google"),
            ("66.249.64.0/19", "Googlebot"),
            ("74.125.0.0/16", "Google"),
            ("142.250.0.0/15", "Google"),
            ("216.58.192.0/19", "Google"),
            ("172.217.0.0/16", "Google"),
            ("8.8.8.0/24", "Google DNS"),
            ("8.8.4.0/24", "Google DNS"),
            ("151.101.0.0/16", "Fastly CDN"),
            ("199.232.0.0/16", "Fastly CDN"),
            ("146.75.0.0/17", "Fastly CDN"),
            ("23.235.32.0/20", "Fastly CDN"),
        ];
        for (cidr_str, name) in KNOWN_PROVIDERS {
            if let Ok(cidr) = cidr_str.parse::<IpNet>() {
                if cidr.contains(ip) {
                    return (*name).to_string();
                }
            }
        }
        "well-known infrastructure CIDR".to_string()
    }

    /// Whether a given threat type config key is in the zero-tolerance list
    /// (v2.6.0 Bucket B). Used by block_ip() to decide whether to short-circuit
    /// the strike counter and jump straight to permanent ban.
    pub fn is_zero_tolerance(&self, threat_type_key: &str) -> bool {
        self.zero_tolerance_threats.contains(threat_type_key)
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

        // v2.6.2: a reverse-shell match emitted by the process module under
        // a known interactive dev-tool parent has been demoted to Medium and
        // tagged with `degraded_by_dev_parent`. Honor that hint by routing
        // through severity-based defaults instead of the per-threat-type
        // override (which is "kill" for reverse_shell). Without this short-
        // circuit a `[response.overrides] reverse_shell = "kill"` would still
        // kill the developer's process — defeating the demotion.
        // See incident 20260509004453373-1434.
        if event.details.get("degraded_by_dev_parent").map(String::as_str) == Some("true") {
            return match event.severity {
                crate::core::threat::ThreatSeverity::Info
                | crate::core::threat::ThreatSeverity::Low => ResponseAction::Log,
                crate::core::threat::ThreatSeverity::Medium => ResponseAction::Alert,
                crate::core::threat::ThreatSeverity::High => ResponseAction::Block,
                crate::core::threat::ThreatSeverity::Critical => ResponseAction::BlockAndKill,
            };
        }

        // Check per-threat-type overrides first.
        let threat_key = threat_type_to_config_key(&event.threat_type);
        if let Some(action_str) = self.config.overrides.get(&threat_key) {
            return action_str
                .parse::<ResponseAction>()
                .unwrap_or(ResponseAction::Log);
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
    ///
    /// v2.6.0: threads the threat type key through to `block_ip()` so the
    /// zero-tolerance policy (Bucket B) can check it, and uses the new
    /// `BlockOutcome` return type to build honest response messages.
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

        // v2.6.2: best-effort desktop notification on destructive actions.
        // Fires before the action so the user sees it immediately even if
        // the kill/block fails. notify_action_taken() filters internally to
        // Kill/Block/BlockAndKill — for Log/Alert/Quarantine this is a no-op.
        if self.config.desktop_notifications {
            // Best-effort: never let a notification problem propagate.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                notify::notify_action_taken(event, &action);
            }))
            .ok();
        }

        // Config key for the current threat type (used for zero-tolerance check).
        let threat_key = threat_type_to_config_key(&event.threat_type);

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
                    let outcome =
                        self.block_ip(source_ip, &event.description, Some(&threat_key), state)?;
                    Ok(outcome.describe(source_ip))
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
                    let outcome =
                        self.block_ip(source_ip, &event.description, Some(&threat_key), state)?;
                    msg.push_str(&outcome.describe(source_ip));
                    msg.push_str("; ");
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
    ///
    /// ## v2.6.0 changes
    ///
    /// - **New parameter** `threat_type_key`: the config key (e.g. `"path_traversal"`,
    ///   `"brute_force"`) of the detection that triggered this block. Used to
    ///   check against `response.zero_tolerance_threats` (Bucket B). Can be
    ///   `None` for manual/CLI blocks where zero-tolerance doesn't apply.
    /// - **New return type** `Result<BlockOutcome, anyhow::Error>`: lets callers
    ///   tell "actually blocked" apart from "skipped because whitelisted /
    ///   rate-limited / safety-pinned". Old behavior of "return Ok(()) on any
    ///   non-fatal skip" made the response log dishonest.
    ///
    /// ## Order of checks (matters for correctness)
    ///
    /// 1. Already blocked? → `AlreadyBlocked` (idempotent)
    /// 2. In user whitelist? → `Whitelisted` (user decision wins)
    /// 3. In well_known_destinations? → `SafetyPinInfrastructure` (Bucket A)
    /// 4. Rate limit? → `RateLimited`
    /// 5. Firewall call (may fail)
    /// 6. Zero-tolerance or strike-based escalation → `Blocked` or
    ///    `BlockedPermanentZeroTolerance` (Bucket B)
    ///
    /// Whitelist wins over safety pin so a user who has explicitly whitelisted
    /// an IP sees consistent behavior. Safety pin wins over rate limit so
    /// infrastructure hits don't consume the rate-limit budget.
    fn block_ip(
        &self,
        ip_addr: IpAddr,
        reason: &str,
        threat_type_key: Option<&str>,
        state: &mut AppState,
    ) -> Result<BlockOutcome> {
        // Validate by round-tripping through IpAddr (already guaranteed by
        // the type system, but we re-parse for defence-in-depth if the IP
        // somehow came from an untrusted string somewhere).
        let validated: IpAddr = ip_addr
            .to_string()
            .parse()
            .context("IP address validation failed")?;

        // (1) Skip if this IP is already blocked (prevents duplicate iptables rules).
        if state.is_ip_blocked(&validated) {
            info!(ip = %validated, "IP already blocked, skipping duplicate");
            return Ok(BlockOutcome::AlreadyBlocked);
        }

        // (2) Check user-curated whitelist. Highest priority — user decision wins.
        if ip::is_whitelisted(&validated, &self.whitelist) {
            info!(ip = %validated, "IP is whitelisted, skipping block");
            return Ok(BlockOutcome::Whitelisted);
        }

        // (3) v2.6.0 Bucket A safety pin — check well-known infrastructure list.
        // If an IP is in a shipped CDN/cloud/code-host CIDR, we refuse to
        // auto-block it. This prevents the class of bug documented in
        // docs/TRIAGE_PHASE_A0.md where Aegis firewalls legitimate
        // CloudFront/GitHub/Anthropic endpoints based on noisy threat intel.
        //
        // The detection itself still gets recorded in threats.jsonl (the
        // caller emits the ThreatEvent before calling us). We just refuse
        // to install the firewall rule.
        if self.is_well_known_destination(&validated) {
            let provider = self.describe_well_known_destination(&validated);
            warn!(
                ip = %validated,
                provider = %provider,
                reason = reason,
                "SAFETY PIN ACTIVATED: refusing to auto-block well-known infrastructure IP"
            );
            return Ok(BlockOutcome::SafetyPinInfrastructure(provider));
        }

        // (4) Rate limiting: prune entries older than 60 seconds, then check
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
                return Ok(BlockOutcome::RateLimited);
            }

            recent.push_back(Instant::now());
        }

        // (5) Execute the firewall block.
        info!(ip = %validated, reason = reason, "Blocking IP address");
        if let Err(e) = self.firewall.block_ip(&validated) {
            error!(ip = %validated, error = %e, "Firewall block failed — IP NOT added to block list");
            return Err(e);
        }

        // (6) Determine expires_at: zero-tolerance, strike escalation, or default.
        //
        // Zero-tolerance (Bucket B) short-circuits the normal logic: if the
        // threat type is in the user's zero_tolerance_threats list, we
        // immediately promote to permanent ban and mark the IP as escalated.
        //
        // Otherwise, the existing repeat-offender strike counter decides.
        let is_zero_tol = threat_type_key
            .map(|k| self.is_zero_tolerance(k))
            .unwrap_or(false);

        let expires_at = if is_zero_tol {
            // Zero-tolerance path: permanent ban on first offense.
            let window = Scheduler::parse_duration(&self.config.repeat_offender_window)
                .map(|d| chrono::Duration::from_std(d).unwrap_or(chrono::Duration::days(30)))
                .unwrap_or(chrono::Duration::days(30));
            // Record a strike so the history is complete, then immediately
            // escalate (bypassing the threshold check).
            let _strike_count = state.record_strike(validated, reason, window);
            if !state.is_escalated(&validated) {
                state.mark_escalated(&validated);
            }
            warn!(
                ip = %validated,
                threat_type = ?threat_type_key,
                "ZERO-TOLERANCE: permanent ban on first offense"
            );
            None
        } else {
            let threshold = self.config.repeat_offender_threshold;
            if threshold > 0 {
                let window = Scheduler::parse_duration(&self.config.repeat_offender_window)
                    .map(|d| chrono::Duration::from_std(d).unwrap_or(chrono::Duration::days(30)))
                    .unwrap_or(chrono::Duration::days(30));

                let strike_count = state.record_strike(validated, reason, window);

                if state.is_escalated(&validated) || strike_count >= threshold as usize {
                    if !state.is_escalated(&validated) {
                        state.mark_escalated(&validated);
                    }
                    info!(
                        ip = %validated,
                        strikes = strike_count,
                        threshold = threshold,
                        "Repeat offender escalated to permanent ban"
                    );
                    None // permanent
                } else {
                    Some(
                        Utc::now()
                            + chrono::Duration::from_std(self.block_duration)
                                .unwrap_or_else(|_| chrono::Duration::hours(24)),
                    )
                }
            } else {
                // Escalation disabled — use default duration.
                Some(
                    Utc::now()
                        + chrono::Duration::from_std(self.block_duration)
                            .unwrap_or_else(|_| chrono::Duration::hours(24)),
                )
            }
        };

        let entry = BlockEntry {
            ip: validated,
            blocked_at: Utc::now(),
            expires_at,
            reason: reason.to_string(),
            auto: true,
        };
        state.block_ip(entry);

        // Distinguish permanent zero-tolerance from normal block in the outcome
        // so callers and audit logs can tell them apart.
        if is_zero_tol {
            Ok(BlockOutcome::BlockedPermanentZeroTolerance(
                threat_type_key.unwrap_or("").to_string(),
            ))
        } else {
            Ok(BlockOutcome::Blocked)
        }
    }

    /// v2.6.0 Bucket D: compare the persisted block list against the live
    /// firewall chain and return a report of discrepancies. Optionally
    /// repairs drift if `config.auto_reconcile_firewall` is true.
    ///
    /// # Handling the large historical drift
    ///
    /// When this is first called on Chris's box, the report will contain a
    /// huge number of orphaned firewall rules (~500+ iptables rules that
    /// are NOT in block_list.json, mostly historical threat-intel-match
    /// blocks that were never cleaned up). The first-run behavior must not
    /// auto-reconcile that mess — it might silently remove manual admin
    /// decisions. So: the report is produced, but auto-repair only fires
    /// AFTER the operator has explicitly enabled `auto_reconcile_firewall`
    /// in config AND we've verified the drift is "small" (less than
    /// INITIAL_DRIFT_THRESHOLD entries out of sync). For larger drift,
    /// we log a warning and refuse to auto-repair even when enabled,
    /// pointing the operator at `aegis reconcile --first-run` (future CLI).
    pub fn reconcile_firewall_state(&self, state: &mut AppState) -> ReconcileReport {
        use std::collections::HashSet;

        const INITIAL_DRIFT_THRESHOLD: usize = 100;

        let persisted: HashSet<IpAddr> = state.blocked_ips.keys().copied().collect();
        let firewall: HashSet<IpAddr> = match self.firewall.list_blocked_ips() {
            Ok(ips) => ips.into_iter().collect(),
            Err(e) => {
                warn!(error = %e, "Firewall list_blocked_ips failed during reconciliation");
                HashSet::new()
            }
        };

        let missing_from_firewall: Vec<IpAddr> = persisted.difference(&firewall).copied().collect();
        let orphaned_in_firewall: Vec<IpAddr> = firewall.difference(&persisted).copied().collect();

        let total_drift = missing_from_firewall.len() + orphaned_in_firewall.len();

        info!(
            persisted = persisted.len(),
            firewall = firewall.len(),
            missing = missing_from_firewall.len(),
            orphaned = orphaned_in_firewall.len(),
            "Firewall drift reconciliation"
        );

        let mut auto_reconciled = false;
        if self.config.auto_reconcile_firewall {
            if total_drift > INITIAL_DRIFT_THRESHOLD {
                warn!(
                    total_drift = total_drift,
                    threshold = INITIAL_DRIFT_THRESHOLD,
                    "Drift exceeds safety threshold; skipping auto-reconciliation. \
                     Run `aegis reconcile --first-run` to clean up, or raise the \
                     threshold if this box legitimately has many rules."
                );
            } else {
                // Re-add missing rules. If a "missing" IP is actually
                // whitelisted, that means persisted state is corrupted
                // (e.g. from a pre-fix version that banned loopback). Don't
                // blindly re-install the rule — purge the bad entry so
                // state self-heals, and loudly warn the operator.
                for ip in &missing_from_firewall {
                    let canonical = ip::canonicalize(*ip);
                    if ip::is_whitelisted(&canonical, &self.whitelist) {
                        warn!(
                            ip = %ip,
                            canonical = %canonical,
                            "Reconcile: refusing to restore whitelisted IP; purging from state"
                        );
                        state.blocked_ips.remove(ip);
                        state.blocked_ips.remove(&canonical);
                        continue;
                    }
                    if let Err(e) = self.firewall.block_ip(ip) {
                        warn!(ip = %ip, error = %e, "Reconcile: failed to re-add missing firewall rule");
                    } else {
                        info!(ip = %ip, "Reconcile: re-added missing firewall rule");
                    }
                }
                // Remove orphaned rules.
                for ip in &orphaned_in_firewall {
                    if let Err(e) = self.firewall.unblock_ip(ip) {
                        warn!(ip = %ip, error = %e, "Reconcile: failed to remove orphaned firewall rule");
                    } else {
                        info!(ip = %ip, "Reconcile: removed orphaned firewall rule");
                    }
                }
                auto_reconciled = true;
            }
        }

        ReconcileReport {
            persisted_count: persisted.len(),
            firewall_count: firewall.len(),
            missing_from_firewall,
            orphaned_in_firewall,
            auto_reconciled,
        }
    }

    /// Block an IP address via the configured firewall backend (manual/CLI use).
    ///
    /// Applies the user whitelist and loopback/RFC1918 sanity checks before
    /// touching the firewall backend. This is the code path used by
    /// `aegis block <ip>` and by the daemon startup restoration loop in
    /// `Engine::new` — both legitimately *ask* for a raw firewall block
    /// without going through the full detector pipeline, but neither should
    /// be allowed to cut loopback or RFC1918 traffic. The 2026-04-10
    /// incident happened in a related path; this guard keeps CLI and
    /// restoration honest even if persisted state has been corrupted.
    pub fn block_ip_firewall(&self, ip: &IpAddr) -> Result<()> {
        let validated: IpAddr = ip
            .to_string()
            .parse()
            .context("IP address validation failed")?;
        // Canonicalize IPv4-mapped IPv6 so the whitelist check can catch
        // `::ffff:127.0.0.1` and friends even if an older block_list.json
        // persisted entries in the mapped form.
        let validated = ip::canonicalize(validated);
        if ip::is_whitelisted(&validated, &self.whitelist) {
            warn!(
                ip = %validated,
                "Refusing manual firewall block: IP is in the user whitelist"
            );
            anyhow::bail!(
                "IP {} is in the user whitelist and cannot be blocked via the firewall backend",
                validated
            );
        }
        info!(ip = %validated, "Blocking IP address via firewall");
        self.firewall.block_ip(&validated)
    }

    /// Public helper so other modules (e.g. `Engine::new` during startup
    /// restoration) can consult the same whitelist the response engine uses,
    /// without having to re-parse the CIDR list.
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        ip::is_whitelisted(ip, &self.whitelist)
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
        ThreatType::ConnectionRateExceeded => "connection_rate_exceeded".into(),
        ThreatType::CertExpiringSoon => "cert_expiring_soon".into(),
        ThreatType::KernelModuleLoaded => "kernel_module_loaded".into(),
        ThreatType::NewOutboundDestination => "new_outbound_destination".into(),
        ThreatType::DgaDomain => "dga_domain".into(),
        ThreatType::DnsTunneling => "dns_tunneling".into(),
        ThreatType::ContainerEscape => "container_escape".into(),
        ThreatType::TlsBadFingerprint => "tls_bad_fingerprint".into(),
        ThreatType::YaraMatch => "yara_match".into(),
        ThreatType::RootkitDetected => "rootkit_detected".into(),
        ThreatType::HiddenProcess => "hidden_process".into(),
        ThreatType::LdPreloadHook => "ld_preload_hook".into(),
        ThreatType::SuspiciousCommand => "suspicious_command".into(),
        ThreatType::CisBenchmarkFail => "cis_benchmark_fail".into(),
        ThreatType::ForensicSnapshot => "forensic_snapshot".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests (v2.6.0 Bucket A + B)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::AegisConfig;
    use crate::core::state::AppState;
    use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// No-op firewall backend for tests. All operations succeed without
    /// touching iptables/nftables/ufw. Lets us unit-test block_ip() and
    /// respond() without needing root or real kernel firewall state.
    struct NoOpBackend;

    impl FirewallBackend for NoOpBackend {
        fn init(&self) -> Result<()> {
            Ok(())
        }
        fn block_ip(&self, _ip: &IpAddr) -> Result<()> {
            Ok(())
        }
        fn unblock_ip(&self, _ip: &IpAddr) -> Result<()> {
            Ok(())
        }
    }

    impl ResponseEngine {
        /// Test-only constructor. Bypasses the normal firewall-backend
        /// selection (which would need root for iptables) and injects a
        /// NoOpBackend instead.
        fn for_test(config: ResponseConfig) -> Self {
            Self::for_test_with_extra_safety_pin(config, &[])
        }

        fn for_test_with_extra_safety_pin(
            config: ResponseConfig,
            extra: &[String],
        ) -> Self {
            let whitelist = ip::parse_whitelist(&config.whitelist);
            let mut well_known_destinations =
                ip::parse_whitelist(&config.well_known_destinations);
            well_known_destinations.extend(ip::parse_whitelist(extra));
            let zero_tolerance_threats: HashSet<String> =
                config.zero_tolerance_threats.iter().cloned().collect();
            let firewall: Box<dyn FirewallBackend> = Box::new(NoOpBackend);
            let block_duration = Scheduler::parse_duration(&config.default_block_duration)
                .unwrap_or(Duration::from_secs(86400));
            Self {
                config,
                whitelist,
                well_known_destinations,
                zero_tolerance_threats,
                firewall,
                block_duration,
                recent_blocks: std::sync::Mutex::new(VecDeque::new()),
                data_dir: std::path::PathBuf::from("/tmp/aegis-test"),
                geoip: None,
            }
        }
    }

    fn default_state() -> AppState {
        AppState::with_config(AegisConfig::default())
    }

    // -----------------------------------------------------------------------
    // BlockOutcome unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_outcome_did_install_rule() {
        assert!(BlockOutcome::Blocked.did_install_rule());
        assert!(BlockOutcome::BlockedPermanentZeroTolerance("x".into()).did_install_rule());
        assert!(!BlockOutcome::AlreadyBlocked.did_install_rule());
        assert!(!BlockOutcome::Whitelisted.did_install_rule());
        assert!(!BlockOutcome::SafetyPinInfrastructure("x".into()).did_install_rule());
        assert!(!BlockOutcome::RateLimited.did_install_rule());
    }

    #[test]
    fn test_block_outcome_describe_messages_are_distinct() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let blocked = BlockOutcome::Blocked.describe(ip);
        let pinned = BlockOutcome::SafetyPinInfrastructure("Cloudflare".into()).describe(ip);
        let whitelisted = BlockOutcome::Whitelisted.describe(ip);
        let zero_tol =
            BlockOutcome::BlockedPermanentZeroTolerance("path_traversal".into()).describe(ip);

        // Each outcome produces a distinct message so operators can tell
        // them apart in the threat log.
        assert!(blocked.contains("Blocked IP 1.2.3.4"));
        assert!(pinned.contains("Safety pin") && pinned.contains("Cloudflare"));
        assert!(whitelisted.contains("whitelisted"));
        assert!(zero_tol.contains("PERMANENTLY") && zero_tol.contains("path_traversal"));
        assert_ne!(blocked, pinned);
        assert_ne!(blocked, zero_tol);
    }

    // -----------------------------------------------------------------------
    // Bucket A: safety pin tests (well_known_destinations)
    // -----------------------------------------------------------------------

    #[test]
    fn test_safety_pin_blocks_anthropic_ip() {
        // 160.79.104.10 is in Anthropic's ARIN-allocated range 160.79.104.0/21.
        // This is the exact IP that triggered Chris's original alert.
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let ip: IpAddr = "160.79.104.10".parse().unwrap();
        assert!(engine.is_well_known_destination(&ip));
    }

    #[test]
    fn test_safety_pin_blocks_cloudfront_ips() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        // Exact IPs from Chris's AEGIS_BLOCK chain with 19k-23k packet drops.
        for ip_str in &[
            "13.224.185.97",
            "13.224.185.100",
            "13.224.185.102",
            "13.224.185.127",
        ] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                engine.is_well_known_destination(&ip),
                "CloudFront IP {} should be in safety pin",
                ip_str
            );
        }
    }

    #[test]
    fn test_safety_pin_blocks_github_ips() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        for ip_str in &["140.82.112.25", "140.82.112.26", "140.82.114.22"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                engine.is_well_known_destination(&ip),
                "GitHub IP {} should be in safety pin",
                ip_str
            );
        }
    }

    #[test]
    fn test_safety_pin_blocks_cloudflare_ips() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        for ip_str in &["104.28.164.48", "104.16.1.1", "172.64.1.1", "162.158.1.1"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                engine.is_well_known_destination(&ip),
                "Cloudflare IP {} should be in safety pin",
                ip_str
            );
        }
    }

    #[test]
    fn test_safety_pin_does_not_block_random_public_ips() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        // Random IPs that should NOT be in the safety pin list — if any of
        // these somehow match, the CIDR list is too broad and needs fixing.
        for ip_str in &[
            "1.2.3.4",
            "185.156.73.233",
            "79.124.40.174",
            "45.148.10.187",
        ] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                !engine.is_well_known_destination(&ip),
                "Random public IP {} should NOT be in safety pin (list is too broad!)",
                ip_str
            );
        }
    }

    #[test]
    fn test_safety_pin_describe_provider_names() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let anthropic: IpAddr = "160.79.104.10".parse().unwrap();
        let cf: IpAddr = "104.16.1.1".parse().unwrap();
        let gh: IpAddr = "140.82.112.26".parse().unwrap();
        let cloudfront: IpAddr = "13.224.185.100".parse().unwrap();
        let google: IpAddr = "142.250.32.6".parse().unwrap();

        assert!(engine
            .describe_well_known_destination(&anthropic)
            .contains("Anthropic"));
        assert!(engine
            .describe_well_known_destination(&cf)
            .contains("Cloudflare"));
        assert!(engine
            .describe_well_known_destination(&gh)
            .contains("GitHub"));
        assert!(engine
            .describe_well_known_destination(&cloudfront)
            .contains("CloudFront"));
        assert!(engine
            .describe_well_known_destination(&google)
            .contains("Google"));
    }

    #[test]
    fn test_block_ip_safety_pin_skips_firewall_call() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let ip: IpAddr = "13.224.185.100".parse().unwrap();

        let outcome = engine
            .block_ip(ip, "test beacon", Some("c2_beacon"), &mut state)
            .unwrap();

        match outcome {
            BlockOutcome::SafetyPinInfrastructure(provider) => {
                assert!(provider.contains("CloudFront"));
            }
            other => panic!("Expected SafetyPinInfrastructure, got {:?}", other),
        }

        // Verify no entry was added to state.blocked_ips
        assert!(!state.is_ip_blocked(&ip));
        assert!(state.blocked_ips.is_empty());
    }

    #[test]
    fn test_block_ip_loopback_excluded_via_extra_safety_pin() {
        // v2.6.1 regression test: when [network] excluded_destinations is
        // merged into the safety-pin list (via new_with_extra_safety_pin /
        // for_test_with_extra_safety_pin), block_ip() against 127.0.0.1
        // must short-circuit with SafetyPinInfrastructure and never hit
        // the firewall backend. This is the response-layer half of the
        // gradle/adb fix; the network-layer half is tested in
        // src/modules/network/mod.rs::excluded_destinations_tests.
        let mut config = ResponseConfig::default();
        // The default user whitelist contains 127.0.0.0/8 too, which would
        // short-circuit before the safety pin and produce BlockOutcome::
        // Whitelisted. Clear it so this test exercises ONLY the safety-pin
        // path that the new excluded_destinations integration installs.
        config.whitelist.clear();
        let extra = vec![
            "127.0.0.0/8".into(),
            "::1/128".into(),
            "169.254.0.0/16".into(),
            "fe80::/10".into(),
        ];
        let engine = ResponseEngine::for_test_with_extra_safety_pin(config, &extra);
        let mut state = default_state();

        for ip_str in &["127.0.0.1", "127.5.5.5", "::1", "169.254.10.20", "fe80::abcd"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            let outcome = engine
                .block_ip(ip, "test loopback", Some("c2_beacon"), &mut state)
                .unwrap();
            assert!(
                matches!(outcome, BlockOutcome::SafetyPinInfrastructure(_)),
                "expected SafetyPinInfrastructure for {}, got {:?}",
                ip_str,
                outcome
            );
            assert!(
                !state.is_ip_blocked(&ip),
                "{} must NOT end up in the blocked-IP list",
                ip_str
            );
        }
        assert!(state.blocked_ips.is_empty());

        // Sanity: a public IP still gets blocked normally — protection
        // against external attackers is unchanged.
        let public: IpAddr = "203.0.113.5".parse().unwrap();
        let outcome = engine
            .block_ip(public, "test public", Some("c2_beacon"), &mut state)
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Blocked);
    }

    #[test]
    fn test_block_ip_whitelist_wins_over_safety_pin() {
        // Construct a config where the same IP is in BOTH the user whitelist
        // AND the safety pin list. Expected: user whitelist wins (Whitelisted
        // outcome), because user choice is the highest priority.
        let mut config = ResponseConfig::default();
        config.whitelist.push("160.79.104.0/21".into()); // also in WKD default

        let engine = ResponseEngine::for_test(config);
        let mut state = default_state();
        let ip: IpAddr = "160.79.104.10".parse().unwrap();

        let outcome = engine
            .block_ip(ip, "test", Some("c2_beacon"), &mut state)
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Whitelisted);
    }

    #[test]
    fn test_block_ip_non_infra_ip_does_block() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let ip: IpAddr = "185.156.73.233".parse().unwrap(); // Reldas-net, not infra

        let outcome = engine
            .block_ip(
                ip,
                "brute force from this IP",
                Some("brute_force"),
                &mut state,
            )
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Blocked);
        assert!(state.is_ip_blocked(&ip));
    }

    #[test]
    fn test_block_ip_empty_wkd_list_behaves_like_v2_5() {
        // Migration safety: a user who has explicitly set well_known_destinations = []
        // gets the v2.5.0 behavior (no safety pin).
        let mut config = ResponseConfig::default();
        config.well_known_destinations = vec![]; // empty list, not default

        let engine = ResponseEngine::for_test(config);
        let mut state = default_state();
        let ip: IpAddr = "13.224.185.100".parse().unwrap();

        // Without the safety pin, a CloudFront IP would get blocked (this is
        // the pre-v2.6.0 behavior we're documenting as a regression test).
        let outcome = engine
            .block_ip(ip, "test", Some("c2_beacon"), &mut state)
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Blocked);
    }

    // -----------------------------------------------------------------------
    // Bucket B: zero-tolerance tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_tolerance_default_list_includes_path_traversal() {
        let config = ResponseConfig::default();
        assert!(config
            .zero_tolerance_threats
            .iter()
            .any(|t| t == "path_traversal"));
        assert!(config
            .zero_tolerance_threats
            .iter()
            .any(|t| t == "sqli_attempt"));
        assert!(config
            .zero_tolerance_threats
            .iter()
            .any(|t| t == "reverse_shell"));
    }

    #[test]
    fn test_zero_tolerance_default_list_excludes_noisy_types() {
        // Conservative default: these types are NOT zero-tolerance because
        // they have higher false-positive rates.
        let config = ResponseConfig::default();
        assert!(!config
            .zero_tolerance_threats
            .iter()
            .any(|t| t == "web_ddos"));
        assert!(!config
            .zero_tolerance_threats
            .iter()
            .any(|t| t == "brute_force"));
        assert!(!config
            .zero_tolerance_threats
            .iter()
            .any(|t| t == "scanner_probe"));
    }

    #[test]
    fn test_is_zero_tolerance_lookup() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        assert!(engine.is_zero_tolerance("path_traversal"));
        assert!(engine.is_zero_tolerance("sqli_attempt"));
        assert!(engine.is_zero_tolerance("reverse_shell"));
        assert!(!engine.is_zero_tolerance("brute_force"));
        assert!(!engine.is_zero_tolerance("web_ddos"));
        assert!(!engine.is_zero_tolerance("unknown_type"));
    }

    #[test]
    fn test_block_ip_zero_tolerance_first_offense_permaban() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let ip: IpAddr = "185.156.73.233".parse().unwrap(); // not infra, not whitelisted

        // First offense on a zero-tolerance threat type
        let outcome = engine
            .block_ip(
                ip,
                "Path traversal attempt: /../../etc/passwd",
                Some("path_traversal"),
                &mut state,
            )
            .unwrap();

        match outcome {
            BlockOutcome::BlockedPermanentZeroTolerance(key) => {
                assert_eq!(key, "path_traversal");
            }
            other => panic!("Expected BlockedPermanentZeroTolerance, got {:?}", other),
        }

        // Block entry must have expires_at = None (permanent)
        assert!(state.is_ip_blocked(&ip));
        let entry = state.blocked_ips.get(&ip).unwrap();
        assert!(
            entry.expires_at.is_none(),
            "Zero-tolerance ban must be permanent"
        );
        assert!(entry.auto, "Should be marked as auto");

        // And the IP must be marked as escalated in strike history
        assert!(
            state.is_escalated(&ip),
            "Zero-tolerance should mark IP as escalated"
        );
    }

    #[test]
    fn test_block_ip_non_zero_tolerance_uses_normal_expiry() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let ip: IpAddr = "185.156.73.233".parse().unwrap();

        // Normal (non-zero-tolerance) threat — first offense should be a
        // regular 24h ban, not permanent.
        let outcome = engine
            .block_ip(ip, "brute force", Some("brute_force"), &mut state)
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Blocked);

        assert!(state.is_ip_blocked(&ip));
        let entry = state.blocked_ips.get(&ip).unwrap();
        assert!(
            entry.expires_at.is_some(),
            "Non-zero-tolerance first offense should have a time-bounded ban"
        );
    }

    #[test]
    fn test_zero_tolerance_does_not_override_whitelist() {
        let mut config = ResponseConfig::default();
        config.whitelist.push("203.0.113.0/24".into());
        let engine = ResponseEngine::for_test(config);
        let mut state = default_state();
        let ip: IpAddr = "203.0.113.42".parse().unwrap();

        // Even though this is a zero-tolerance threat type, the IP is in the
        // user's whitelist — whitelist wins.
        let outcome = engine
            .block_ip(ip, "sqli", Some("sqli_attempt"), &mut state)
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Whitelisted);
        assert!(!state.is_ip_blocked(&ip));
    }

    #[test]
    fn test_zero_tolerance_does_not_override_safety_pin() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        // Cloudflare IP + path_traversal attempt — even though the threat
        // type is zero-tolerance, we must NOT auto-block Cloudflare IPs.
        let ip: IpAddr = "104.16.1.1".parse().unwrap();

        let outcome = engine
            .block_ip(ip, "sqli via CF", Some("sqli_attempt"), &mut state)
            .unwrap();
        match outcome {
            BlockOutcome::SafetyPinInfrastructure(_) => {}
            other => panic!("Safety pin must win over zero-tolerance, got {:?}", other),
        }
        assert!(!state.is_ip_blocked(&ip));
    }

    #[test]
    fn test_block_ip_already_blocked_is_idempotent() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let ip: IpAddr = "185.156.73.233".parse().unwrap();

        // First block
        let first = engine
            .block_ip(ip, "test", Some("brute_force"), &mut state)
            .unwrap();
        assert_eq!(first, BlockOutcome::Blocked);

        // Second call on the same IP — should be AlreadyBlocked, idempotent
        let second = engine
            .block_ip(ip, "test2", Some("brute_force"), &mut state)
            .unwrap();
        assert_eq!(second, BlockOutcome::AlreadyBlocked);
    }

    #[test]
    fn test_block_ip_no_threat_type_key_no_zero_tolerance() {
        // Manual/CLI blocks pass None for threat_type_key. Zero-tolerance
        // must not apply in that path.
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let ip: IpAddr = "185.156.73.233".parse().unwrap();

        let outcome = engine
            .block_ip(ip, "manual cli block", None, &mut state)
            .unwrap();
        assert_eq!(outcome, BlockOutcome::Blocked);
        let entry = state.blocked_ips.get(&ip).unwrap();
        assert!(entry.expires_at.is_some()); // normal time-bounded ban
    }

    // -----------------------------------------------------------------------
    // Integration: respond() produces accurate messages via BlockOutcome
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_respond_safety_pin_message_is_accurate() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();

        let event = ThreatEvent::new(
            ThreatType::C2Beacon,
            "network",
            "Potential C2 beacon: 11 connections to 160.79.104.10:443",
        )
        .with_source_ip("160.79.104.10".parse().unwrap())
        .with_severity(ThreatSeverity::Critical);

        let msg = engine.respond(&event, &mut state).await.unwrap();
        // The default override now says c2_beacon → alert, so we expect
        // an alert message, not a block attempt. This test also validates
        // the override downgrade (part of Bucket A).
        assert!(
            msg.contains("Alert") || msg.contains("alert"),
            "c2_beacon should be alerted, not blocked. Got: {}",
            msg
        );
        // No block should have happened
        let ip: IpAddr = "160.79.104.10".parse().unwrap();
        assert!(!state.is_ip_blocked(&ip));
    }

    #[tokio::test]
    async fn test_respond_path_traversal_triggers_zero_tolerance_permaban() {
        let engine = ResponseEngine::for_test(ResponseConfig::default());
        let mut state = default_state();
        let attacker: IpAddr = "185.156.73.233".parse().unwrap();

        let event = ThreatEvent::new(
            ThreatType::PathTraversal,
            "web",
            "Path traversal attempt: /../../etc/passwd",
        )
        .with_source_ip(attacker);

        let msg = engine.respond(&event, &mut state).await.unwrap();
        assert!(
            msg.contains("PERMANENTLY") || msg.contains("zero-tolerance"),
            "Expected zero-tolerance message, got: {}",
            msg
        );
        assert!(state.is_ip_blocked(&attacker));
        assert!(state.is_escalated(&attacker));
        assert!(state.blocked_ips[&attacker].expires_at.is_none());
    }

    // -----------------------------------------------------------------------
    // Backwards compat & regression
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_default_has_c2_beacon_override_as_alert() {
        // Bucket A: the override was downgraded from "block" to "alert".
        // This test documents the new default and catches accidental reverts.
        let config = ResponseConfig::default();
        assert_eq!(
            config.overrides.get("c2_beacon").map(|s| s.as_str()),
            Some("alert")
        );
    }

    #[test]
    fn test_config_default_wkd_list_is_nonempty() {
        let config = ResponseConfig::default();
        assert!(
            !config.well_known_destinations.is_empty(),
            "Default WKD list must not be empty — the whole point of the safety pin"
        );
        // Sanity: a few critical entries must be present
        assert!(config
            .well_known_destinations
            .iter()
            .any(|c| c.starts_with("160.79.104")));
        assert!(config
            .well_known_destinations
            .iter()
            .any(|c| c.starts_with("140.82.112")));
        assert!(config
            .well_known_destinations
            .iter()
            .any(|c| c.starts_with("13.224.0")));
    }

    #[test]
    fn test_config_default_zero_tolerance_is_nonempty() {
        let config = ResponseConfig::default();
        assert!(!config.zero_tolerance_threats.is_empty());
    }

    // -----------------------------------------------------------------------
    // Bucket D: drift detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_iptables_list_output_basic() {
        let input = "\
-N AEGIS_BLOCK
-A AEGIS_BLOCK -s 1.2.3.4/32 -j DROP
-A AEGIS_BLOCK -s 5.6.7.8/32 -j DROP
-A AEGIS_BLOCK -s 2001:db8::1/128 -j DROP
";
        let ips = parse_iptables_list_output(input);
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_iptables_list_output_ignores_chain_creation() {
        let input = "-N AEGIS_BLOCK\n";
        let ips = parse_iptables_list_output(input);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_iptables_list_output_ignores_malformed_lines() {
        let input = "\
-N AEGIS_BLOCK
-A AEGIS_BLOCK -s 1.2.3.4/32 -j DROP
random garbage line
-A AEGIS_BLOCK -s not-an-ip -j DROP
-A AEGIS_BLOCK -j DROP
-A AEGIS_BLOCK -s 9.8.7.6/32 -j DROP
";
        let ips = parse_iptables_list_output(input);
        // Only the two valid entries should parse.
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"9.8.7.6".parse().unwrap()));
    }

    #[test]
    fn test_parse_nft_list_output_basic() {
        let input = "\
table inet aegis {
    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr 1.2.3.4 drop
        ip saddr 5.6.7.8 drop
        ip6 saddr 2001:db8::1 drop
    }
}
";
        let ips = parse_nft_list_output(input);
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_ufw_status_output_basic() {
        let input = "\
Status: active

To                         Action      From
--                         ------      ----
Anywhere                   DENY IN     1.2.3.4
Anywhere                   ALLOW IN    10.0.0.0/8
Anywhere (v6)              DENY IN     2001:db8::1
";
        let ips = parse_ufw_status_output(input);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    /// Mock backend that lets tests control what list_blocked_ips returns,
    /// so we can exercise the reconcile logic without touching real iptables.
    struct MockFirewall {
        pub live_ips: std::sync::Mutex<Vec<IpAddr>>,
        pub block_calls: std::sync::Mutex<Vec<IpAddr>>,
        pub unblock_calls: std::sync::Mutex<Vec<IpAddr>>,
    }

    impl FirewallBackend for MockFirewall {
        fn init(&self) -> Result<()> {
            Ok(())
        }
        fn block_ip(&self, ip: &IpAddr) -> Result<()> {
            self.block_calls.lock().unwrap().push(*ip);
            self.live_ips.lock().unwrap().push(*ip);
            Ok(())
        }
        fn unblock_ip(&self, ip: &IpAddr) -> Result<()> {
            self.unblock_calls.lock().unwrap().push(*ip);
            self.live_ips.lock().unwrap().retain(|x| x != ip);
            Ok(())
        }
        fn list_blocked_ips(&self) -> Result<Vec<IpAddr>> {
            Ok(self.live_ips.lock().unwrap().clone())
        }
    }

    fn response_engine_with_mock_firewall(
        config: ResponseConfig,
        live_ips: Vec<IpAddr>,
    ) -> (ResponseEngine, std::sync::Arc<MockFirewall>) {
        let mock = std::sync::Arc::new(MockFirewall {
            live_ips: std::sync::Mutex::new(live_ips),
            block_calls: std::sync::Mutex::new(Vec::new()),
            unblock_calls: std::sync::Mutex::new(Vec::new()),
        });
        // Replicate for_test() but with our mock instead of NoOpBackend.
        let whitelist = ip::parse_whitelist(&config.whitelist);
        let well_known_destinations = ip::parse_whitelist(&config.well_known_destinations);
        let zero_tolerance_threats: HashSet<String> =
            config.zero_tolerance_threats.iter().cloned().collect();
        let firewall: Box<dyn FirewallBackend> = {
            // We need a Box<dyn FirewallBackend>, but we also want to keep
            // a handle to the mock for assertions. Use a newtype that delegates.
            struct BackendDelegate(std::sync::Arc<MockFirewall>);
            impl FirewallBackend for BackendDelegate {
                fn init(&self) -> Result<()> {
                    self.0.init()
                }
                fn block_ip(&self, ip: &IpAddr) -> Result<()> {
                    self.0.block_ip(ip)
                }
                fn unblock_ip(&self, ip: &IpAddr) -> Result<()> {
                    self.0.unblock_ip(ip)
                }
                fn list_blocked_ips(&self) -> Result<Vec<IpAddr>> {
                    self.0.list_blocked_ips()
                }
            }
            Box::new(BackendDelegate(mock.clone()))
        };
        let block_duration = Scheduler::parse_duration(&config.default_block_duration)
            .unwrap_or(Duration::from_secs(86400));
        let engine = ResponseEngine {
            config,
            whitelist,
            well_known_destinations,
            zero_tolerance_threats,
            firewall,
            block_duration,
            recent_blocks: std::sync::Mutex::new(VecDeque::new()),
            data_dir: std::path::PathBuf::from("/tmp/aegis-test"),
            geoip: None,
        };
        (engine, mock)
    }

    #[test]
    fn test_reconcile_report_no_drift() {
        let config = ResponseConfig::default();
        let (engine, _mock) = response_engine_with_mock_firewall(config, vec![]);
        let mut state = default_state();
        let report = engine.reconcile_firewall_state(&mut state);
        assert_eq!(report.persisted_count, 0);
        assert_eq!(report.firewall_count, 0);
        assert!(report.is_in_sync());
        assert_eq!(report.total_drift(), 0);
        assert!(!report.auto_reconciled); // nothing to do
    }

    #[test]
    fn test_reconcile_report_missing_from_firewall() {
        // Persisted: 3 IPs, Firewall: 1 IP → 2 missing
        let config = ResponseConfig::default();
        let fw_ip: IpAddr = "1.1.1.1".parse().unwrap();
        let (engine, _mock) = response_engine_with_mock_firewall(config, vec![fw_ip]);

        let mut state = default_state();
        for ip_str in &["1.1.1.1", "2.2.2.2", "3.3.3.3"] {
            state.block_ip(BlockEntry {
                ip: ip_str.parse().unwrap(),
                reason: "test".into(),
                blocked_at: Utc::now(),
                expires_at: None,
                auto: true,
            });
        }

        let report = engine.reconcile_firewall_state(&mut state);
        assert_eq!(report.persisted_count, 3);
        assert_eq!(report.firewall_count, 1);
        assert_eq!(report.missing_from_firewall.len(), 2);
        assert!(report.orphaned_in_firewall.is_empty());
    }

    #[test]
    fn test_reconcile_report_orphaned_in_firewall() {
        // Persisted: 1 IP, Firewall: 3 IPs → 2 orphaned
        let config = ResponseConfig::default();
        let (engine, _mock) = response_engine_with_mock_firewall(
            config,
            vec![
                "1.1.1.1".parse().unwrap(),
                "2.2.2.2".parse().unwrap(),
                "3.3.3.3".parse().unwrap(),
            ],
        );

        let mut state = default_state();
        state.block_ip(BlockEntry {
            ip: "1.1.1.1".parse().unwrap(),
            reason: "test".into(),
            blocked_at: Utc::now(),
            expires_at: None,
            auto: true,
        });

        let report = engine.reconcile_firewall_state(&mut state);
        assert_eq!(report.persisted_count, 1);
        assert_eq!(report.firewall_count, 3);
        assert!(report.missing_from_firewall.is_empty());
        assert_eq!(report.orphaned_in_firewall.len(), 2);
    }

    #[test]
    fn test_reconcile_auto_repair_disabled_by_default() {
        let config = ResponseConfig::default();
        assert!(!config.auto_reconcile_firewall); // verify default
        let (engine, mock) =
            response_engine_with_mock_firewall(config, vec!["1.1.1.1".parse().unwrap()]);
        let mut state = default_state();
        state.block_ip(BlockEntry {
            ip: "2.2.2.2".parse().unwrap(),
            reason: "test".into(),
            blocked_at: Utc::now(),
            expires_at: None,
            auto: true,
        });

        let _report = engine.reconcile_firewall_state(&mut state);
        // With auto_reconcile_firewall = false, no backend mutation calls.
        assert!(mock.block_calls.lock().unwrap().is_empty());
        assert!(mock.unblock_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_reconcile_auto_repair_fixes_small_drift() {
        let mut config = ResponseConfig::default();
        config.auto_reconcile_firewall = true;

        let orphan: IpAddr = "9.9.9.9".parse().unwrap();
        let missing: IpAddr = "203.0.113.50".parse().unwrap();
        let (engine, mock) = response_engine_with_mock_firewall(config, vec![orphan]);

        let mut state = default_state();
        state.block_ip(BlockEntry {
            ip: missing,
            reason: "test".into(),
            blocked_at: Utc::now(),
            expires_at: None,
            auto: true,
        });

        let report = engine.reconcile_firewall_state(&mut state);
        assert!(report.auto_reconciled);
        // block_ip should have been called to add the missing IP
        assert!(mock.block_calls.lock().unwrap().contains(&missing));
        // unblock_ip should have been called to remove the orphan
        assert!(mock.unblock_calls.lock().unwrap().contains(&orphan));
    }

    #[test]
    fn test_reconcile_auto_repair_skips_when_drift_is_huge() {
        // When the drift count exceeds the safety threshold, auto-repair
        // must refuse to act even if enabled — prevents catastrophic
        // cleanup on a box that has many legitimate historical rules.
        let mut config = ResponseConfig::default();
        config.auto_reconcile_firewall = true;

        // Generate 200 orphaned IPs (above the 100 threshold)
        let orphans: Vec<IpAddr> = (1..=200u8)
            .map(|i| format!("10.0.0.{}", i).parse::<IpAddr>().unwrap())
            .collect();

        let (engine, mock) = response_engine_with_mock_firewall(config, orphans.clone());
        let mut state = default_state();

        let report = engine.reconcile_firewall_state(&mut state);
        assert_eq!(report.orphaned_in_firewall.len(), 200);
        // Auto-reconciled should be false because we crossed the threshold
        assert!(!report.auto_reconciled);
        // No unblock calls should have been made
        assert!(mock.unblock_calls.lock().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // 2026-04-10 incident regression tests
    // -----------------------------------------------------------------------
    //
    // These cover the loopback-outage class of bug. Each test fails on the
    // old code and passes on the fix; keep them in lockstep if the block
    // pipeline is ever refactored.

    #[test]
    fn test_block_ip_firewall_refuses_loopback() {
        // The public firewall API used to bypass the whitelist entirely.
        // With the fix, it must refuse loopback unconditionally — even
        // though the default whitelist contains 127.0.0.0/8.
        let config = ResponseConfig::default();
        let (engine, mock) = response_engine_with_mock_firewall(config, vec![]);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let result = engine.block_ip_firewall(&loopback);
        assert!(result.is_err(), "expected loopback block to be rejected");
        assert!(
            mock.block_calls.lock().unwrap().is_empty(),
            "backend must not have been called for a whitelisted IP"
        );
    }

    #[test]
    fn test_block_ip_firewall_refuses_rfc1918() {
        let config = ResponseConfig::default();
        let (engine, mock) = response_engine_with_mock_firewall(config, vec![]);
        for ip_str in ["10.0.0.1", "172.16.5.5", "192.168.1.1"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                engine.block_ip_firewall(&ip).is_err(),
                "expected {} to be rejected",
                ip_str
            );
        }
        assert!(mock.block_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_block_ip_firewall_refuses_ipv4_mapped_loopback() {
        // The exact form that bit us on 2026-04-10: the detector had
        // `::ffff:127.0.0.1` in hand, and this path skipped the whitelist
        // because ipnet::IpNet can't match across IPv4/IPv6 family boundary.
        let config = ResponseConfig::default();
        let (engine, mock) = response_engine_with_mock_firewall(config, vec![]);
        let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            engine.block_ip_firewall(&mapped_loopback).is_err(),
            "::ffff:127.0.0.1 must be refused via canonicalization"
        );
        assert!(mock.block_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_block_ip_firewall_still_blocks_public_ips() {
        // Regression guard: don't let the new safety checks break the
        // legitimate use case of blocking a real malicious IP.
        let config = ResponseConfig::default();
        let (engine, mock) = response_engine_with_mock_firewall(config, vec![]);
        let bad: IpAddr = "185.156.73.233".parse().unwrap();
        assert!(engine.block_ip_firewall(&bad).is_ok());
        assert_eq!(mock.block_calls.lock().unwrap().as_slice(), &[bad]);
    }

    #[test]
    fn test_reconcile_self_heals_whitelisted_missing_entry() {
        // Simulate the poisoned state we saw in Chris's block_list.json:
        // a loopback (or IPv4-mapped-loopback) entry that slipped in via
        // the pre-fix buggy detector. On reconcile with auto_reconcile
        // enabled, we must NOT re-install the rule — instead we purge it
        // from state so the next save rewrites block_list.json without it.
        let mut config = ResponseConfig::default();
        config.auto_reconcile_firewall = true;
        let (engine, mock) = response_engine_with_mock_firewall(config, vec![]);

        let mut state = default_state();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        state.block_ip(BlockEntry {
            ip: loopback,
            reason: "pre-fix poisoning".into(),
            blocked_at: Utc::now(),
            expires_at: None,
            auto: true,
        });

        let _report = engine.reconcile_firewall_state(&mut state);

        // State must no longer contain the bad entry (self-heal)…
        assert!(
            !state.is_ip_blocked(&loopback),
            "reconcile must purge whitelisted entries from state"
        );
        // …and the backend must not have been asked to re-add it.
        assert!(
            mock.block_calls.lock().unwrap().is_empty(),
            "backend must not be called to re-add a whitelisted IP"
        );
    }

    #[test]
    fn test_is_whitelisted_helper_respects_config() {
        let config = ResponseConfig::default();
        let (engine, _mock) = response_engine_with_mock_firewall(config, vec![]);
        assert!(engine.is_whitelisted(&"127.0.0.1".parse().unwrap()));
        assert!(engine.is_whitelisted(&"::1".parse().unwrap()));
        assert!(engine.is_whitelisted(&"10.0.0.1".parse().unwrap()));
        // IPv4-mapped loopback — the original bug
        assert!(engine.is_whitelisted(&"::ffff:127.0.0.1".parse().unwrap()));
        assert!(!engine.is_whitelisted(&"8.8.8.8".parse().unwrap()));
    }
}
