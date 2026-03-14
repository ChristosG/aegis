use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use colored::Colorize;
use tabled::settings::Style;
use tabled::{Table, Tabled};

use crate::core::state::{AppState, SecurityPosture};
use crate::core::threat::{ThreatEvent, ThreatSeverity};

// ---------------------------------------------------------------------------
// ScanSummary
// ---------------------------------------------------------------------------

/// Aggregated statistics for a completed scan run.
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// Total number of threats detected.
    pub total: usize,
    /// Breakdown of threats by severity level.
    pub by_severity: HashMap<ThreatSeverity, usize>,
    /// Wall-clock duration of the scan.
    pub duration: Duration,
    /// Names of modules that were executed.
    pub modules_run: Vec<String>,
    /// Number of threats suppressed by deduplication.
    pub suppressed_count: usize,
    /// The dedup TTL string for display (e.g. "1h").
    pub dedup_ttl: String,
}

impl ScanSummary {
    /// Build a ScanSummary from a list of threat events.
    pub fn from_threats(
        threats: &[ThreatEvent],
        duration: Duration,
        modules: Vec<String>,
        suppressed_count: usize,
        dedup_ttl: &str,
    ) -> Self {
        let mut by_severity: HashMap<ThreatSeverity, usize> = HashMap::new();
        for t in threats {
            *by_severity.entry(t.severity).or_insert(0) += 1;
        }
        Self {
            total: threats.len(),
            by_severity,
            duration,
            modules_run: modules,
            suppressed_count,
            dedup_ttl: dedup_ttl.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Severity color helper
// ---------------------------------------------------------------------------

/// Apply the appropriate terminal color to a severity string.
///
/// Color mapping:
///   Info     -> blue
///   Low      -> cyan
///   Medium   -> yellow
///   High     -> red
///   Critical -> red + bold
pub fn severity_color(severity: ThreatSeverity) -> colored::ColoredString {
    let label = format!("{}", severity);
    match severity {
        ThreatSeverity::Info => label.blue(),
        ThreatSeverity::Low => label.cyan(),
        ThreatSeverity::Medium => label.yellow(),
        ThreatSeverity::High => label.red(),
        ThreatSeverity::Critical => label.red().bold(),
    }
}

/// Apply the appropriate terminal color to a security posture string.
fn posture_color(posture: SecurityPosture) -> colored::ColoredString {
    let label = format!("{}", posture);
    match posture {
        SecurityPosture::Secure => label.green().bold(),
        SecurityPosture::Guarded => label.blue().bold(),
        SecurityPosture::Elevated => label.yellow().bold(),
        SecurityPosture::High => label.red().bold(),
        SecurityPosture::Critical => label.red().bold().on_white(),
    }
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/// Print the Aegis ASCII-art banner with the current version.
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let banner = format!(
        r#"
   ___    ____________  _____
  /   |  / ____/ ____/ /  _/ ____
 / /| | / __/ / / __   / / / ___/
/ ___ |/ /___/ /_/ / _/ / (__  )
/_/  |_/_____/\____/ /___//____/

  Linux Security Monitor v{}
"#,
        version
    );
    println!("{}", banner.bold().cyan());
}

// ---------------------------------------------------------------------------
// Scan header
// ---------------------------------------------------------------------------

/// Print a colored header line for a scanning module.
pub fn print_scan_header(module: &str) {
    let header = format!("[*] Scanning: {}", module);
    println!("\n{}", header.bold().white());
    println!("{}", "-".repeat(60).dimmed());
}

// ---------------------------------------------------------------------------
// Single threat
// ---------------------------------------------------------------------------

/// Print a single threat event with severity-appropriate coloring.
pub fn print_threat(threat: &ThreatEvent) {
    let sev = severity_color(threat.severity);
    let timestamp = threat.timestamp.format("%Y-%m-%d %H:%M:%S UTC");

    println!(
        "  {} [{}] {} -- {}",
        sev, timestamp, threat.threat_type, threat.description
    );

    if let Some(ref ip) = threat.source_ip {
        println!("       Source IP : {}", ip.to_string().yellow());
    }
    if let Some(ref target) = threat.target {
        println!("       Target    : {}", target);
    }
    if threat.auto_responded {
        println!("       Response  : {}", "auto-responded".green().bold());
    }
}

// ---------------------------------------------------------------------------
// Threats table
// ---------------------------------------------------------------------------

/// Row type for the tabled crate.
#[derive(Tabled)]
struct ThreatRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Type")]
    threat_type: String,
    #[tabled(rename = "Source IP")]
    source_ip: String,
    #[tabled(rename = "Target")]
    target: String,
    #[tabled(rename = "Description")]
    description: String,
    #[tabled(rename = "Time")]
    timestamp: String,
}

/// Get terminal width, falling back to 120 if unavailable.
fn terminal_width() -> usize {
    // Try reading from the COLUMNS env var or default to a wide value.
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            // Try ioctl via a simple command
            std::process::Command::new("tput")
                .arg("cols")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(160)
        })
}

/// Print a list of threats as a formatted ASCII table.
pub fn print_threats_table(threats: &[ThreatEvent]) {
    if threats.is_empty() {
        println!("\n  {}", "No threats detected.".green().bold());
        return;
    }

    // Calculate how much space is available for the description column.
    // Other columns take roughly: severity(10) + type(25) + ip(17) + target(22) + time(10)
    // + borders/padding(~30) = ~114 chars of fixed overhead.
    let term_width = terminal_width();
    let fixed_overhead = 114;
    let max_desc = if term_width > fixed_overhead + 20 {
        term_width - fixed_overhead
    } else {
        60 // minimum fallback
    };

    let rows: Vec<ThreatRow> = threats
        .iter()
        .map(|t| {
            let desc = if t.description.len() > max_desc {
                // Truncate on a word boundary if possible
                let truncated = &t.description[..max_desc.min(t.description.len())];
                match truncated.rfind(' ') {
                    Some(pos) if pos > max_desc / 2 => format!("{}...", &truncated[..pos]),
                    _ => format!("{}...", &t.description[..max_desc - 3]),
                }
            } else {
                t.description.clone()
            };
            ThreatRow {
                severity: format!("{}", t.severity),
                threat_type: format!("{}", t.threat_type),
                source_ip: t
                    .source_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "-".into()),
                target: t.target.clone().unwrap_or_else(|| "-".into()),
                description: desc,
                timestamp: t.timestamp.format("%H:%M:%S").to_string(),
            }
        })
        .collect();

    let table = Table::new(&rows).with(Style::rounded()).to_string();

    println!("\n{}", table);
}

// ---------------------------------------------------------------------------
// Scan summary
// ---------------------------------------------------------------------------

/// Print a summary of the scan results with per-severity counts.
pub fn print_scan_summary(stats: &ScanSummary) {
    println!("\n{}", "=".repeat(60).dimmed());
    println!("{}", " SCAN SUMMARY".bold().white());
    println!("{}", "=".repeat(60).dimmed());

    println!("  Duration     : {:.2}s", stats.duration.as_secs_f64());
    println!("  Modules      : {}", stats.modules_run.join(", "));
    println!(
        "  Total threats: {}",
        if stats.total == 0 {
            "0".green().bold().to_string()
        } else {
            stats.total.to_string().red().bold().to_string()
        }
    );

    if stats.suppressed_count > 0 {
        println!(
            "  Suppressed   : {} (previously seen within {})",
            stats.suppressed_count.to_string().dimmed(),
            stats.dedup_ttl.dimmed()
        );
    }

    // Per-severity breakdown, always in order from Critical down to Info.
    let severities = [
        ThreatSeverity::Critical,
        ThreatSeverity::High,
        ThreatSeverity::Medium,
        ThreatSeverity::Low,
        ThreatSeverity::Info,
    ];

    for sev in &severities {
        let count = stats.by_severity.get(sev).copied().unwrap_or(0);
        if count > 0 {
            println!("    {:<10} : {}", severity_color(*sev), count);
        }
    }

    println!("{}", "=".repeat(60).dimmed());
}

// ---------------------------------------------------------------------------
// Response summary
// ---------------------------------------------------------------------------

/// Print a summary of automated response actions taken.
pub fn print_response_summary(threats: &[ThreatEvent]) {
    let responded: Vec<&ThreatEvent> = threats.iter().filter(|t| t.auto_responded).collect();
    if responded.is_empty() {
        return;
    }

    // Categorise by actual response_action stored in details.
    let mut blocked_ips: HashMap<IpAddr, String> = HashMap::new(); // ip -> reason
    let mut killed: Vec<&ThreatEvent> = Vec::new();
    let mut alerts: usize = 0;
    let mut logged: usize = 0;

    for t in &responded {
        let action = t
            .details
            .get("response_action")
            .map(|s| s.as_str())
            .unwrap_or("alert");
        match action {
            "block" => {
                if let Some(ip) = t.source_ip {
                    blocked_ips
                        .entry(ip)
                        .or_insert_with(|| format!("{}", t.threat_type));
                } else {
                    alerts += 1;
                }
            }
            "kill" => {
                killed.push(t);
            }
            "block+kill" => {
                if let Some(ip) = t.source_ip {
                    blocked_ips
                        .entry(ip)
                        .or_insert_with(|| format!("{}", t.threat_type));
                }
                killed.push(t);
            }
            "alert" => {
                alerts += 1;
            }
            _ => {
                logged += 1;
            }
        }
    }

    println!("\n{}", "=".repeat(60).dimmed());
    println!("{}", " RESPONSE SUMMARY".bold().green());
    println!("{}", "=".repeat(60).dimmed());

    println!(
        "  Actions taken : {}",
        responded.len().to_string().green().bold()
    );

    if !blocked_ips.is_empty() {
        println!(
            "  IPs blocked   : {}",
            blocked_ips.len().to_string().red().bold()
        );
        let mut sorted_ips: Vec<(&IpAddr, &String)> = blocked_ips.iter().collect();
        sorted_ips.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
        for (ip, reason) in &sorted_ips {
            println!(
                "    {} {} ({})",
                "DROP".red().bold(),
                ip.to_string().yellow(),
                reason.dimmed()
            );
        }
    }

    if !killed.is_empty() {
        println!(
            "  Processes killed: {}",
            killed.len().to_string().red().bold()
        );
        for t in &killed {
            let pid = t.details.get("pid").map(|s| s.as_str()).unwrap_or("?");
            let name = t
                .details
                .get("name")
                .map(|s| s.as_str())
                .unwrap_or(&t.description);
            println!(
                "    {} PID {} ({})",
                "KILL".red().bold(),
                pid.yellow(),
                name.dimmed()
            );
        }
    }

    if alerts > 0 {
        println!("  Alerts raised : {}", alerts.to_string().yellow().bold());
    }

    if logged > 0 {
        println!("  Events logged : {}", logged.to_string().dimmed());
    }

    println!("{}", "=".repeat(60).dimmed());
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Print the current security posture and high-level state.
pub fn print_status(state: &AppState) {
    print_banner();

    println!("{}", "-".repeat(60).dimmed());
    println!("  Security Posture : {}", posture_color(state.posture));
    println!(
        "  Active since     : {}",
        state.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "  Daemon running   : {}",
        if state.daemon_running {
            "yes".green().to_string()
        } else {
            "no".yellow().to_string()
        }
    );
    println!("  Total threats    : {}", state.threats.len());
    println!("  Blocked IPs      : {}", state.blocked_ips.len());
    println!(
        "  Modules run      : {}",
        if state.modules_run.is_empty() {
            "none".dimmed().to_string()
        } else {
            let mut mods: Vec<&String> = state.modules_run.iter().collect();
            mods.sort();
            mods.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!("{}", "-".repeat(60).dimmed());

    // Quick threat summary if there are any.
    if !state.threats.is_empty() {
        let counts = state.threat_counts();
        println!("\n  Threat breakdown:");
        let severities = [
            ThreatSeverity::Critical,
            ThreatSeverity::High,
            ThreatSeverity::Medium,
            ThreatSeverity::Low,
            ThreatSeverity::Info,
        ];
        for sev in &severities {
            if let Some(&count) = counts.get(sev) {
                println!("    {:<10} : {}", severity_color(*sev), count);
            }
        }

        // Top attacking IPs.
        let top_ips = state.top_attacking_ips(5);
        if !top_ips.is_empty() {
            println!("\n  Top attacking IPs:");
            for (ip, count) in &top_ips {
                let blocked = if state.blocked_ips.contains_key(ip) {
                    " [BLOCKED]".red().bold().to_string()
                } else {
                    String::new()
                };
                println!("    {} ({} events){}", ip, count, blocked);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::threat::{ThreatEvent, ThreatType};

    #[test]
    fn test_scan_summary_from_threats() {
        let threats = vec![
            ThreatEvent::new(ThreatType::PortScan, "network", "port scan 1"),
            ThreatEvent::new(ThreatType::SynFlood, "network", "syn flood 1"),
            ThreatEvent::new(ThreatType::TorExit, "threat_intel", "tor exit node"),
        ];

        let summary = ScanSummary::from_threats(
            &threats,
            Duration::from_secs(5),
            vec!["network".into()],
            0,
            "1h",
        );

        assert_eq!(summary.total, 3);
        assert!(summary.by_severity.contains_key(&ThreatSeverity::Medium)); // PortScan
        assert!(summary.by_severity.contains_key(&ThreatSeverity::High)); // SynFlood
        assert!(summary.by_severity.contains_key(&ThreatSeverity::Info)); // TorExit
    }

    #[test]
    fn test_severity_color_returns_correct_labels() {
        let info = severity_color(ThreatSeverity::Info);
        assert!(info.to_string().contains("INFO") || info.to_string().contains("info"));

        let crit = severity_color(ThreatSeverity::Critical);
        assert!(crit.to_string().contains("CRITICAL") || crit.to_string().contains("critical"));
    }
}
