use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Local, NaiveDateTime, Utc};
use regex::Regex;

use crate::config::schema::AuthConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};
use crate::modules::ScanModule;
use crate::util::log_cursor::LogCursors;

/// Authentication monitoring module: parses auth logs (auth.log / secure)
/// to detect SSH brute force attacks, root logins, and logins from new IPs.
pub struct AuthModule {
    config: AuthConfig,
    data_dir: PathBuf,
}

impl AuthModule {
    pub fn new(config: AuthConfig, data_dir: PathBuf) -> Self {
        Self { config, data_dir }
    }
}

/// Parsed representation of a single auth log entry.
#[derive(Debug)]
enum AuthEvent {
    FailedLogin { username: String, ip: String },
    AcceptedLogin { username: String, ip: String },
    InvalidUser { username: String, ip: String },
    RootLogin { ip: String },
}

/// Compiled set of regexes for auth log parsing.
struct AuthPatterns {
    failed: Regex,
    accepted: Regex,
    invalid_user: Regex,
    root_login: Regex,
    syslog_ts: Regex,
}

impl AuthPatterns {
    fn compile() -> Self {
        Self {
            failed: Regex::new(
                r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
            )
            .expect("failed password regex"),
            accepted: Regex::new(
                r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
            )
            .expect("accepted password regex"),
            invalid_user: Regex::new(r"Invalid user (\S+) from (\S+)").expect("invalid user regex"),
            root_login: Regex::new(r"Accepted .+ for root from (\S+)").expect("root login regex"),
            syslog_ts: Regex::new(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
                .expect("syslog timestamp regex"),
        }
    }

    /// Parse a syslog timestamp (e.g. "Mar 12 10:15:32") from the beginning of a line.
    /// Infers the current year since syslog format omits it.
    fn parse_timestamp(&self, line: &str) -> Option<DateTime<Utc>> {
        let caps = self.syslog_ts.captures(line)?;
        let ts_str = caps.get(1)?.as_str();
        let now = Local::now();
        let year = now.year();

        let with_year = format!("{} {}", ts_str, year);
        let naive = NaiveDateTime::parse_from_str(&with_year, "%b %e %H:%M:%S %Y").ok()?;

        // Handle year rollover: if parsed date is in the future by more than a day,
        // it's probably from December of the previous year
        let dt = naive.and_utc();
        if dt > Utc::now() + chrono::Duration::days(1) {
            let with_prev_year = format!("{} {}", ts_str, year - 1);
            NaiveDateTime::parse_from_str(&with_prev_year, "%b %e %H:%M:%S %Y")
                .ok()
                .map(|n| n.and_utc())
        } else {
            Some(dt)
        }
    }

    /// Parse a single log line into zero or more AuthEvents.
    fn parse_line(&self, line: &str) -> Vec<AuthEvent> {
        let mut events = Vec::new();

        // Check for root login first (before generic accepted) so we capture it specifically.
        if let Some(caps) = self.root_login.captures(line) {
            let ip = caps[1].to_string();
            events.push(AuthEvent::RootLogin { ip });
        }

        if let Some(caps) = self.failed.captures(line) {
            let username = caps[1].to_string();
            let ip = caps[2].to_string();
            events.push(AuthEvent::FailedLogin { username, ip });
        } else if let Some(caps) = self.accepted.captures(line) {
            let username = caps[1].to_string();
            let ip = caps[2].to_string();
            events.push(AuthEvent::AcceptedLogin { username, ip });
        } else if let Some(caps) = self.invalid_user.captures(line) {
            let username = caps[1].to_string();
            let ip = caps[2].to_string();
            events.push(AuthEvent::InvalidUser { username, ip });
        }

        events
    }
}

/// Returns true if the IP address is in a private/reserved range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.octets()[0] == 0
            // 0.0.0.0/8
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[async_trait]
impl ScanModule for AuthModule {
    fn name(&self) -> &str {
        "auth"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();
        tracing::info!(
            "Running auth scan (brute_force_threshold={}, window={}s)",
            self.config.brute_force_threshold,
            self.config.brute_force_window
        );

        let patterns = AuthPatterns::compile();

        // Load log cursor for incremental reading (only new lines since last scan)
        let cursor_path = LogCursors::path_for_module("auth", &self.data_dir);
        let mut cursors = LogCursors::load(&cursor_path);

        // Track failed attempts per IP: ip -> list of (username, timestamp)
        let mut failed_by_ip: HashMap<String, Vec<(String, Option<DateTime<Utc>>)>> =
            HashMap::new();
        // Track successful logins: (username, ip)
        let mut successful_logins: Vec<(String, String)> = Vec::new();
        // Track root logins
        let mut root_login_ips: Vec<String> = Vec::new();
        // Track IPs we've already seen for dedup of root login alerts
        let mut root_alerted: HashSet<String> = HashSet::new();

        for log_path_str in &self.config.log_paths {
            let log_path = Path::new(log_path_str);
            if !log_path.exists() {
                tracing::debug!(path = %log_path_str, "Auth log file not found, skipping");
                continue;
            }

            let lines = match cursors.read_lines(log_path, 10_000) {
                Ok(lines) => lines,
                Err(e) => {
                    tracing::warn!(path = %log_path_str, error = %e, "Failed to read auth log");
                    continue;
                }
            };

            for line in &lines {
                let ts = patterns.parse_timestamp(line);
                let events = patterns.parse_line(line);
                for event in events {
                    match event {
                        AuthEvent::FailedLogin { username, ip } => {
                            failed_by_ip.entry(ip).or_default().push((username, ts));
                        }
                        AuthEvent::AcceptedLogin { username, ip } => {
                            successful_logins.push((username, ip));
                        }
                        AuthEvent::InvalidUser { username, ip } => {
                            // Count invalid user attempts as failed logins too
                            failed_by_ip.entry(ip).or_default().push((username, ts));
                        }
                        AuthEvent::RootLogin { ip } => {
                            root_login_ips.push(ip);
                        }
                    }
                }
            }
        }

        // --- Brute Force Detection ---
        let threshold = self.config.brute_force_threshold as usize;
        let window = chrono::Duration::seconds(self.config.brute_force_window as i64);

        for (ip_str, entries) in &failed_by_ip {
            // Find the latest timestamp in this batch to use as reference point.
            // This handles both real-time and historical log analysis correctly.
            let latest_ts = entries.iter().filter_map(|(_, ts)| *ts).max();

            // Filter entries to only those within brute_force_window of the latest entry.
            // If no timestamps are parseable, include all entries conservatively.
            let in_window: Vec<&(String, Option<DateTime<Utc>>)> = match latest_ts {
                Some(latest) => entries
                    .iter()
                    .filter(|(_, ts)| match ts {
                        Some(t) => latest - *t <= window,
                        None => true,
                    })
                    .collect(),
                None => entries.iter().collect(),
            };

            let count = in_window.len();
            if count >= threshold {
                let unique_users: HashSet<&str> =
                    in_window.iter().map(|(u, _)| u.as_str()).collect();
                let users_sample: Vec<&str> = unique_users.iter().take(10).copied().collect();

                let description = format!(
                    "SSH brute force detected: {} failed attempts from {}",
                    count, ip_str
                );

                let mut event = ThreatEvent::new(ThreatType::BruteForce, "auth", description)
                    .with_detail("failed_count", count.to_string())
                    .with_detail("usernames_targeted", users_sample.join(", "))
                    .with_detail("threshold", threshold.to_string());

                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    event = event.with_source_ip(ip);
                }

                event = event.with_target("sshd");

                threats.push(event);
            }
        }

        // --- Root Login Detection ---
        if self.config.alert_root_login {
            for ip_str in &root_login_ips {
                if root_alerted.contains(ip_str) {
                    continue;
                }
                root_alerted.insert(ip_str.clone());

                let description = format!("Root login accepted from {}", ip_str);

                let mut event = ThreatEvent::new(ThreatType::RootLogin, "auth", description)
                    .with_target("root");

                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    event = event.with_source_ip(ip);
                }

                threats.push(event);
            }
        }

        // --- Login Anomaly Detection ---
        // In scan mode, report successful logins from non-private IPs as informational.
        if self.config.alert_new_ip {
            let mut seen_login_ips: HashSet<String> = HashSet::new();
            for (username, ip_str) in &successful_logins {
                // Deduplicate by IP within this scan
                if seen_login_ips.contains(ip_str) {
                    continue;
                }
                seen_login_ips.insert(ip_str.clone());

                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !is_private_ip(&ip) {
                        let description = format!(
                            "Successful login for '{}' from external IP {}",
                            username, ip_str
                        );

                        let event = ThreatEvent::new(ThreatType::LoginAnomaly, "auth", description)
                            .with_severity(ThreatSeverity::Info)
                            .with_source_ip(ip)
                            .with_target(username.as_str())
                            .with_detail("login_type", "external_ip");

                        threats.push(event);
                    }
                }
            }
        }

        // Save cursor so next scan only reads new lines
        if let Err(e) = cursors.save(&cursor_path) {
            tracing::warn!(error = %e, "Failed to save auth log cursor");
        }

        tracing::info!(count = threats.len(), "Auth scan complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_failed_password() {
        let patterns = AuthPatterns::compile();
        let line =
            "Mar 12 10:15:32 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22";
        let events = patterns.parse_line(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, AuthEvent::FailedLogin { username, ip }
            if username == "admin" && ip == "192.168.1.100")));
    }

    #[test]
    fn test_parse_failed_password_invalid_user() {
        let patterns = AuthPatterns::compile();
        let line = "Mar 12 10:15:32 server sshd[12345]: Failed password for invalid user test from 10.0.0.5 port 2222";
        let events = patterns.parse_line(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, AuthEvent::FailedLogin { username, ip }
            if username == "test" && ip == "10.0.0.5")));
    }

    #[test]
    fn test_parse_accepted_password() {
        let patterns = AuthPatterns::compile();
        let line =
            "Mar 12 10:16:00 server sshd[12346]: Accepted password for admin from 10.0.0.1 port 22";
        let events = patterns.parse_line(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, AuthEvent::AcceptedLogin { username, ip }
            if username == "admin" && ip == "10.0.0.1")));
    }

    #[test]
    fn test_parse_accepted_publickey() {
        let patterns = AuthPatterns::compile();
        let line = "Mar 12 10:16:00 server sshd[12346]: Accepted publickey for deploy from 203.0.113.5 port 44100";
        let events = patterns.parse_line(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, AuthEvent::AcceptedLogin { username, ip }
            if username == "deploy" && ip == "203.0.113.5")));
    }

    #[test]
    fn test_parse_invalid_user() {
        let patterns = AuthPatterns::compile();
        let line = "Mar 12 10:15:30 server sshd[12344]: Invalid user ghost from 192.168.1.50";
        let events = patterns.parse_line(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, AuthEvent::InvalidUser { username, ip }
            if username == "ghost" && ip == "192.168.1.50")));
    }

    #[test]
    fn test_parse_root_login() {
        let patterns = AuthPatterns::compile();
        let line =
            "Mar 12 10:20:00 server sshd[12350]: Accepted password for root from 45.33.32.156 port 22";
        let events = patterns.parse_line(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, AuthEvent::RootLogin { ip } if ip == "45.33.32.156")));
    }

    #[test]
    fn test_brute_force_detection() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        let mut content = String::new();
        for i in 0..10 {
            content.push_str(&format!(
                "Mar 12 10:15:{:02} server sshd[{}]: Failed password for admin from 10.0.0.99 port 22\n",
                i, 12345 + i
            ));
        }
        std::fs::write(&log_path, content).unwrap();

        let config = AuthConfig {
            enabled: true,
            brute_force_threshold: 5,
            brute_force_window: 300,
            alert_root_login: false,
            alert_new_ip: false,
            log_paths: vec![log_path.to_str().unwrap().to_string()],
        };

        let module = AuthModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::BruteForce));
        let bf = threats
            .iter()
            .find(|t| t.threat_type == ThreatType::BruteForce)
            .unwrap();
        assert_eq!(bf.details.get("failed_count").unwrap(), "10");
    }

    #[test]
    fn test_root_login_detection() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Mar 12 10:20:00 server sshd[99]: Accepted password for root from 8.8.8.8 port 22\n",
        )
        .unwrap();

        let config = AuthConfig {
            enabled: true,
            brute_force_threshold: 100,
            brute_force_window: 300,
            alert_root_login: true,
            alert_new_ip: false,
            log_paths: vec![log_path.to_str().unwrap().to_string()],
        };

        let module = AuthModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::RootLogin));
    }

    #[test]
    fn test_no_brute_force_below_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        let mut content = String::new();
        for i in 0..3 {
            content.push_str(&format!(
                "Mar 12 10:15:{:02} server sshd[{}]: Failed password for admin from 10.0.0.99 port 22\n",
                i, 12345 + i
            ));
        }
        std::fs::write(&log_path, content).unwrap();

        let config = AuthConfig {
            enabled: true,
            brute_force_threshold: 5,
            brute_force_window: 300,
            alert_root_login: false,
            alert_new_ip: false,
            log_paths: vec![log_path.to_str().unwrap().to_string()],
        };

        let module = AuthModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats.is_empty());
    }

    #[test]
    fn test_missing_log_file_is_handled() {
        let dir = tempfile::tempdir().unwrap();
        let config = AuthConfig {
            enabled: true,
            brute_force_threshold: 5,
            brute_force_window: 300,
            alert_root_login: true,
            alert_new_ip: true,
            log_paths: vec!["/nonexistent/path/auth.log".to_string()],
        };

        let module = AuthModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats.is_empty());
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"203.0.113.5".parse().unwrap()));
    }
}
