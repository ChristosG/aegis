use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use crate::config::schema::AnomalyConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};
use crate::modules::ScanModule;

/// Log anomaly detection module.
///
/// Detects unusual login times, cron/sudoers modifications, and new user accounts
/// by parsing system logs and comparing against baselines.
pub struct AnomalyModule {
    config: AnomalyConfig,
    data_dir: std::path::PathBuf,
}

impl AnomalyModule {
    pub fn new(config: AnomalyConfig, data_dir: std::path::PathBuf) -> Self {
        Self { config, data_dir }
    }

    /// Check for logins outside normal hours by parsing auth logs.
    fn check_unusual_login_times(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        if self.config.normal_login_hours.len() != 2 {
            return threats;
        }
        let start_hour = self.config.normal_login_hours[0];
        let end_hour = self.config.normal_login_hours[1];

        let auth_log_paths = ["/var/log/auth.log", "/var/log/secure"];

        for log_path in &auth_log_paths {
            let path = Path::new(log_path);
            if !path.exists() {
                continue;
            }

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Parse recent login lines (last 100 lines to avoid huge scans)
            let lines: Vec<&str> = content.lines().collect();
            let recent = if lines.len() > 100 {
                &lines[lines.len() - 100..]
            } else {
                &lines[..]
            };

            for line in recent {
                // Match "Accepted" login lines
                if !line.contains("Accepted") {
                    continue;
                }

                // Parse timestamp from syslog format: "Mar 15 03:42:17"
                if let Some(hour) = parse_syslog_hour(line) {
                    let outside_normal = if start_hour <= end_hour {
                        hour < start_hour || hour >= end_hour
                    } else {
                        // Wrapping case: e.g., normal = [22, 6] means 22:00-06:00
                        hour < start_hour && hour >= end_hour
                    };

                    if outside_normal {
                        // Extract username and IP if possible
                        let desc = format!(
                            "Login detected outside normal hours ({:02}:00-{:02}:00): {}",
                            start_hour,
                            end_hour,
                            line.trim()
                        );
                        let mut event =
                            ThreatEvent::new(ThreatType::UnusualLoginTime, "anomaly", desc);

                        // Try to extract source IP from the line
                        if let Some(ip) = extract_ip_from_line(line) {
                            if let Ok(addr) = ip.parse() {
                                event = event.with_source_ip(addr);
                            }
                        }

                        threats.push(event);
                    }
                }
            }
        }

        threats
    }

    /// Check for cron file modifications by hashing and comparing to baseline.
    fn check_cron_changes(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let baseline_path = self.data_dir.join("anomaly_cron_baseline.json");

        let cron_paths = vec![
            "/etc/crontab".to_string(),
            "/etc/cron.d".to_string(),
            "/var/spool/cron".to_string(),
            "/var/spool/cron/crontabs".to_string(),
        ];

        let current = hash_paths(&cron_paths);

        // Load baseline
        let baseline: HashMap<String, String> = if baseline_path.exists() {
            match std::fs::read_to_string(&baseline_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        if !baseline.is_empty() {
            for (path, hash) in &current {
                match baseline.get(path) {
                    Some(old_hash) if old_hash != hash => {
                        threats.push(
                            ThreatEvent::new(
                                ThreatType::CronModified,
                                "anomaly",
                                format!("Cron file modified: {}", path),
                            )
                            .with_target(path.clone()),
                        );
                    }
                    None => {
                        threats.push(
                            ThreatEvent::new(
                                ThreatType::CronModified,
                                "anomaly",
                                format!("New cron file detected: {}", path),
                            )
                            .with_target(path.clone()),
                        );
                    }
                    _ => {}
                }
            }
        }

        // Save current as new baseline
        if let Ok(json) = serde_json::to_string_pretty(&current) {
            let _ = std::fs::write(&baseline_path, json);
        }

        threats
    }

    /// Check for sudoers file modifications.
    fn check_sudoers_changes(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let baseline_path = self.data_dir.join("anomaly_sudoers_baseline.json");

        let sudoers_paths = vec!["/etc/sudoers".to_string(), "/etc/sudoers.d".to_string()];

        let current = hash_paths(&sudoers_paths);

        let baseline: HashMap<String, String> = if baseline_path.exists() {
            match std::fs::read_to_string(&baseline_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        if !baseline.is_empty() {
            for (path, hash) in &current {
                match baseline.get(path) {
                    Some(old_hash) if old_hash != hash => {
                        threats.push(
                            ThreatEvent::new(
                                ThreatType::SudoersModified,
                                "anomaly",
                                format!("Sudoers file modified: {}", path),
                            )
                            .with_target(path.clone())
                            .with_severity(ThreatSeverity::High),
                        );
                    }
                    None => {
                        threats.push(
                            ThreatEvent::new(
                                ThreatType::SudoersModified,
                                "anomaly",
                                format!("New sudoers file detected: {}", path),
                            )
                            .with_target(path.clone())
                            .with_severity(ThreatSeverity::High),
                        );
                    }
                    _ => {}
                }
            }
        }

        if let Ok(json) = serde_json::to_string_pretty(&current) {
            let _ = std::fs::write(&baseline_path, json);
        }

        threats
    }

    /// Detect new user accounts by comparing /etc/passwd against baseline.
    fn check_new_users(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let baseline_path = self.data_dir.join("anomaly_users_baseline.json");

        let current_users = match parse_passwd_users() {
            Ok(users) => users,
            Err(_) => return threats,
        };

        let baseline_users: Vec<String> = if baseline_path.exists() {
            match std::fs::read_to_string(&baseline_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        if !baseline_users.is_empty() {
            for user in &current_users {
                if !baseline_users.contains(user) {
                    threats.push(
                        ThreatEvent::new(
                            ThreatType::NewUserCreated,
                            "anomaly",
                            format!("New user account detected: {}", user),
                        )
                        .with_detail("username", user.clone()),
                    );
                }
            }
        }

        // Save current as baseline
        if let Ok(json) = serde_json::to_string_pretty(&current_users) {
            let _ = std::fs::write(&baseline_path, json);
        }

        threats
    }

    /// D3: Check for new/unexpected kernel modules by comparing /proc/modules to baseline.
    fn check_kernel_modules(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let baseline_path = self.data_dir.join("kernel_modules_baseline.json");

        let current_modules = match parse_kernel_modules() {
            Ok(m) => m,
            Err(_) => return threats,
        };

        let baseline_modules: Vec<String> = if baseline_path.exists() {
            match std::fs::read_to_string(&baseline_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        if !baseline_modules.is_empty() {
            for module in &current_modules {
                if !baseline_modules.contains(module) {
                    threats.push(
                        ThreatEvent::new(
                            ThreatType::KernelModuleLoaded,
                            "anomaly",
                            format!("New kernel module detected: {}", module),
                        )
                        .with_detail("module_name", module.clone())
                        .with_severity(ThreatSeverity::High),
                    );
                }
            }
        }

        // Save current as baseline
        if let Ok(json) = serde_json::to_string_pretty(&current_modules) {
            let _ = std::fs::write(&baseline_path, json);
        }

        threats
    }
}

#[async_trait]
impl ScanModule for AnomalyModule {
    fn name(&self) -> &str {
        "anomaly"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();

        threats.extend(self.check_unusual_login_times());

        if self.config.watch_cron {
            threats.extend(self.check_cron_changes());
        }

        if self.config.watch_sudoers {
            threats.extend(self.check_sudoers_changes());
        }

        if self.config.watch_user_changes {
            threats.extend(self.check_new_users());
        }

        threats.extend(self.check_kernel_modules());

        debug!(count = threats.len(), "Anomaly scan complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the hour from a syslog-format timestamp at the start of a line.
fn parse_syslog_hour(line: &str) -> Option<u32> {
    // Syslog format: "Mar 15 03:42:17 ..."
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() < 3 {
        return None;
    }
    // parts[2] should be "HH:MM:SS"
    let time_parts: Vec<&str> = parts[2].split(':').collect();
    if time_parts.is_empty() {
        return None;
    }
    time_parts[0].parse().ok()
}

/// Try to extract an IP address from an auth log line.
fn extract_ip_from_line(line: &str) -> Option<&str> {
    // Look for "from <IP>" pattern
    if let Some(pos) = line.find(" from ") {
        let after = &line[pos + 6..];
        let ip_end = after.find(' ').unwrap_or(after.len());
        let candidate = &after[..ip_end];
        // Basic validation: must contain a dot or colon
        if candidate.contains('.') || candidate.contains(':') {
            return Some(candidate);
        }
    }
    None
}

/// Hash all files under the given paths, returning a map of path -> SHA256.
fn hash_paths(paths: &[String]) -> HashMap<String, String> {
    use sha2::{Digest, Sha256};
    let mut result = HashMap::new();

    for base_path in paths {
        let path = Path::new(base_path);
        if !path.exists() {
            continue;
        }

        if path.is_file() {
            if let Ok(content) = std::fs::read(path) {
                let hash = hex::encode(Sha256::digest(&content));
                result.insert(base_path.clone(), hash);
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        if let Ok(content) = std::fs::read(&entry_path) {
                            let hash = hex::encode(Sha256::digest(&content));
                            result.insert(entry_path.to_string_lossy().to_string(), hash);
                        }
                    }
                }
            }
        }
    }

    result
}

/// Parse kernel module names from /proc/modules.
fn parse_kernel_modules() -> Result<Vec<String>> {
    let content = std::fs::read_to_string("/proc/modules")?;
    let modules: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            Some(name.to_string())
        })
        .collect();
    Ok(modules)
}

/// Parse usernames from /etc/passwd.
fn parse_passwd_users() -> Result<Vec<String>> {
    let content = std::fs::read_to_string("/etc/passwd")?;
    let users: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                // Only track users with UID >= 1000 (regular users) or UID 0 (root)
                if let Ok(uid) = parts[2].parse::<u32>() {
                    if uid == 0 || uid >= 1000 {
                        return Some(parts[0].to_string());
                    }
                }
            }
            None
        })
        .collect();
    Ok(users)
}
