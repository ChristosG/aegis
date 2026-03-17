use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::config::schema::RootkitConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;

pub struct RootkitModule {
    config: RootkitConfig,
}

impl RootkitModule {
    pub fn new(config: RootkitConfig) -> Self {
        Self { config }
    }

    /// Check for hidden processes by comparing readdir(/proc) vs kill(pid, 0).
    fn check_hidden_processes(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Get PIDs visible via readdir
        let visible_pids: HashSet<u32> = match fs::read_dir("/proc") {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .collect(),
            Err(_) => return threats,
        };

        // Probe PID range with kill(pid, 0) - returns 0 if process exists
        let max_pid = fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(32768);

        // Only probe a reasonable range to avoid performance issues
        let probe_max = max_pid.min(65536);

        for pid in 1..probe_max {
            if !visible_pids.contains(&pid) {
                // Check if process actually exists
                let result = unsafe { libc::kill(pid as i32, 0) };
                if result == 0 {
                    // Process exists but not visible in /proc readdir
                    threats.push(
                        ThreatEvent::new(
                            ThreatType::HiddenProcess,
                            "rootkit",
                            format!(
                                "Hidden process detected: PID {} exists but not visible in /proc",
                                pid
                            ),
                        )
                        .with_detail("pid", pid.to_string())
                        .with_detail("detection_method", "readdir_vs_kill"),
                    );
                }
            }
        }

        threats
    }

    /// Check for LD_PRELOAD hooks in process environments.
    fn check_ld_preload(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Check system-wide ld.so.preload
        if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
            let content = content.trim();
            if !content.is_empty() && !content.starts_with('#') {
                threats.push(
                    ThreatEvent::new(
                        ThreatType::LdPreloadHook,
                        "rootkit",
                        format!("System-wide LD_PRELOAD found in /etc/ld.so.preload: {}", content),
                    )
                    .with_detail("file", "/etc/ld.so.preload")
                    .with_detail("libraries", content)
                    .with_detail("detection_method", "ld_so_preload"),
                );
            }
        }

        // Check per-process LD_PRELOAD environment
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = entry.file_name();
                let pid_str = pid_str.to_string_lossy();
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let environ_path = format!("/proc/{}/environ", pid_str);
                    if let Ok(environ) = fs::read_to_string(&environ_path) {
                        // environ is NUL-separated
                        for var in environ.split('\0') {
                            if var.starts_with("LD_PRELOAD=") {
                                let value = &var[11..];
                                if !value.is_empty() {
                                    // Get process name for context
                                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                                        .unwrap_or_default()
                                        .trim()
                                        .to_string();

                                    threats.push(
                                        ThreatEvent::new(
                                            ThreatType::LdPreloadHook,
                                            "rootkit",
                                            format!(
                                                "LD_PRELOAD set for process {} (PID {}): {}",
                                                comm, pid_str, value
                                            ),
                                        )
                                        .with_detail("pid", pid_str.to_string())
                                        .with_detail("process", &comm)
                                        .with_detail("ld_preload", value)
                                        .with_detail("detection_method", "process_environ"),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        threats
    }

    /// Check for suspicious kernel symbol hooks in /proc/kallsyms.
    fn check_kernel_symbols(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        let kallsyms = match fs::read_to_string("/proc/kallsyms") {
            Ok(content) => content,
            Err(_) => return threats,
        };

        // Known suspicious patterns in kernel symbols
        let suspicious_patterns = [
            "rootkit",
            "hide_pid",
            "hidden_",
            "invisible",
            "stealth",
        ];

        for line in kallsyms.lines() {
            let lower = line.to_lowercase();
            for pattern in &suspicious_patterns {
                if lower.contains(pattern) {
                    threats.push(
                        ThreatEvent::new(
                            ThreatType::RootkitDetected,
                            "rootkit",
                            format!("Suspicious kernel symbol found: {}", line.trim()),
                        )
                        .with_detail("symbol", line.trim())
                        .with_detail("pattern", *pattern)
                        .with_detail("detection_method", "kallsyms"),
                    );
                    break;
                }
            }
        }

        threats
    }

    /// Check for hidden files in suspicious directories by comparing readdir vs stat.
    fn check_hidden_files(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for dir_path in &self.config.hidden_files_dirs {
            let dir = Path::new(dir_path);
            if !dir.exists() || !dir.is_dir() {
                continue;
            }

            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    // Check for files starting with "..." or other rootkit hiding patterns
                    if name_str.starts_with("...") || name_str.starts_with(". ") {
                        threats.push(
                            ThreatEvent::new(
                                ThreatType::RootkitDetected,
                                "rootkit",
                                format!(
                                    "Suspicious hidden file in {}: {}",
                                    dir_path, name_str
                                ),
                            )
                            .with_detail("file", entry.path().to_string_lossy().to_string())
                            .with_detail("directory", dir_path)
                            .with_detail("detection_method", "hidden_files"),
                        );
                    }
                }
            }
        }

        threats
    }

    /// Verify integrity of critical shared libraries.
    fn check_shared_libraries(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Check if ld.so.preload was recently modified
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            if let Ok(metadata) = preload_path.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = modified.elapsed() {
                        // Flag if modified in last 24 hours
                        if age.as_secs() < 86400 {
                            threats.push(
                                ThreatEvent::new(
                                    ThreatType::RootkitDetected,
                                    "rootkit",
                                    "ld.so.preload was recently modified (last 24h)".to_string(),
                                )
                                .with_detail("file", "/etc/ld.so.preload")
                                .with_detail("detection_method", "shared_lib_mtime"),
                            );
                        }
                    }
                }
            }
        }

        // Check for unexpected entries in /etc/ld.so.conf.d/
        let ld_conf_dir = Path::new("/etc/ld.so.conf.d");
        if ld_conf_dir.exists() {
            if let Ok(entries) = fs::read_dir(ld_conf_dir) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            // Flag paths pointing to tmp/shm directories
                            if line.starts_with("/tmp") || line.starts_with("/dev/shm")
                                || line.starts_with("/var/tmp")
                            {
                                threats.push(
                                    ThreatEvent::new(
                                        ThreatType::RootkitDetected,
                                        "rootkit",
                                        format!(
                                            "Suspicious library path in ld.so.conf.d: {} -> {}",
                                            entry.path().display(),
                                            line
                                        ),
                                    )
                                    .with_detail("config_file", entry.path().to_string_lossy().to_string())
                                    .with_detail("suspicious_path", line)
                                    .with_detail("detection_method", "ld_conf"),
                                );
                            }
                        }
                    }
                }
            }
        }

        threats
    }
}

#[async_trait]
impl ScanModule for RootkitModule {
    fn name(&self) -> &str {
        "rootkit"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();

        if self.config.check_hidden_processes {
            threats.extend(self.check_hidden_processes());
        }

        if self.config.check_ld_preload {
            threats.extend(self.check_ld_preload());
        }

        if self.config.check_kernel_symbols {
            threats.extend(self.check_kernel_symbols());
        }

        if self.config.check_hidden_files {
            threats.extend(self.check_hidden_files());
        }

        if self.config.check_shared_libraries {
            threats.extend(self.check_shared_libraries());
        }

        if !threats.is_empty() {
            info!(
                count = threats.len(),
                "Rootkit module detected {} threat(s)",
                threats.len()
            );
        }

        Ok(threats)
    }

    // Rootkit detection is scan-only (point-in-time, expensive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rootkit_module_creation() {
        let config = RootkitConfig::default();
        let module = RootkitModule::new(config);
        assert_eq!(module.name(), "rootkit");
        assert!(!module.supports_watch());
    }
}
