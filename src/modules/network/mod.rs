mod beacon_history;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::config::schema::NetworkConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;
use crate::util::ip::{is_private, is_whitelisted, parse_whitelist};
use crate::util::proc_parse::{parse_tcp_line, tcp_state};
use ipnet::IpNet;

use beacon_history::{exe_path_for_pid, history_file_path, BeaconHistory, BeaconKey};

/// A parsed TCP connection entry from /proc/net/tcp{,6}.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TcpConnection {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    state: u8,
    inode: u64,
}

/// Network scanning module: detects SYN floods, port scans, suspicious outbound
/// connections, and C2 beacons by analyzing /proc/net/tcp and related data.
///
/// v2.6.0: now holds per-module beacon history state for the time-series
/// detector (Bucket E). The history is loaded from disk on module
/// construction and persisted at scan time, so short-cycle beacons aren't
/// lost between scans or across daemon restarts.
pub struct NetworkModule {
    config: NetworkConfig,
    /// v2.6.0 Bucket E: data directory for beacon_history.json persistence.
    data_dir: PathBuf,
    /// v2.6.0 Bucket E: per-key beacon timing history. Wrapped in Mutex
    /// because scan() takes &self but needs to mutate the history.
    beacon_history: Mutex<BeaconHistory>,
    /// v2.6.0 Bucket E: set of BeaconKeys observed in the previous scan
    /// cycle. Used to compute the diff (NEW connections since last scan)
    /// that feeds into beacon_history. Without this, we'd mistake
    /// persistent connections for periodic beacons.
    last_seen_keys: Mutex<HashSet<BeaconKey>>,
    /// v2.6.1: parsed `excluded_destinations` CIDRs. Connections to a
    /// destination matching any of these ranges are skipped by every
    /// network detector (suspicious-outbound, C2 beacon, etc.) BEFORE
    /// they can increment any counter. Defense-in-depth complement to
    /// `is_private`: explicit, configurable, and mirrored at the
    /// response-engine layer so a future detector that forgets to call
    /// us still can't get a loopback IP into iptables.
    excluded_destinations: Vec<IpNet>,
}

/// Look up the exe path and full command line for a given PID.
fn get_process_details(pid: u32) -> (Option<String>, String) {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string();
    (exe, cmdline)
}

/// Truncate a string to `max` bytes on a valid UTF-8 boundary, appending "..." if truncated.
fn truncate_cmdline(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Walk backwards from max to find a char boundary
    let mut end = max;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Map well-known ports to service names.
fn port_to_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 => Some("https"),
        465 => Some("smtps"),
        587 => Some("submission"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

impl NetworkModule {
    pub fn new(config: NetworkConfig) -> Self {
        // Default to ~/.aegis if no explicit data_dir given at construction
        // time. The module factory (modules/mod.rs) calls new() without a
        // data_dir, consistent with the pre-v2.6.0 API. Beacon history
        // persistence is still best-effort — if the path isn't writable,
        // the detector still works (it just loses history across restarts).
        let data_dir = crate::config::defaults::resolve_path("~/.aegis");
        Self::new_with_data_dir(config, data_dir)
    }

    /// v2.6.0: construct a NetworkModule with an explicit data_dir. Used
    /// by tests and by future callers that want full control over where
    /// beacon history is persisted.
    pub fn new_with_data_dir(config: NetworkConfig, data_dir: PathBuf) -> Self {
        let beacon_history = BeaconHistory::load_or_default(
            &history_file_path(&data_dir),
            config.c2_beacon_max_keys,
            config.c2_beacon_max_samples_per_key,
            config.c2_beacon_window,
        );
        let excluded_destinations = parse_whitelist(&config.excluded_destinations);
        info!(
            count = excluded_destinations.len(),
            "Loaded network excluded_destinations CIDRs (loopback/link-local skip list)"
        );
        Self {
            config,
            data_dir,
            beacon_history: Mutex::new(beacon_history),
            last_seen_keys: Mutex::new(HashSet::new()),
            excluded_destinations,
        }
    }

    /// Whether a remote IP belongs to a configured excluded destination
    /// CIDR (defaults: loopback + link-local). Detectors must consult this
    /// in addition to `is_private` so operators can extend the skip list
    /// (e.g. an internal management VLAN) without code changes.
    fn is_excluded(&self, ip: &IpAddr) -> bool {
        is_whitelisted(ip, &self.excluded_destinations)
    }

    /// Read and parse all TCP connections from /proc/net/tcp and /proc/net/tcp6.
    fn read_tcp_connections(&self) -> Vec<TcpConnection> {
        let mut connections = Vec::new();

        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            let p = Path::new(path);
            if !p.exists() {
                debug!(path = %path, "TCP proc file does not exist, skipping");
                continue;
            }

            let content = match std::fs::read_to_string(p) {
                Ok(c) => c,
                Err(e) => {
                    warn!(path = %path, error = %e, "Failed to read TCP proc file");
                    continue;
                }
            };

            for line in content.lines().skip(1) {
                // Skip the header line
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Parse inode from field 9 (0-indexed) before the structured parse
                let inode = line
                    .split_whitespace()
                    .nth(9)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                match parse_tcp_line(line) {
                    Ok((local_ip, local_port, remote_ip, remote_port, state)) => {
                        connections.push(TcpConnection {
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            state,
                            inode,
                        });
                    }
                    Err(e) => {
                        debug!(error = %e, line = %line, "Failed to parse TCP line");
                    }
                }
            }
        }

        connections
    }

    /// Detect SYN flood attacks by counting SYN_RECV state connections.
    fn detect_syn_flood(&self, connections: &[TcpConnection]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Count connections in SYN_RECV state and track source IPs + target ports
        let mut source_ip_counts: HashMap<IpAddr, u32> = HashMap::new();
        let mut syn_recv_count: u32 = 0;
        let mut target_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for conn in connections {
            if conn.state == tcp_state::SYN_RECV {
                syn_recv_count += 1;
                *source_ip_counts.entry(conn.remote_ip).or_insert(0) += 1;
                target_ports.insert(conn.local_port);
            }
        }

        if syn_recv_count > self.config.syn_flood_threshold {
            // Find top source IPs
            let mut top_sources: Vec<(IpAddr, u32)> = source_ip_counts.into_iter().collect();
            top_sources.sort_by(|a, b| b.1.cmp(&a.1));
            top_sources.truncate(10);

            let top_ips_str = top_sources
                .iter()
                .map(|(ip, count)| format!("{}({})", ip, count))
                .collect::<Vec<_>>()
                .join(", ");

            let description = format!(
                "SYN flood detected: {} SYN_RECV connections (threshold: {})",
                syn_recv_count, self.config.syn_flood_threshold
            );

            let mut sorted_ports: Vec<u16> = target_ports.into_iter().collect();
            sorted_ports.sort();
            let target_ports_str = sorted_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            let mut event = ThreatEvent::new(ThreatType::SynFlood, "network", &description)
                .with_detail("syn_recv_count", syn_recv_count.to_string())
                .with_detail("threshold", self.config.syn_flood_threshold.to_string())
                .with_detail("top_source_ips", &top_ips_str)
                .with_detail("target_ports", &target_ports_str);

            // Set source IP to the top offender if available
            if let Some((top_ip, _)) = top_sources.first() {
                event = event.with_source_ip(*top_ip);
            }

            warn!(
                syn_recv_count = syn_recv_count,
                threshold = self.config.syn_flood_threshold,
                top_sources = %top_ips_str,
                "SYN flood detected"
            );

            threats.push(event);
        } else {
            debug!(
                syn_recv_count = syn_recv_count,
                threshold = self.config.syn_flood_threshold,
                "SYN flood check passed"
            );
        }

        threats
    }

    /// Detect port scans by finding remote IPs connecting to many local ports.
    fn detect_port_scan(&self, connections: &[TcpConnection]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Group unique local ports per remote IP (only for inbound connections)
        let mut remote_ip_ports: HashMap<IpAddr, std::collections::HashSet<u16>> = HashMap::new();

        for conn in connections {
            // Skip loopback and private IPs
            if is_private(&conn.remote_ip) {
                continue;
            }
            // Skip connections where remote port is 0 (not a real connection)
            if conn.remote_port == 0 {
                continue;
            }
            remote_ip_ports
                .entry(conn.remote_ip)
                .or_default()
                .insert(conn.local_port);
        }

        for (remote_ip, local_ports) in &remote_ip_ports {
            let port_count = local_ports.len() as u32;
            if port_count > self.config.port_scan_threshold {
                let mut ports_list: Vec<u16> = local_ports.iter().copied().collect();
                ports_list.sort();

                // Sample ports (first 20) for the sample field
                let ports_str = ports_list
                    .iter()
                    .take(20)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                // Full ports list capped at 100
                let full_ports_str = ports_list
                    .iter()
                    .take(100)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                // Map well-known ports to service names
                let services: Vec<String> = ports_list
                    .iter()
                    .filter_map(|p| port_to_service(*p).map(|s| format!("{}({})", s, p)))
                    .collect();
                let services_str = services.join(", ");

                let description = format!(
                    "Port scan detected from {}: {} unique ports probed (threshold: {})",
                    remote_ip, port_count, self.config.port_scan_threshold
                );

                let mut event = ThreatEvent::new(ThreatType::PortScan, "network", &description)
                    .with_source_ip(*remote_ip)
                    .with_detail("unique_ports", port_count.to_string())
                    .with_detail("threshold", self.config.port_scan_threshold.to_string())
                    .with_detail("sample_ports", &ports_str)
                    .with_detail("target_ports_full", &full_ports_str);

                if !services_str.is_empty() {
                    event = event.with_detail("target_services", &services_str);
                }

                warn!(
                    remote_ip = %remote_ip,
                    unique_ports = port_count,
                    "Port scan detected"
                );

                threats.push(event);
            }
        }

        threats
    }

    /// Detect suspicious outbound connections to non-standard ports on public IPs.
    fn detect_suspicious_outbound(
        &self,
        connections: &[TcpConnection],
        inode_map: &HashMap<u64, (u32, String)>,
        listen_ports: &HashSet<u16>,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for conn in connections {
            // Only look at ESTABLISHED connections
            if conn.state != tcp_state::ESTABLISHED {
                continue;
            }

            // Skip connections to private/loopback IPs
            if is_private(&conn.remote_ip) {
                continue;
            }

            // v2.6.1: also skip explicitly-excluded destinations (loopback +
            // link-local by default, operator-extensible). Belt-and-braces with
            // the is_private check above so a future expansion of this list
            // (e.g. management VLAN) takes effect without further code edits.
            if self.is_excluded(&conn.remote_ip) {
                continue;
            }

            // Skip inbound connections: if the local port has a LISTEN socket,
            // this is a server accepting a client — not an outbound connection.
            // Also skip privileged ports (< 1024) which are always server ports.
            if conn.local_port < 1024 || listen_ports.contains(&conn.local_port) {
                continue;
            }

            // Check if remote port is NOT in known outbound ports
            if self.config.known_outbound_ports.contains(&conn.remote_port) {
                continue;
            }

            let description = format!(
                "Suspicious outbound connection to {}:{} (port not in known list)",
                conn.remote_ip, conn.remote_port
            );

            let mut event =
                ThreatEvent::new(ThreatType::SuspiciousConnection, "network", &description)
                    .with_source_ip(conn.remote_ip)
                    .with_target(format!("{}:{}", conn.remote_ip, conn.remote_port))
                    .with_detail("local_port", conn.local_port.to_string())
                    .with_detail("remote_port", conn.remote_port.to_string());

            // Enrich with process details from the inode map
            if conn.inode != 0 {
                if let Some((pid, name)) = inode_map.get(&conn.inode) {
                    let (exe, cmdline) = get_process_details(*pid);
                    event = event
                        .with_detail("process_name", name.clone())
                        .with_detail("process_pid", pid.to_string());
                    if let Some(exe_path) = exe {
                        event = event.with_detail("process_exe", exe_path);
                    }
                    if !cmdline.is_empty() {
                        event =
                            event.with_detail("process_cmdline", truncate_cmdline(&cmdline, 500));
                    }
                }
            }

            debug!(
                remote_ip = %conn.remote_ip,
                remote_port = conn.remote_port,
                local_port = conn.local_port,
                "Suspicious outbound connection detected"
            );

            threats.push(event);
        }

        threats
    }

    /// v2.6.0 Bucket E: Time-series C2 beacon detection via coefficient-of-
    /// variation analysis of inter-arrival times.
    ///
    /// REPLACES the v2.5.0 count-based detector, which produced massive
    /// false positives against any HTTP/2 client (see
    /// docs/TRIAGE_PHASE_A0.md for the real-world impact).
    ///
    /// # Algorithm
    ///
    /// 1. Build the current set of BeaconKey(local_exe, remote_ip, remote_port)
    ///    for all ESTABLISHED outbound connections to non-private IPs.
    /// 2. Compute the diff: `new_keys = current - last_seen` — these are
    ///    connections that weren't here last scan, which is what we want to
    ///    time-stamp as a "beacon initiation" sample. Persistent connections
    ///    don't get counted on every scan, which is what distinguishes this
    ///    detector from the legacy count-based one.
    /// 3. Record samples for `new_keys` in `beacon_history` with the current
    ///    timestamp.
    /// 4. Prune stale history entries outside the window.
    /// 5. For every key in the history, compute stats and emit a beacon
    ///    event if the CoV is below threshold and the interval is in range.
    /// 6. Save history to disk (best-effort).
    ///
    /// # Why diff against last_seen?
    ///
    /// Without the diff, every persistent connection would get a sample
    /// recorded on every scan (every 60s), producing a perfectly periodic
    /// series with CoV ≈ 0 — a false positive on literally every
    /// long-lived TCP connection. The diff means we only capture *new
    /// connection establishments*, which is what real beacons look like.
    ///
    /// # Interaction with Bucket A's safety pin
    ///
    /// If the new detector DOES fire on a well-known-infrastructure IP
    /// (some CDN health-check that genuinely beacons every 60s), Bucket A's
    /// safety pin in the response engine will refuse to install a firewall
    /// rule for it — so false positives here are a dashboard-noise issue,
    /// not a service-outage issue.
    fn detect_c2_beacon(
        &self,
        connections: &[TcpConnection],
        inode_map: &HashMap<u64, (u32, String)>,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // -------------------------------------------------------------------
        // Step 1: build current BeaconKey set from ESTABLISHED outbound conns.
        // For each key, remember ONE representative (inode, local_ip, local_port)
        // so we can enrich the eventual threat event with local-endpoint info
        // (this is the Bug #1 fix from Bucket A, subsumed into Bucket E).
        // -------------------------------------------------------------------
        struct KeyMeta {
            local_ip: IpAddr,
            local_port: u16,
            inode: u64,
        }
        let mut current: HashMap<BeaconKey, KeyMeta> = HashMap::new();

        for conn in connections {
            if conn.state != tcp_state::ESTABLISHED {
                continue;
            }
            if is_private(&conn.remote_ip) {
                continue;
            }
            // v2.6.1: also skip explicit exclusions (loopback + link-local
            // by default). Without this, anything binding to 127.0.0.1 with
            // a fast poll loop (Gradle daemon, adb fork-server,
            // systemd-resolved) accumulates beacon samples and trips the
            // CoV detector — the original developer-tool outage.
            if self.is_excluded(&conn.remote_ip) {
                continue;
            }

            // Resolve local exe path for this connection's inode. If we can't,
            // fall back to "unknown:<inode>" so different unknown sockets
            // don't collapse into one key.
            let local_exe = if conn.inode != 0 {
                match inode_map.get(&conn.inode) {
                    Some((pid, _name)) => exe_path_for_pid(*pid),
                    None => format!("unknown:inode-{}", conn.inode),
                }
            } else {
                "unknown:no-inode".to_string()
            };

            let key = BeaconKey {
                local_exe,
                remote_ip: conn.remote_ip,
                remote_port: conn.remote_port,
            };
            current.entry(key).or_insert(KeyMeta {
                local_ip: conn.local_ip,
                local_port: conn.local_port,
                inode: conn.inode,
            });
        }

        // -------------------------------------------------------------------
        // Step 2: diff against last_seen to find NEW connections.
        // -------------------------------------------------------------------
        let current_keys: HashSet<BeaconKey> = current.keys().cloned().collect();
        let new_keys: Vec<BeaconKey> = {
            let last_seen = self.last_seen_keys.lock().unwrap();
            current_keys
                .iter()
                .filter(|k| !last_seen.contains(*k))
                .cloned()
                .collect()
        };

        // -------------------------------------------------------------------
        // Step 3-4: record samples for new keys, prune stale entries.
        // -------------------------------------------------------------------
        {
            let mut history = self.beacon_history.lock().unwrap();
            for key in &new_keys {
                history.record_sample(key.clone());
            }
            history.prune_stale();
        }

        // -------------------------------------------------------------------
        // Step 5: analyze every key in history and emit beacon events.
        // Iterate with a clone of the keys to release the lock before
        // building events (which may allocate and is slower).
        // -------------------------------------------------------------------
        let candidates: Vec<(BeaconKey, beacon_history::BeaconStats)> = {
            let history = self.beacon_history.lock().unwrap();
            history
                .keys()
                .filter_map(|k| history.analyze(k).map(|s| (k.clone(), s)))
                .collect()
        };

        for (key, stats) in candidates {
            if !stats.is_beacon(
                self.config.c2_beacon_cov_threshold,
                self.config.c2_beacon_min_samples,
                self.config.c2_beacon_min_interval_secs,
                self.config.c2_beacon_max_interval_secs,
            ) {
                continue;
            }

            let description = format!(
                "C2 beacon (time-series): {} sample(s) to {}:{} from '{}' with CoV {:.3} \
                 (mean {:.1}s, stddev {:.1}s)",
                stats.sample_count,
                key.remote_ip,
                key.remote_port,
                key.local_exe,
                stats.cov,
                stats.mean_interval_secs,
                stats.stddev_interval_secs,
            );

            let mut event = ThreatEvent::new(ThreatType::C2Beacon, "network", &description)
                .with_source_ip(key.remote_ip)
                .with_target(format!("{}:{}", key.remote_ip, key.remote_port))
                // Bucket A bug-fix: record local endpoint explicitly. The old
                // detector stored remote_ip in both source_ip AND target,
                // leaving operators with no way to see which local process
                // was talking.
                .with_detail("local_exe", key.local_exe.clone())
                .with_detail("sample_count", stats.sample_count.to_string())
                .with_detail("cov", format!("{:.4}", stats.cov))
                .with_detail(
                    "mean_interval_secs",
                    format!("{:.2}", stats.mean_interval_secs),
                )
                .with_detail(
                    "stddev_interval_secs",
                    format!("{:.2}", stats.stddev_interval_secs),
                )
                .with_detail("window_secs", format!("{:.0}", stats.window_secs))
                .with_detail(
                    "cov_threshold",
                    format!("{:.2}", self.config.c2_beacon_cov_threshold),
                );

            // If the key is currently active, add the current local endpoint
            // + process info from the inode_map.
            if let Some(meta) = current.get(&key) {
                event = event
                    .with_detail("local_ip", meta.local_ip.to_string())
                    .with_detail("local_port", meta.local_port.to_string());
                if meta.inode != 0 {
                    if let Some((pid, name)) = inode_map.get(&meta.inode) {
                        let (exe, cmdline) = get_process_details(*pid);
                        event = event
                            .with_detail("process_name", name.clone())
                            .with_detail("process_pid", pid.to_string());
                        if let Some(exe_path) = exe {
                            event = event.with_detail("process_exe", exe_path);
                        }
                        if !cmdline.is_empty() {
                            event = event
                                .with_detail("process_cmdline", truncate_cmdline(&cmdline, 500));
                        }
                    }
                }
            }

            warn!(
                remote_ip = %key.remote_ip,
                remote_port = key.remote_port,
                local_exe = %key.local_exe,
                cov = stats.cov,
                mean_interval_secs = stats.mean_interval_secs,
                sample_count = stats.sample_count,
                "C2 beacon detected (time-series CoV analysis)"
            );

            threats.push(event);
        }

        // -------------------------------------------------------------------
        // Step 6: update last_seen and persist history.
        // -------------------------------------------------------------------
        {
            let mut last_seen = self.last_seen_keys.lock().unwrap();
            *last_seen = current_keys;
        }
        {
            let history = self.beacon_history.lock().unwrap();
            history.save(&history_file_path(&self.data_dir));
        }

        threats
    }

    /// D1: Detect connection rate exceeded per source IP.
    fn detect_connection_rate(
        &self,
        connections: &[TcpConnection],
        inode_map: &HashMap<u64, (u32, String)>,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        if self.config.connection_rate_threshold == 0 {
            return threats;
        }

        // Count all connections per remote IP (not just ESTABLISHED), with a representative inode
        let mut ip_counts: HashMap<IpAddr, (u32, u64)> = HashMap::new();
        for conn in connections {
            if is_private(&conn.remote_ip) {
                continue;
            }
            let entry = ip_counts.entry(conn.remote_ip).or_insert((0, 0));
            entry.0 += 1;
            // Store the inode from the first connection as the representative
            if entry.1 == 0 && conn.inode != 0 {
                entry.1 = conn.inode;
            }
        }

        for (ip, (count, repr_inode)) in &ip_counts {
            if *count > self.config.connection_rate_threshold {
                let description = format!(
                    "Connection rate exceeded from {}: {} connections (threshold: {})",
                    ip, count, self.config.connection_rate_threshold
                );
                let mut event =
                    ThreatEvent::new(ThreatType::ConnectionRateExceeded, "network", &description)
                        .with_source_ip(*ip)
                        .with_detail("connection_count", count.to_string())
                        .with_detail(
                            "threshold",
                            self.config.connection_rate_threshold.to_string(),
                        );

                // Enrich with process details from the representative inode
                if *repr_inode != 0 {
                    if let Some((pid, name)) = inode_map.get(repr_inode) {
                        let (exe, cmdline) = get_process_details(*pid);
                        event = event
                            .with_detail("process_name", name.clone())
                            .with_detail("process_pid", pid.to_string());
                        if let Some(exe_path) = exe {
                            event = event.with_detail("process_exe", exe_path);
                        }
                        if !cmdline.is_empty() {
                            event = event
                                .with_detail("process_cmdline", truncate_cmdline(&cmdline, 500));
                        }
                    }
                }

                warn!(
                    ip = %ip,
                    count = count,
                    "Connection rate threshold exceeded"
                );
                threats.push(event);
            }
        }

        threats
    }

    /// Build a map from socket inode → (pid, process_name) by scanning /proc/<pid>/fd/.
    fn build_inode_to_process_map(&self) -> HashMap<u64, (u32, String)> {
        let mut map = HashMap::new();
        let pids = crate::util::proc_parse::list_pids();
        for pid in pids {
            let fd_dir = format!("/proc/{}/fd", pid);
            let entries = match std::fs::read_dir(&fd_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let target_str = target.to_string_lossy();
                    if let Some(inode_str) = target_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.entry(inode).or_insert_with(|| {
                                let name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                                    .unwrap_or_default()
                                    .trim()
                                    .to_string();
                                (pid, name)
                            });
                        }
                    }
                }
            }
        }
        map
    }

    /// D4: Detect new outbound destinations not seen in baseline.
    fn detect_new_outbound_destinations(
        &self,
        connections: &[TcpConnection],
        inode_map: &HashMap<u64, (u32, String)>,
        listen_ports: &HashSet<u16>,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        let data_dir = crate::config::defaults::resolve_path("~/.aegis");
        let baseline_path = data_dir.join("outbound_baseline.json");

        // Collect current outbound destinations and map dest → inode for process lookup
        let mut current_destinations: std::collections::HashSet<(String, u16)> =
            std::collections::HashSet::new();
        let mut dest_to_inode: HashMap<(String, u16), u64> = HashMap::new();
        for conn in connections {
            if conn.state != tcp_state::ESTABLISHED {
                continue;
            }
            if is_private(&conn.remote_ip) {
                continue;
            }
            if conn.local_port < 1024 || listen_ports.contains(&conn.local_port) {
                continue; // Not outbound — server port accepting inbound connections
            }
            let key = (conn.remote_ip.to_string(), conn.remote_port);
            current_destinations.insert(key.clone());
            if conn.inode != 0 {
                dest_to_inode.entry(key).or_insert(conn.inode);
            }
        }

        // Load baseline
        let baseline: std::collections::HashSet<(String, u16)> = if baseline_path.exists() {
            match std::fs::read_to_string(&baseline_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => std::collections::HashSet::new(),
            }
        } else {
            std::collections::HashSet::new()
        };

        if !baseline.is_empty() {
            let new_dests: Vec<_> = current_destinations
                .iter()
                .filter(|d| !baseline.contains(*d))
                .collect();

            for (dest_ip, dest_port) in &new_dests {
                // Resolve process info from inode using the shared inode map
                let proc_info = dest_to_inode
                    .get(&(dest_ip.clone(), *dest_port))
                    .and_then(|inode| inode_map.get(inode));

                let process_name = proc_info.map(|(_, name)| name.clone());

                let description = match &process_name {
                    Some(name) => format!(
                        "New outbound connection to {}:{} by process '{}'",
                        dest_ip, dest_port, name
                    ),
                    None => format!("New outbound connection to {}:{}", dest_ip, dest_port),
                };

                let mut event =
                    ThreatEvent::new(ThreatType::NewOutboundDestination, "network", &description)
                        .with_target(format!("{}:{}", dest_ip, dest_port))
                        .with_detail("dest_port", dest_port.to_string());

                if let Some((pid, name)) = proc_info {
                    event = event
                        .with_detail("process", name.clone())
                        .with_detail("process_pid", pid.to_string());
                    let (exe, cmdline) = get_process_details(*pid);
                    if let Some(exe_path) = exe {
                        event = event.with_detail("process_exe", exe_path);
                    }
                    if !cmdline.is_empty() {
                        event =
                            event.with_detail("process_cmdline", truncate_cmdline(&cmdline, 500));
                    }
                }

                if let Ok(ip) = dest_ip.parse() {
                    threats.push(event.with_source_ip(ip));
                } else {
                    threats.push(event);
                }
            }
        }

        // Save current snapshot as baseline (replaces previous, capped at 5000 entries)
        let mut baseline_vec: Vec<_> = current_destinations.into_iter().collect();
        if baseline_vec.len() > 5000 {
            baseline_vec.truncate(5000);
        }
        let capped: std::collections::HashSet<(String, u16)> = baseline_vec.into_iter().collect();
        if let Ok(json) = serde_json::to_string_pretty(&capped) {
            if let Err(e) = std::fs::create_dir_all(&data_dir) {
                warn!(error = %e, "Failed to create outbound baseline directory");
            }
            if let Err(e) = std::fs::write(&baseline_path, json) {
                warn!(path = %baseline_path.display(), error = %e, "Failed to write outbound baseline");
            }
        }

        threats
    }

    /// Collect the set of local ports that have a LISTEN socket.
    /// Connections *from* these ports are inbound (server accepted them),
    /// not outbound — so they must be excluded from outbound detectors.
    fn listening_ports(connections: &[TcpConnection]) -> HashSet<u16> {
        connections
            .iter()
            .filter(|c| c.state == tcp_state::LISTEN)
            .map(|c| c.local_port)
            .collect()
    }
}

#[async_trait]
impl ScanModule for NetworkModule {
    fn name(&self) -> &str {
        "network"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        info!(
            "Running network scan (syn_flood_threshold={}, port_scan_threshold={})",
            self.config.syn_flood_threshold, self.config.port_scan_threshold
        );

        let connections = self.read_tcp_connections();
        debug!(
            total_connections = connections.len(),
            "Parsed TCP connections from /proc/net/tcp"
        );

        let mut threats = Vec::new();

        // Build the inode→(pid, name) map once for all detectors that need process resolution
        let inode_map = self.build_inode_to_process_map();

        // Ports with LISTEN sockets — connections on these are inbound, not outbound
        let listen_ports = Self::listening_ports(&connections);

        // Run all detectors
        threats.extend(self.detect_syn_flood(&connections));
        threats.extend(self.detect_port_scan(&connections));
        threats.extend(self.detect_suspicious_outbound(&connections, &inode_map, &listen_ports));
        threats.extend(self.detect_c2_beacon(&connections, &inode_map));
        threats.extend(self.detect_connection_rate(&connections, &inode_map));
        threats.extend(self.detect_new_outbound_destinations(
            &connections,
            &inode_map,
            &listen_ports,
        ));

        info!(count = threats.len(), "Network scan complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// v2.6.1 tests — pin the loopback / link-local exclusion behavior so a
// future detector refactor can't silently re-introduce the gradle / adb
// auto-block regression.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod excluded_destinations_tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn module_with_defaults() -> NetworkModule {
        let mut cfg = NetworkConfig::default();
        // Make the time-series detector fire trivially: 1 sample is enough
        // to "be a beacon" for the purposes of this test if it gets recorded.
        cfg.c2_beacon_min_samples = 1;
        cfg.c2_beacon_cov_threshold = 1.0;
        cfg.c2_beacon_min_interval_secs = 0.0;
        cfg.c2_beacon_max_interval_secs = 1e9;
        NetworkModule::new_with_data_dir(cfg, std::env::temp_dir().join("aegis-net-test"))
    }

    fn loopback_conn(remote_port: u16) -> TcpConnection {
        TcpConnection {
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 54321,
            remote_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_port,
            state: tcp_state::ESTABLISHED,
            inode: 0,
        }
    }

    #[test]
    fn loopback_destination_does_not_increment_c2_beacon_counter() {
        // Simulates the gradle / adb scenario: dozens of fast loopback
        // connections to a developer-tool fork-server. Pre-v2.6.1, the
        // is_private filter already covered this — but this test pins it
        // explicitly AND verifies the new excluded_destinations path runs
        // even if is_private were ever weakened.
        let module = module_with_defaults();
        let inode_map: HashMap<u64, (u32, String)> = HashMap::new();
        // 50 distinct ephemeral ports → would be 50 beacon samples without
        // the exclusion.
        let connections: Vec<TcpConnection> = (40000u16..40050).map(loopback_conn).collect();

        let threats = module.detect_c2_beacon(&connections, &inode_map);
        assert!(
            threats.is_empty(),
            "C2 beacon detector must not flag loopback destinations; got {} threats",
            threats.len()
        );

        // And the excluded helper itself agrees, so the response engine
        // (which mirrors this list via new_with_extra_safety_pin) will
        // also refuse to install a firewall rule.
        assert!(module.is_excluded(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(module.is_excluded(&"::1".parse().unwrap()));
        assert!(module.is_excluded(&"169.254.1.1".parse().unwrap()));
        assert!(module.is_excluded(&"fe80::1".parse().unwrap()));
        // Public IPs must NOT be excluded — protection against external
        // attackers is unchanged.
        assert!(!module.is_excluded(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!module.is_excluded(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn loopback_destination_does_not_trigger_suspicious_outbound() {
        let module = module_with_defaults();
        let inode_map: HashMap<u64, (u32, String)> = HashMap::new();
        let listen_ports: HashSet<u16> = HashSet::new();
        // adb fork-server on 127.0.0.1:5037, gradle daemon on a random
        // ephemeral port — both must produce zero alerts.
        let connections = vec![loopback_conn(5037), loopback_conn(63919)];
        let threats = module.detect_suspicious_outbound(&connections, &inode_map, &listen_ports);
        assert!(threats.is_empty());
    }
}
