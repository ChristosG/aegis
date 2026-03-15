use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::config::schema::NetworkConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;
use crate::util::ip::is_private;
use crate::util::proc_parse::{parse_tcp_line, tcp_state};

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
pub struct NetworkModule {
    config: NetworkConfig,
}

impl NetworkModule {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
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

        // Count connections in SYN_RECV state and track source IPs
        let mut source_ip_counts: HashMap<IpAddr, u32> = HashMap::new();
        let mut syn_recv_count: u32 = 0;

        for conn in connections {
            if conn.state == tcp_state::SYN_RECV {
                syn_recv_count += 1;
                *source_ip_counts.entry(conn.remote_ip).or_insert(0) += 1;
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

            let mut event = ThreatEvent::new(ThreatType::SynFlood, "network", &description)
                .with_detail("syn_recv_count", syn_recv_count.to_string())
                .with_detail("threshold", self.config.syn_flood_threshold.to_string())
                .with_detail("top_source_ips", &top_ips_str);

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
                let ports_str = ports_list
                    .iter()
                    .take(20)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                let description = format!(
                    "Port scan detected from {}: {} unique ports probed (threshold: {})",
                    remote_ip, port_count, self.config.port_scan_threshold
                );

                let event = ThreatEvent::new(ThreatType::PortScan, "network", &description)
                    .with_source_ip(*remote_ip)
                    .with_detail("unique_ports", port_count.to_string())
                    .with_detail("threshold", self.config.port_scan_threshold.to_string())
                    .with_detail("sample_ports", &ports_str);

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
    fn detect_suspicious_outbound(&self, connections: &[TcpConnection]) -> Vec<ThreatEvent> {
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

            // Outbound connection: local port is ephemeral (>= 1024) and we initiated it
            if conn.local_port < 1024 {
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

            let event = ThreatEvent::new(ThreatType::SuspiciousConnection, "network", &description)
                .with_source_ip(conn.remote_ip)
                .with_target(format!("{}:{}", conn.remote_ip, conn.remote_port))
                .with_detail("local_port", conn.local_port.to_string())
                .with_detail("remote_port", conn.remote_port.to_string());

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

    /// Detect potential C2 beacon patterns by looking for multiple connections
    /// to the same remote IP:port.
    fn detect_c2_beacon(&self, connections: &[TcpConnection]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Count ESTABLISHED connections to each remote IP:port pair
        let mut endpoint_counts: HashMap<(IpAddr, u16), u32> = HashMap::new();

        for conn in connections {
            if conn.state != tcp_state::ESTABLISHED {
                continue;
            }
            // Skip private/loopback IPs
            if is_private(&conn.remote_ip) {
                continue;
            }

            *endpoint_counts
                .entry((conn.remote_ip, conn.remote_port))
                .or_insert(0) += 1;
        }

        for ((remote_ip, remote_port), count) in &endpoint_counts {
            if *count > self.config.c2_beacon_threshold {
                let description = format!(
                    "Potential C2 beacon: {} connections to {}:{} (threshold: {})",
                    count, remote_ip, remote_port, self.config.c2_beacon_threshold
                );

                let event = ThreatEvent::new(ThreatType::C2Beacon, "network", &description)
                    .with_source_ip(*remote_ip)
                    .with_target(format!("{}:{}", remote_ip, remote_port))
                    .with_detail("connection_count", count.to_string())
                    .with_detail("threshold", self.config.c2_beacon_threshold.to_string());

                warn!(
                    remote_ip = %remote_ip,
                    remote_port = remote_port,
                    connection_count = count,
                    "Potential C2 beacon detected"
                );

                threats.push(event);
            }
        }

        threats
    }

    /// D1: Detect connection rate exceeded per source IP.
    fn detect_connection_rate(&self, connections: &[TcpConnection]) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        if self.config.connection_rate_threshold == 0 {
            return threats;
        }

        // Count all connections per remote IP (not just ESTABLISHED)
        let mut ip_counts: HashMap<IpAddr, u32> = HashMap::new();
        for conn in connections {
            if is_private(&conn.remote_ip) {
                continue;
            }
            *ip_counts.entry(conn.remote_ip).or_insert(0) += 1;
        }

        for (ip, count) in &ip_counts {
            if *count > self.config.connection_rate_threshold {
                let description = format!(
                    "Connection rate exceeded from {}: {} connections (threshold: {})",
                    ip, count, self.config.connection_rate_threshold
                );
                let event =
                    ThreatEvent::new(ThreatType::ConnectionRateExceeded, "network", &description)
                        .with_source_ip(*ip)
                        .with_detail("connection_count", count.to_string())
                        .with_detail(
                            "threshold",
                            self.config.connection_rate_threshold.to_string(),
                        );

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

    /// Build a map from socket inode → process name by scanning /proc/<pid>/fd/.
    fn build_inode_to_process_map(&self) -> HashMap<u64, String> {
        let mut map = HashMap::new();
        let pids = crate::util::proc_parse::list_pids();
        for pid in pids {
            let fd_dir = format!("/proc/{}/fd", pid);
            let entries = match std::fs::read_dir(&fd_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let mut has_socket = false;
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let target_str = target.to_string_lossy();
                    if let Some(inode_str) = target_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            if !has_socket {
                                has_socket = true;
                            }
                            map.entry(inode).or_insert_with(|| {
                                std::fs::read_to_string(format!("/proc/{}/comm", pid))
                                    .unwrap_or_default()
                                    .trim()
                                    .to_string()
                            });
                        }
                    }
                }
            }
        }
        map
    }

    /// D4: Detect new outbound destinations not seen in baseline.
    fn detect_new_outbound_destinations(&self, connections: &[TcpConnection]) -> Vec<ThreatEvent> {
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
            if conn.local_port < 1024 {
                continue; // Not outbound
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
            // Only build the process map if we have new destinations to report
            let new_dests: Vec<_> = current_destinations
                .iter()
                .filter(|d| !baseline.contains(*d))
                .collect();

            let inode_map = if !new_dests.is_empty() {
                self.build_inode_to_process_map()
            } else {
                HashMap::new()
            };

            for (dest_ip, dest_port) in &new_dests {
                // Resolve process name from inode
                let process_name = dest_to_inode
                    .get(&(dest_ip.clone(), *dest_port))
                    .and_then(|inode| inode_map.get(inode))
                    .cloned();

                let description = match &process_name {
                    Some(name) => format!(
                        "New outbound connection to {}:{} by process '{}'",
                        dest_ip, dest_port, name
                    ),
                    None => format!(
                        "New outbound connection to {}:{}",
                        dest_ip, dest_port
                    ),
                };

                let mut event = ThreatEvent::new(
                    ThreatType::NewOutboundDestination,
                    "network",
                    &description,
                )
                .with_target(format!("{}:{}", dest_ip, dest_port))
                .with_detail("dest_port", dest_port.to_string());

                if let Some(name) = &process_name {
                    event = event.with_detail("process", name.clone());
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
            let _ = std::fs::create_dir_all(&data_dir);
            let _ = std::fs::write(&baseline_path, json);
        }

        threats
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

        // Run all detectors
        threats.extend(self.detect_syn_flood(&connections));
        threats.extend(self.detect_port_scan(&connections));
        threats.extend(self.detect_suspicious_outbound(&connections));
        threats.extend(self.detect_c2_beacon(&connections));
        threats.extend(self.detect_connection_rate(&connections));
        threats.extend(self.detect_new_outbound_destinations(&connections));

        info!(count = threats.len(), "Network scan complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        false
    }
}
