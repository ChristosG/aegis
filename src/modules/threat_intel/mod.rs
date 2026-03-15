use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use tracing::{debug, info, warn};

use crate::config::defaults::resolve_path;
use crate::config::schema::{FeedConfig, ThreatIntelConfig};
use crate::core::state::IpLookup;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};
use crate::modules::ScanModule;
use crate::util::ip::is_private;
use crate::util::proc_parse::parse_tcp_line;

/// Threat intelligence module: cross-references active connections and
/// logged IPs against curated threat intelligence feeds (FireHOL, Spamhaus,
/// blocklist.de, etc.) to identify communications with known-malicious hosts.
pub struct ThreatIntelModule {
    config: ThreatIntelConfig,
}

impl ThreatIntelModule {
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self { config }
    }

    /// Return the resolved feed cache directory, creating it if necessary.
    fn feed_cache_dir(&self) -> Result<PathBuf> {
        let dir = resolve_path(&self.config.feed_dir);
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create feed cache dir: {}", dir.display()))?;
        }
        Ok(dir)
    }

    /// Return the cache file path for a given feed name.
    fn feed_cache_path(&self, feed_name: &str) -> Result<PathBuf> {
        let dir = self.feed_cache_dir()?;
        Ok(dir.join(format!("{}.txt", feed_name)))
    }

    /// Check whether a cached feed file is stale (older than 24 hours).
    fn is_feed_stale(path: &Path) -> bool {
        if !path.exists() {
            return true;
        }

        match path.metadata().and_then(|m| m.modified()) {
            Ok(modified) => {
                let age = modified.elapsed().unwrap_or(Duration::from_secs(u64::MAX));
                age > Duration::from_secs(24 * 3600)
            }
            Err(_) => true,
        }
    }

    /// Download feeds that are stale or missing. Uses reqwest async client.
    async fn refresh_feeds(&self) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        for (feed_name, feed_config) in &self.config.feeds {
            if !feed_config.enabled {
                debug!(feed = %feed_name, "Feed disabled, skipping download");
                continue;
            }

            let cache_path = match self.feed_cache_path(feed_name) {
                Ok(p) => p,
                Err(e) => {
                    warn!(feed = %feed_name, error = %e, "Cannot determine cache path");
                    continue;
                }
            };

            if !Self::is_feed_stale(&cache_path) {
                debug!(feed = %feed_name, "Feed cache is fresh, skipping download");
                continue;
            }

            info!(feed = %feed_name, url = %feed_config.url, "Downloading threat feed");

            match Self::download_feed(&client, feed_config).await {
                Ok(body) => {
                    if let Err(e) = std::fs::write(&cache_path, &body) {
                        warn!(
                            feed = %feed_name,
                            error = %e,
                            "Failed to write feed cache file"
                        );
                    } else {
                        info!(
                            feed = %feed_name,
                            bytes = body.len(),
                            "Feed downloaded and cached"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        feed = %feed_name,
                        error = %e,
                        "Failed to download feed, using stale cache if available"
                    );
                }
            }
        }

        Ok(())
    }

    /// Download a single feed and return its body as a string.
    async fn download_feed(client: &reqwest::Client, feed_config: &FeedConfig) -> Result<String> {
        let mut request = client.get(&feed_config.url);

        if let Some(ref api_key) = feed_config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("HTTP request failed for {}", feed_config.url))?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "Feed download returned HTTP {}: {}",
                status,
                feed_config.url
            );
        }

        let body = response
            .text()
            .await
            .with_context(|| format!("Failed to read response body from {}", feed_config.url))?;

        Ok(body)
    }

    /// Parse all cached feeds into an IpLookup structure.
    fn build_ip_lookup(&self) -> Result<IpLookup> {
        let mut lookup = IpLookup::new();

        for (feed_name, feed_config) in &self.config.feeds {
            if !feed_config.enabled {
                continue;
            }

            let cache_path = match self.feed_cache_path(feed_name) {
                Ok(p) => p,
                Err(e) => {
                    warn!(feed = %feed_name, error = %e, "Cannot determine cache path");
                    continue;
                }
            };

            if !cache_path.exists() {
                debug!(feed = %feed_name, "No cache file found, skipping");
                continue;
            }

            let content = match std::fs::read_to_string(&cache_path) {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        feed = %feed_name,
                        error = %e,
                        "Failed to read feed cache file"
                    );
                    continue;
                }
            };

            let mut count = 0u64;
            for line in content.lines() {
                let line = line.trim();

                // Skip empty lines and comments
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }

                // Some feeds (e.g., Spamhaus DROP) have format: "IP ; SB_ID"
                // or "IP/CIDR ; comment" - extract the first token before any separator
                let token = line.split([';', ' ', '\t']).next().unwrap_or("").trim();

                if token.is_empty() {
                    continue;
                }

                // Try parsing as CIDR first, then as plain IP
                if token.contains('/') {
                    match token.parse::<IpNet>() {
                        Ok(network) => {
                            // For small networks, enumerate IPs; for large ones, just
                            // add the network address as a representative.
                            let prefix_len = match network {
                                IpNet::V4(net) => net.prefix_len(),
                                IpNet::V6(net) => net.prefix_len(),
                            };

                            // Only enumerate for /24 and smaller (up to 256 IPs for v4)
                            if (network.addr().is_ipv4() && prefix_len >= 24)
                                || (network.addr().is_ipv6() && prefix_len >= 120)
                            {
                                for ip in network.hosts() {
                                    lookup.insert(ip, feed_name.clone(), feed_config.weight);
                                    count += 1;
                                }
                            } else {
                                // For larger ranges, store as CIDR for containment checks
                                lookup.insert_cidr(network, feed_name.clone(), feed_config.weight);
                                count += 1;
                            }
                        }
                        Err(e) => {
                            debug!(
                                feed = %feed_name,
                                token = %token,
                                error = %e,
                                "Failed to parse CIDR"
                            );
                        }
                    }
                } else {
                    match token.parse::<IpAddr>() {
                        Ok(ip) => {
                            lookup.insert(ip, feed_name.clone(), feed_config.weight);
                            count += 1;
                        }
                        Err(e) => {
                            debug!(
                                feed = %feed_name,
                                token = %token,
                                error = %e,
                                "Failed to parse IP"
                            );
                        }
                    }
                }
            }

            info!(
                feed = %feed_name,
                entries = count,
                "Parsed threat intel feed"
            );
        }

        info!(
            total_ips = lookup.len(),
            "Built threat intel IP lookup table"
        );

        Ok(lookup)
    }

    /// Read current TCP connections from /proc/net/tcp and /proc/net/tcp6.
    fn read_active_connections(&self) -> Vec<(IpAddr, u16, IpAddr, u16)> {
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
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match parse_tcp_line(line) {
                    Ok((local_ip, local_port, remote_ip, remote_port, _state)) => {
                        connections.push((local_ip, local_port, remote_ip, remote_port));
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to parse TCP line");
                    }
                }
            }
        }

        connections
    }

    /// Cross-reference active connections against the IP lookup table.
    fn check_connections(
        &self,
        connections: &[(IpAddr, u16, IpAddr, u16)],
        lookup: &IpLookup,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        // Track remote IPs we've already reported to avoid duplicates
        let mut reported: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();

        for &(local_ip, local_port, remote_ip, remote_port) in connections {
            // Skip private/loopback and unspecified addresses
            if is_private(&remote_ip) {
                continue;
            }

            // Skip if we already reported this remote IP
            if reported.contains(&remote_ip) {
                continue;
            }

            if let Some((max_weight, feeds)) = lookup.lookup_with_details(&remote_ip) {
                reported.insert(remote_ip);

                // Get the feed details for this IP
                let feed_details = feeds
                    .iter()
                    .map(|(name, weight)| format!("{}({})", name, weight))
                    .collect::<Vec<_>>()
                    .join(", ");

                let feed_names: Vec<&str> = feeds.iter().map(|(name, _)| name.as_str()).collect();

                // Check if this is a Tor exit node (special handling)
                let is_tor = feed_names
                    .iter()
                    .any(|name| name.contains("tor") || name.contains("Tor"));

                if is_tor {
                    let description = format!(
                        "Connection from/to Tor exit node: {} (local {}:{})",
                        remote_ip, local_ip, local_port
                    );

                    let event = ThreatEvent::new(ThreatType::TorExit, "threat_intel", &description)
                        .with_severity(ThreatSeverity::Info)
                        .with_source_ip(remote_ip)
                        .with_target(format!("{}:{}", local_ip, local_port))
                        .with_detail("feeds", &feed_details)
                        .with_detail("max_weight", max_weight.to_string())
                        .with_detail("remote_port", remote_port.to_string());

                    info!(
                        remote_ip = %remote_ip,
                        feeds = %feed_details,
                        "Tor exit node connection detected"
                    );

                    threats.push(event);
                } else {
                    let description = format!(
                        "Connection to known malicious IP: {} (feeds: {}, max_weight: {})",
                        remote_ip, feed_details, max_weight
                    );

                    let event = ThreatEvent::new(
                        ThreatType::ThreatIntelMatch,
                        "threat_intel",
                        &description,
                    )
                    .with_source_ip(remote_ip)
                    .with_target(format!("{}:{}", local_ip, local_port))
                    .with_detail("feeds", &feed_details)
                    .with_detail("max_weight", max_weight.to_string())
                    .with_detail("remote_port", remote_port.to_string())
                    .with_detail("local_port", local_port.to_string());

                    warn!(
                        remote_ip = %remote_ip,
                        feeds = %feed_details,
                        max_weight = max_weight,
                        "Threat intel match detected"
                    );

                    threats.push(event);
                }
            }
        }

        threats
    }
}

#[async_trait]
impl ScanModule for ThreatIntelModule {
    fn name(&self) -> &str {
        "threat_intel"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        info!(
            "Running threat intel scan (feeds={}, update_on_scan={})",
            self.config.feeds.len(),
            self.config.update_on_scan
        );

        // Step 1: Optionally download/refresh feeds
        if self.config.update_on_scan {
            if let Err(e) = self.refresh_feeds().await {
                warn!(error = %e, "Failed to refresh threat intel feeds, using cached data");
            }
        }

        // Step 2: Parse all feeds into IpLookup
        let lookup = self.build_ip_lookup()?;

        if lookup.is_empty() {
            info!("No threat intel data loaded, skipping connection check");
            return Ok(Vec::new());
        }

        // Step 3: Read current connections
        let connections = self.read_active_connections();
        debug!(
            total_connections = connections.len(),
            "Read active TCP connections"
        );

        // Step 4: Cross-reference
        let threats = self.check_connections(&connections, &lookup);

        info!(count = threats.len(), "Threat intel scan complete");
        Ok(threats)
    }
}
