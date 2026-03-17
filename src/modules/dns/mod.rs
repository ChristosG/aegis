pub mod entropy;
pub mod tunneling;

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::config::schema::DnsConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;
use crate::util::log_cursor::LogCursors;

pub struct DnsModule {
    config: DnsConfig,
    data_dir: PathBuf,
}

impl DnsModule {
    pub fn new(config: DnsConfig, data_dir: PathBuf) -> Self {
        Self { config, data_dir }
    }

    /// Parse a syslog line for DNS query information.
    /// Matches dnsmasq and systemd-resolved patterns.
    fn parse_dns_query(line: &str) -> Option<DnsQuery> {
        // dnsmasq pattern: "dnsmasq[1234]: query[A] suspicious.example.com from 192.168.1.5"
        if let Some(pos) = line.find("dnsmasq[") {
            if let Some(query_pos) = line[pos..].find("query[") {
                let after_bracket = &line[pos + query_pos + 6..];
                // Extract query type
                let qtype_end = after_bracket.find(']')?;
                let qtype = &after_bracket[..qtype_end];
                let rest = after_bracket[qtype_end + 2..].trim();
                // Domain is first token
                let domain = rest.split_whitespace().next()?;
                // Source IP after "from "
                let source_ip = rest.split(" from ").nth(1).and_then(|s| s.split_whitespace().next());
                return Some(DnsQuery {
                    domain: domain.to_string(),
                    query_type: qtype.to_string(),
                    source_ip: source_ip.map(String::from),
                });
            }
        }

        // systemd-resolved pattern: "systemd-resolved[1234]: ... query suspicious.example.com IN A"
        if line.contains("systemd-resolved[") {
            if let Some(pos) = line.find(" query ") {
                let rest = &line[pos + 7..];
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 3 {
                    return Some(DnsQuery {
                        domain: parts[0].to_string(),
                        query_type: parts.get(2).unwrap_or(&"A").to_string(),
                        source_ip: None,
                    });
                }
            }
        }

        None
    }
}

struct DnsQuery {
    domain: String,
    query_type: String,
    source_ip: Option<String>,
}

#[async_trait]
impl ScanModule for DnsModule {
    fn name(&self) -> &str {
        "dns"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();
        let cursor_path = LogCursors::path_for_module("dns", &self.data_dir);
        let mut cursors = LogCursors::load(&cursor_path);
        let mut domain_counts: HashMap<String, u32> = HashMap::new();
        let mut txt_domains: HashMap<String, u32> = HashMap::new();

        for log_path in &self.config.log_paths {
            let path = std::path::Path::new(log_path);
            if !path.exists() {
                continue;
            }

            let lines = cursors.read_lines(path, 500)?;

            for line in &lines {
                if let Some(query) = Self::parse_dns_query(line) {
                    // Skip whitelisted domains
                    let domain_lower = query.domain.to_lowercase();
                    if self.config.whitelist_domains.iter().any(|w| domain_lower.ends_with(w)) {
                        continue;
                    }

                    // DGA detection: check entropy of domain labels
                    let labels: Vec<&str> = query.domain.split('.').collect();
                    if let Some(sld) = labels.first() {
                        if sld.len() >= self.config.dga_min_length {
                            let ent = entropy::shannon_entropy(sld);
                            if ent > self.config.dga_entropy_threshold {
                                let mut event = ThreatEvent::new(
                                    ThreatType::DgaDomain,
                                    "dns",
                                    format!(
                                        "Possible DGA domain detected: {} (entropy: {:.2})",
                                        query.domain, ent
                                    ),
                                )
                                .with_detail("domain", &query.domain)
                                .with_detail("entropy", format!("{:.2}", ent))
                                .with_detail("query_type", &query.query_type);

                                if let Some(ref ip) = query.source_ip {
                                    if let Ok(addr) = ip.parse() {
                                        event = event.with_source_ip(addr);
                                    }
                                }

                                threats.push(event);
                            }
                        }
                    }

                    // Track query rates for tunneling detection
                    let sld = tunneling::extract_second_level_domain(&query.domain);
                    *domain_counts.entry(sld.clone()).or_insert(0) += 1;

                    if query.query_type == "TXT" {
                        *txt_domains.entry(sld).or_insert(0) += 1;
                    }
                }
            }
        }

        // Tunneling detection: high query rate to single domain, especially TXT
        for (domain, count) in &domain_counts {
            if *count >= self.config.tunnel_query_rate_threshold {
                let txt_count = txt_domains.get(domain).copied().unwrap_or(0);
                let txt_ratio = if *count > 0 {
                    txt_count as f64 / *count as f64
                } else {
                    0.0
                };

                // Flag if high volume OR high TXT ratio
                if *count >= self.config.tunnel_query_rate_threshold * 2 || txt_ratio > 0.3 {
                    threats.push(
                        ThreatEvent::new(
                            ThreatType::DnsTunneling,
                            "dns",
                            format!(
                                "Possible DNS tunneling: {} queries to {} ({} TXT, {:.0}% TXT ratio)",
                                count, domain, txt_count, txt_ratio * 100.0
                            ),
                        )
                        .with_detail("domain", domain)
                        .with_detail("query_count", count.to_string())
                        .with_detail("txt_count", txt_count.to_string()),
                    );
                }
            }
        }

        // Save cursors for incremental reading
        let _ = cursors.save(&cursor_path);

        if !threats.is_empty() {
            info!(count = threats.len(), "DNS module detected {} threat(s)", threats.len());
        }

        Ok(threats)
    }

    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let scan_interval = std::time::Duration::from_secs(60);
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
                        Err(e) => warn!(error = %e, "DNS periodic scan failed"),
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
    fn test_parse_dnsmasq_query() {
        let line = "Mar 17 10:00:01 server dnsmasq[1234]: query[A] evil.example.com from 192.168.1.5";
        let query = DnsModule::parse_dns_query(line).unwrap();
        assert_eq!(query.domain, "evil.example.com");
        assert_eq!(query.query_type, "A");
        assert_eq!(query.source_ip.as_deref(), Some("192.168.1.5"));
    }

    #[test]
    fn test_parse_resolved_query() {
        let line = "Mar 17 10:00:01 server systemd-resolved[456]: Outgoing query suspicious.test.com IN A";
        // Pattern matches " query " substring
        // Need a line that contains "systemd-resolved[" and " query "
        let adjusted_line = "Mar 17 10:00:01 server systemd-resolved[456]: some query suspicious.test.com IN A stuff";
        let query = DnsModule::parse_dns_query(adjusted_line).unwrap();
        assert_eq!(query.domain, "suspicious.test.com");
        assert_eq!(query.query_type, "A");
    }

    #[test]
    fn test_no_match() {
        let line = "Mar 17 10:00:01 server sshd[789]: Accepted publickey for user";
        assert!(DnsModule::parse_dns_query(line).is_none());
    }
}
