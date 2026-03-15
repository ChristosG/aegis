use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;

use crate::config::schema::WebConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;
use crate::util::log_cursor::LogCursors;

/// Web application security module: parses web server access logs to detect
/// DDoS attacks, SQL injection attempts, path traversal attacks, and
/// known vulnerability scanners.
pub struct WebModule {
    config: WebConfig,
}

impl WebModule {
    pub fn new(config: WebConfig) -> Self {
        Self { config }
    }
}

/// Parsed representation of a single nginx combined log entry.
#[derive(Debug)]
struct AccessLogEntry {
    ip: String,
    timestamp: String,
    request: String,
    status: u16,
    _bytes: u64,
    _referer: String,
    user_agent: String,
}

/// Common scanner paths that indicate automated probing.
const SCANNER_PATHS: &[&str] = &[
    "/wp-admin",
    "/wp-login.php",
    "/.env",
    "/phpinfo.php",
    "/phpmyadmin",
    "/admin",
    "/.git",
    "/actuator",
    "/console",
    "/manager/html",
    "/solr",
    "/api/v1",
    "/debug",
    "/.well-known",
    "/server-status",
    "/server-info",
];

/// Compiled set of regexes and patterns for web log analysis.
struct WebPatterns {
    access_log: Regex,
    sqli_patterns: Vec<Regex>,
    traversal_patterns: Vec<Regex>,
}

impl WebPatterns {
    fn compile() -> Self {
        let access_log = Regex::new(
            r#"^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "([^"]*)" "([^"]*)""#,
        )
        .expect("access log regex");

        let sqli_patterns = vec![
            Regex::new(r"(?i)union\s+(all\s+)?select").expect("sqli union select"),
            Regex::new(r"(?i)'\s*or\s+1\s*=\s*1").expect("sqli or 1=1"),
            Regex::new(r"(?i)'\s*or\s+'1'\s*=\s*'1").expect("sqli or '1'='1'"),
            Regex::new(r"(?i)';\s*drop\s+table").expect("sqli drop table"),
            Regex::new(r"(?i)';\s*delete\s+from").expect("sqli delete from"),
            Regex::new(r"(?i)\band\s+1\s*=\s*1\b").expect("sqli and 1=1"),
            Regex::new(r"(?i)\bor\s+1\s*=\s*1\b").expect("sqli or 1=1 bare"),
            Regex::new(r"(?i)sleep\s*\(").expect("sqli sleep"),
            Regex::new(r"(?i)benchmark\s*\(").expect("sqli benchmark"),
            Regex::new(r"(?i)waitfor\s+delay").expect("sqli waitfor"),
            Regex::new(r"(?i)information_schema").expect("sqli information_schema"),
            Regex::new(r"(?i)table_name").expect("sqli table_name"),
            Regex::new(r"(?i)column_name").expect("sqli column_name"),
            Regex::new(r"--\s*$").expect("sqli comment"),
            Regex::new(r"/\*").expect("sqli block comment"),
        ];

        let traversal_patterns = vec![
            Regex::new(r"\.\.(/|\\)").expect("traversal ../ or ..\\"),
            Regex::new(r"(?i)/etc/passwd").expect("traversal /etc/passwd"),
            Regex::new(r"(?i)/etc/shadow").expect("traversal /etc/shadow"),
            Regex::new(r"(?i)/proc/self").expect("traversal /proc/self"),
            Regex::new(r"(?i)/proc/version").expect("traversal /proc/version"),
            Regex::new(r"(?i)%2e%2e").expect("traversal url-encoded .."),
            Regex::new(r"(?i)%00").expect("traversal null byte"),
        ];

        Self {
            access_log,
            sqli_patterns,
            traversal_patterns,
        }
    }

    /// Parse a single nginx combined log line.
    fn parse_line(&self, line: &str) -> Option<AccessLogEntry> {
        let caps = self.access_log.captures(line)?;
        let status: u16 = caps[4].parse().ok()?;
        let bytes: u64 = caps[5].parse().unwrap_or(0);

        Some(AccessLogEntry {
            ip: caps[1].to_string(),
            timestamp: caps[2].to_string(),
            request: caps[3].to_string(),
            status,
            _bytes: bytes,
            _referer: caps[6].to_string(),
            user_agent: caps[7].to_string(),
        })
    }

    /// Check if a request URI contains SQL injection patterns.
    /// Normalizes URL-encoded spaces (`+` and `%20`) before matching.
    fn is_sqli(&self, request: &str) -> bool {
        let normalized = normalize_url_encoding(request);
        self.sqli_patterns.iter().any(|re| re.is_match(&normalized))
    }

    /// Check if a request URI contains path traversal patterns.
    fn is_path_traversal(&self, request: &str) -> bool {
        self.traversal_patterns
            .iter()
            .any(|re| re.is_match(request))
    }
}

/// Extract the request path from a full request line like "GET /path HTTP/1.1".
fn extract_request_path(request: &str) -> &str {
    // The request is typically "METHOD /path HTTP/version"
    // Extract the path portion (the second token)
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1]
    } else {
        request
    }
}

/// Normalize common URL-encoded characters to their plain-text equivalents
/// so that pattern matching works on URL-encoded payloads.
fn normalize_url_encoding(input: &str) -> String {
    input
        .replace('+', " ")
        .replace("%20", " ")
        .replace("%27", "'")
        .replace("%22", "\"")
        .replace("%3B", ";")
        .replace("%3b", ";")
        .replace("%2D", "-")
        .replace("%2d", "-")
        .replace("%3D", "=")
        .replace("%3d", "=")
        .replace("%28", "(")
        .replace("%29", ")")
}

/// Parse a nginx timestamp like "10/Oct/2023:13:55:36 +0000" and return epoch seconds.
/// Returns None if parsing fails.
fn parse_nginx_timestamp(ts: &str) -> Option<i64> {
    // Format: dd/Mon/YYYY:HH:MM:SS +ZZZZ
    chrono::NaiveDateTime::parse_from_str(
        ts.split_once(' ').map(|(dt, _)| dt).unwrap_or(ts),
        "%d/%b/%Y:%H:%M:%S",
    )
    .ok()
    .map(|ndt| ndt.and_utc().timestamp())
}

#[async_trait]
impl ScanModule for WebModule {
    fn name(&self) -> &str {
        "web"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();
        tracing::info!(
            "Running web scan (ddos_threshold={} req/min)",
            self.config.ddos_threshold
        );

        let patterns = WebPatterns::compile();

        // Load log cursor for incremental reading (only new lines since last scan)
        let cursor_path = LogCursors::path_for_module("web");
        let mut cursors = LogCursors::load(&cursor_path);

        // Collect all parsed entries from all log files
        let mut all_entries: Vec<AccessLogEntry> = Vec::new();

        for log_path_str in &self.config.access_log_paths {
            let log_path = Path::new(log_path_str);
            if !log_path.exists() {
                tracing::debug!(path = %log_path_str, "Access log file not found, skipping");
                continue;
            }

            let lines = match cursors.read_lines(log_path, 10_000) {
                Ok(lines) => lines,
                Err(e) => {
                    tracing::warn!(path = %log_path_str, error = %e, "Failed to read access log");
                    continue;
                }
            };

            for line in &lines {
                if let Some(entry) = patterns.parse_line(line) {
                    all_entries.push(entry);
                }
            }
        }

        // Track which IPs have already been flagged for each threat type to avoid
        // producing thousands of duplicate events.
        let mut scanner_flagged: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut sqli_flagged: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut traversal_flagged: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // --- Per-entry analysis: Scanner, SQLi, Path Traversal ---
        for entry in &all_entries {
            let request_path = extract_request_path(&entry.request);
            let request_lower = entry.request.to_lowercase();
            let path_lower = request_path.to_lowercase();

            // --- Scanner Detection ---
            if self.config.detect_scanners {
                let mut is_scanner = false;
                let mut scanner_reason = String::new();

                // Check user-agent against known scanner agents
                let ua_lower = entry.user_agent.to_lowercase();
                for agent in &self.config.scanner_agents {
                    if ua_lower.contains(&agent.to_lowercase()) {
                        is_scanner = true;
                        scanner_reason = format!("scanner user-agent: {}", agent);
                        break;
                    }
                }

                // Check for scanner probe paths
                if !is_scanner {
                    for probe_path in SCANNER_PATHS {
                        if path_lower.starts_with(&probe_path.to_lowercase()) {
                            is_scanner = true;
                            scanner_reason = format!("scanner probe path: {}", probe_path);
                            break;
                        }
                    }
                }

                if is_scanner && !scanner_flagged.contains(&entry.ip) {
                    scanner_flagged.insert(entry.ip.clone());
                    let description = format!(
                        "Scanner/probe detected from {} ({})",
                        entry.ip, scanner_reason
                    );

                    let mut event = ThreatEvent::new(ThreatType::ScannerProbe, "web", description)
                        .with_detail("reason", scanner_reason)
                        .with_detail("user_agent", entry.user_agent.clone())
                        .with_detail("request", entry.request.clone())
                        .with_detail("status", entry.status.to_string());

                    if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                        event = event.with_source_ip(ip);
                    }

                    threats.push(event);
                }
            }

            // --- SQL Injection Detection ---
            if self.config.detect_sqli
                && patterns.is_sqli(&request_lower)
                && !sqli_flagged.contains(&entry.ip)
            {
                sqli_flagged.insert(entry.ip.clone());
                let description = format!("SQL injection attempt detected from {}", entry.ip);

                let mut event = ThreatEvent::new(ThreatType::SqlInjection, "web", description)
                    .with_detail("request", entry.request.clone())
                    .with_detail("user_agent", entry.user_agent.clone())
                    .with_detail("status", entry.status.to_string());

                if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                    event = event.with_source_ip(ip);
                }

                threats.push(event);
            }

            // --- Path Traversal Detection ---
            if self.config.detect_path_traversal
                && patterns.is_path_traversal(&request_lower)
                && !traversal_flagged.contains(&entry.ip)
            {
                traversal_flagged.insert(entry.ip.clone());
                let description = format!("Path traversal attempt detected from {}", entry.ip);

                let mut event = ThreatEvent::new(ThreatType::PathTraversal, "web", description)
                    .with_detail("request", entry.request.clone())
                    .with_detail("user_agent", entry.user_agent.clone())
                    .with_detail("status", entry.status.to_string());

                if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                    event = event.with_source_ip(ip);
                }

                threats.push(event);
            }
        }

        // --- DDoS Detection ---
        // Count requests per IP, and estimate requests per minute using timestamps.
        let mut ip_timestamps: HashMap<String, Vec<i64>> = HashMap::new();
        let mut ip_request_count: HashMap<String, u64> = HashMap::new();

        for entry in &all_entries {
            *ip_request_count.entry(entry.ip.clone()).or_insert(0) += 1;
            if let Some(ts) = parse_nginx_timestamp(&entry.timestamp) {
                ip_timestamps.entry(entry.ip.clone()).or_default().push(ts);
            }
        }

        let ddos_threshold = self.config.ddos_threshold as u64;
        for (ip_str, count) in &ip_request_count {
            let mut flagged = false;

            // If we have timestamps, calculate requests per minute more accurately
            if let Some(timestamps) = ip_timestamps.get(ip_str) {
                if timestamps.len() >= 2 {
                    let min_ts = *timestamps.iter().min().unwrap();
                    let max_ts = *timestamps.iter().max().unwrap();
                    let duration_secs = (max_ts - min_ts).max(1);
                    let rpm = (*count as f64 / duration_secs as f64) * 60.0;
                    if rpm >= ddos_threshold as f64 {
                        flagged = true;
                    }
                }
            }

            // Fallback: if total count alone exceeds threshold, flag it
            // (handles case where all timestamps are the same or unparseable)
            if !flagged && *count >= ddos_threshold {
                flagged = true;
            }

            if flagged {
                let description = format!(
                    "Potential DDoS: {} sent {} requests (threshold: {}/min)",
                    ip_str, count, ddos_threshold
                );

                let mut event = ThreatEvent::new(ThreatType::WebDdos, "web", description)
                    .with_detail("request_count", count.to_string())
                    .with_detail("threshold", ddos_threshold.to_string());

                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    event = event.with_source_ip(ip);
                }

                threats.push(event);
            }
        }

        // Save cursor so next scan only reads new lines
        if let Err(e) = cursors.save(&cursor_path) {
            tracing::warn!(error = %e, "Failed to save web log cursor");
        }

        tracing::info!(count = threats.len(), "Web scan complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(log_path: &str) -> WebConfig {
        WebConfig {
            enabled: true,
            access_log_paths: vec![log_path.to_string()],
            ddos_threshold: 100,
            detect_sqli: true,
            detect_path_traversal: true,
            detect_scanners: true,
            scanner_agents: vec!["nikto".into(), "sqlmap".into(), "nmap".into()],
        }
    }

    fn sample_log_line(ip: &str, request: &str, ua: &str) -> String {
        format!(
            r#"{} - - [10/Oct/2023:13:55:36 +0000] "{}" 200 512 "-" "{}""#,
            ip, request, ua
        )
    }

    #[test]
    fn test_parse_nginx_log_line() {
        let patterns = WebPatterns::compile();
        let line = r#"192.168.1.1 - frank [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0""#;
        let entry = patterns.parse_line(line).unwrap();
        assert_eq!(entry.ip, "192.168.1.1");
        assert_eq!(entry.request, "GET /index.html HTTP/1.1");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn test_sqli_detection_union_select() {
        let patterns = WebPatterns::compile();
        assert!(patterns.is_sqli("get /search?q=1 union select * from users"));
        assert!(patterns.is_sqli("get /search?q=1 union all select * from users"));
    }

    #[test]
    fn test_sqli_detection_or_1_1() {
        let patterns = WebPatterns::compile();
        assert!(patterns.is_sqli("get /login?user=' or 1=1--"));
    }

    #[test]
    fn test_sqli_detection_sleep() {
        let patterns = WebPatterns::compile();
        assert!(patterns.is_sqli("get /id=1 and sleep(5)"));
    }

    #[test]
    fn test_sqli_detection_information_schema() {
        let patterns = WebPatterns::compile();
        assert!(
            patterns.is_sqli("get /id=1 union select table_name from information_schema.tables")
        );
    }

    #[test]
    fn test_no_sqli_for_normal_request() {
        let patterns = WebPatterns::compile();
        assert!(!patterns.is_sqli("get /index.html http/1.1"));
        assert!(!patterns.is_sqli("get /search?q=hello+world http/1.1"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let patterns = WebPatterns::compile();
        assert!(patterns.is_path_traversal("GET /../../etc/passwd HTTP/1.1"));
        assert!(patterns.is_path_traversal("GET /files?name=%2e%2e/secret HTTP/1.1"));
        assert!(patterns.is_path_traversal("GET /image%00.jpg HTTP/1.1"));
        assert!(patterns.is_path_traversal("GET /proc/self/environ HTTP/1.1"));
    }

    #[test]
    fn test_no_path_traversal_for_normal_request() {
        let patterns = WebPatterns::compile();
        assert!(!patterns.is_path_traversal("GET /index.html HTTP/1.1"));
        assert!(!patterns.is_path_traversal("GET /api/users/123 HTTP/1.1"));
    }

    #[test]
    fn test_scanner_detection_by_user_agent() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        std::fs::write(
            &log_path,
            sample_log_line("10.0.0.5", "GET / HTTP/1.1", "Nikto/2.1.6"),
        )
        .unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::ScannerProbe));
    }

    #[test]
    fn test_scanner_detection_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        std::fs::write(
            &log_path,
            sample_log_line("10.0.0.5", "GET /.env HTTP/1.1", "Mozilla/5.0"),
        )
        .unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::ScannerProbe));
    }

    #[test]
    fn test_sqli_in_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        std::fs::write(
            &log_path,
            sample_log_line(
                "10.0.0.5",
                "GET /search?q=1'+UNION+SELECT+*+FROM+users HTTP/1.1",
                "Mozilla/5.0",
            ),
        )
        .unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::SqlInjection));
    }

    #[test]
    fn test_path_traversal_in_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        std::fs::write(
            &log_path,
            sample_log_line("10.0.0.5", "GET /../../etc/passwd HTTP/1.1", "Mozilla/5.0"),
        )
        .unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::PathTraversal));
    }

    #[test]
    fn test_ddos_detection() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        // Generate 150 requests from the same IP at the same second to trigger DDoS
        for _ in 0..150 {
            content.push_str(&sample_log_line(
                "10.0.0.99",
                "GET / HTTP/1.1",
                "Mozilla/5.0",
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats.iter().any(|t| t.threat_type == ThreatType::WebDdos));
    }

    #[test]
    fn test_no_ddos_below_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        // Generate 10 requests spread over 10 minutes (1/min, well below 100/min threshold)
        let mut content = String::new();
        for i in 0..10 {
            content.push_str(&format!(
                r#"10.0.0.99 - - [10/Oct/2023:13:{:02}:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0""#,
                i
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(!threats.iter().any(|t| t.threat_type == ThreatType::WebDdos));
    }

    #[test]
    fn test_missing_log_file_is_handled() {
        let config = test_config("/nonexistent/path/access.log");
        let module = WebModule::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(threats.is_empty());
    }

    #[test]
    fn test_extract_request_path() {
        assert_eq!(
            extract_request_path("GET /index.html HTTP/1.1"),
            "/index.html"
        );
        assert_eq!(
            extract_request_path("POST /api/login HTTP/1.1"),
            "/api/login"
        );
        assert_eq!(extract_request_path("/raw-path"), "/raw-path");
    }

    #[test]
    fn test_parse_nginx_timestamp() {
        let ts = parse_nginx_timestamp("10/Oct/2023:13:55:36 +0000");
        assert!(ts.is_some());
        // 2023-10-10 13:55:36 UTC = 1696946136
        assert_eq!(ts.unwrap(), 1696946136);
    }
}
