use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

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
    data_dir: PathBuf,
}

impl WebModule {
    pub fn new(config: WebConfig, data_dir: PathBuf) -> Self {
        Self { config, data_dir }
    }
}

/// Parsed representation of a single nginx combined log entry.
#[derive(Debug)]
struct AccessLogEntry {
    ip: String,
    timestamp: String,
    request: String,
    status: u16,
    bytes: u64,
    referer: String,
    user_agent: String,
}

/// Common WebSocket path prefixes used as fallback auto-detection when no
/// explicit `ddos_high_traffic_paths` are configured. Traffic on these paths
/// is counted against the higher DDoS threshold to avoid false positives on
/// legitimate real-time connections (chat, live updates, etc.).
const WEBSOCKET_PATH_PREFIXES: &[&str] = &[
    "/ws/",
    "/ws",
    "/wss/",
    "/wss",
    "/socket.io/",
    "/socket.io",
    "/sockjs/",
    "/sockjs",
    "/cable",
    "/hub",
];

/// Static asset path prefixes — excluded from DDoS counting entirely.
/// Modern SPAs (Next.js, Vite, Webpack, Nuxt) emit dozens of these per page
/// load. Counting them as DDoS traffic causes false positives on legitimate
/// browser users.
const STATIC_ASSET_PATH_PREFIXES: &[&str] = &[
    "/_next/static/",
    "/_next/image",
    "/_next/data/",
    "/_nuxt/",
    "/static/",
    "/assets/",
    "/public/",
    "/build/",
    "/dist/",
];

/// Static asset file extensions — excluded from DDoS counting entirely.
/// Matched against the path portion of the request URL after stripping any
/// query string. nginx serves these cheaply; an attacker fetching only static
/// files cannot meaningfully harm the origin.
const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    ".ico", ".css", ".js", ".mjs", ".map", ".json", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".bmp", ".mp4", ".webm", ".mp3",
    ".wav", ".ogg",
];

/// Server-Sent Events / streaming path prefixes — auto-classified as
/// high-traffic (counted against `ddos_high_traffic_threshold`, not excluded,
/// so a real flood of stream opens against e.g. a local vLLM server still
/// trips the alarm).
const SSE_PATH_PREFIXES: &[&str] = &[
    "/sse",
    "/events",
    "/stream",
    "/v1/chat/completions",
    "/v1/completions",
    "/api/chat",
    "/api/stream",
    "/api/sse",
];

/// Returns true if `path` (query-string stripped) is a static asset that
/// should be excluded from DDoS counting.
fn is_static_asset_path(path: &str, extra_prefixes: &[String]) -> bool {
    if STATIC_ASSET_PATH_PREFIXES
        .iter()
        .any(|p| path.starts_with(p))
    {
        return true;
    }
    if extra_prefixes.iter().any(|p| path.starts_with(p.as_str())) {
        return true;
    }
    // Extension match — lowercase the tail for case-insensitive comparison.
    if let Some(dot_idx) = path.rfind('.') {
        let ext = &path[dot_idx..];
        // Fast ASCII lowercase comparison.
        for known in STATIC_ASSET_EXTENSIONS {
            if ext.eq_ignore_ascii_case(known) {
                return true;
            }
        }
    }
    false
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
            bytes,
            referer: caps[6].to_string(),
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

/// Extract the request method (first token) from a request line like "GET /path HTTP/1.1".
fn extract_request_method(request: &str) -> &str {
    request.split_whitespace().next().unwrap_or("-")
}

/// Format a byte count as a human-readable string (e.g., "1.5 KB", "2.3 MB").
/// Values <= 1024 are returned as plain integers (e.g., "512").
fn format_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let bf = b as f64;
    if bf >= GB {
        format!("{:.1} GB", bf / GB)
    } else if bf >= MB {
        format!("{:.1} MB", bf / MB)
    } else if bf > KB {
        format!("{:.1} KB", bf / KB)
    } else {
        b.to_string()
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
        let cursor_path = LogCursors::path_for_module("web", &self.data_dir);
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
                        .with_detail("status", entry.status.to_string())
                        .with_detail(
                            "request_method",
                            extract_request_method(&entry.request).to_string(),
                        )
                        .with_detail("request_path", request_path.to_string())
                        .with_detail("referer", entry.referer.clone())
                        .with_detail("response_bytes", format_bytes(entry.bytes));

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
                    .with_detail("status", entry.status.to_string())
                    .with_detail(
                        "request_method",
                        extract_request_method(&entry.request).to_string(),
                    )
                    .with_detail("request_path", request_path.to_string())
                    .with_detail("referer", entry.referer.clone())
                    .with_detail("response_bytes", format_bytes(entry.bytes));

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
                    .with_detail("status", entry.status.to_string())
                    .with_detail(
                        "request_method",
                        extract_request_method(&entry.request).to_string(),
                    )
                    .with_detail("request_path", request_path.to_string())
                    .with_detail("referer", entry.referer.clone())
                    .with_detail("response_bytes", format_bytes(entry.bytes));

                if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                    event = event.with_source_ip(ip);
                }

                threats.push(event);
            }
        }

        // --- DDoS Detection ---
        // Count requests per IP, split into normal vs high-traffic paths.
        // High-traffic paths (WebSocket, chat, streaming) use a separate,
        // higher threshold to avoid false positives on legitimate real-time traffic.
        let ht_paths = &self.config.ddos_high_traffic_paths;
        let mut ip_timestamps: HashMap<String, Vec<i64>> = HashMap::new();
        let mut ip_request_count: HashMap<String, u64> = HashMap::new();
        let mut ip_ht_count: HashMap<String, u64> = HashMap::new();
        let mut ip_paths: HashMap<String, HashMap<String, u32>> = HashMap::new();
        let mut ip_user_agents: HashMap<String, HashSet<String>> = HashMap::new();

        for entry in &all_entries {
            let raw_path = entry.request.split_whitespace().nth(1).unwrap_or("");
            // Strip query string for path classification — static assets
            // often carry cache-busting query params (e.g. ?v=1.2.3).
            let request_path = raw_path.split('?').next().unwrap_or(raw_path);

            // Track paths and user agents per IP for DDoS enrichment.
            // We populate this even for excluded static assets so that, if a
            // real attack does fire, the forensic detail isn't degraded.
            *ip_paths
                .entry(entry.ip.clone())
                .or_default()
                .entry(request_path.to_string())
                .or_insert(0) += 1;
            ip_user_agents
                .entry(entry.ip.clone())
                .or_default()
                .insert(entry.user_agent.clone());

            // Static assets (favicons, /_next/static/*, *.css, *.js, fonts,
            // images) are excluded from DDoS counting entirely. A single SPA
            // page load can easily emit 100+ such requests; treating them as
            // attack traffic was the source of the user-reported false
            // positives.
            if is_static_asset_path(request_path, &self.config.ddos_static_paths) {
                continue;
            }

            let is_ws_status = entry.status == 101;
            let is_ws_path = WEBSOCKET_PATH_PREFIXES
                .iter()
                .any(|p| request_path.starts_with(p));
            let is_sse_path = SSE_PATH_PREFIXES
                .iter()
                .any(|p| request_path.starts_with(p));
            let is_ht = is_ws_status
                || is_ws_path
                || is_sse_path
                || (!ht_paths.is_empty()
                    && ht_paths
                        .iter()
                        .any(|prefix| request_path.starts_with(prefix.as_str())));

            if is_ws_status {
                tracing::debug!(ip = %entry.ip, path = %request_path, "WebSocket upgrade detected, using high-traffic threshold");
            }

            if is_ht {
                *ip_ht_count.entry(entry.ip.clone()).or_insert(0) += 1;
            } else {
                *ip_request_count.entry(entry.ip.clone()).or_insert(0) += 1;
            }
            if let Some(ts) = parse_nginx_timestamp(&entry.timestamp) {
                ip_timestamps.entry(entry.ip.clone()).or_default().push(ts);
            }
        }

        // Check normal-path requests against standard threshold
        let ddos_threshold = self.config.ddos_threshold as u64;
        let ht_threshold = self.config.ddos_high_traffic_threshold as u64;

        // Merge counts: flag if EITHER normal exceeds normal threshold
        // OR high-traffic exceeds high-traffic threshold.
        let mut all_ips: std::collections::HashSet<&String> = ip_request_count.keys().collect();
        all_ips.extend(ip_ht_count.keys());

        for ip_str in &all_ips {
            let normal_count = ip_request_count.get(*ip_str).copied().unwrap_or(0);
            let ht_count = ip_ht_count.get(*ip_str).copied().unwrap_or(0);
            let total_count = normal_count + ht_count;
            let mut flagged = false;
            let mut effective_threshold = ddos_threshold;

            // Determine which threshold applies
            if ht_count > normal_count && ht_threshold > 0 {
                // Mostly high-traffic path requests — use higher threshold
                effective_threshold = ht_threshold;
            }

            // If we have timestamps spanning a meaningful window, calculate RPM.
            // Require >= 10 s to avoid extrapolating short page-load bursts
            // (e.g. 36 reqs in 3 s → 720 RPM) into false DDoS positives.
            if let Some(timestamps) = ip_timestamps.get(*ip_str) {
                if timestamps.len() >= 2 {
                    let min_ts = *timestamps.iter().min().unwrap();
                    let max_ts = *timestamps.iter().max().unwrap();
                    let duration_secs = max_ts - min_ts;
                    if duration_secs >= 10 {
                        let rpm = (total_count as f64 / duration_secs as f64) * 60.0;
                        if rpm >= effective_threshold as f64 {
                            flagged = true;
                        }
                    }
                }
            }

            // Fallback: if total count alone exceeds threshold, flag it
            if !flagged && total_count >= effective_threshold {
                flagged = true;
            }

            let count = &total_count;

            if flagged {
                let description = format!(
                    "Potential DDoS: {} sent {} requests (threshold: {}/min)",
                    ip_str, count, effective_threshold
                );

                let mut event = ThreatEvent::new(ThreatType::WebDdos, "web", description)
                    .with_detail("request_count", count.to_string())
                    .with_detail("threshold", effective_threshold.to_string());

                // Enrich with top paths
                if let Some(paths) = ip_paths.get(*ip_str) {
                    let mut path_vec: Vec<(&String, &u32)> = paths.iter().collect();
                    path_vec.sort_by(|a, b| b.1.cmp(a.1));
                    let top_paths: Vec<String> = path_vec
                        .iter()
                        .take(5)
                        .map(|(p, c)| format!("{} ({})", p, c))
                        .collect();
                    event = event.with_detail("top_paths", top_paths.join(", "));
                }

                // Enrich with unique user agents
                if let Some(agents) = ip_user_agents.get(*ip_str) {
                    let ua_list: Vec<&String> = agents.iter().take(5).collect();
                    let ua_str: Vec<&str> = ua_list.iter().map(|s| s.as_str()).collect();
                    event = event.with_detail("user_agents", ua_str.join(", "));
                }

                // Enrich with time window and RPM
                if let Some(timestamps) = ip_timestamps.get(*ip_str) {
                    if timestamps.len() >= 2 {
                        let min_ts = *timestamps.iter().min().unwrap();
                        let max_ts = *timestamps.iter().max().unwrap();
                        let window_secs = max_ts - min_ts;
                        event = event.with_detail("time_window", format!("{}s", window_secs));
                        if window_secs > 0 {
                            let rpm = (total_count as f64 / window_secs as f64) * 60.0;
                            event = event.with_detail("requests_per_minute", format!("{:.1}", rpm));
                        }
                    }
                }

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
            ddos_high_traffic_paths: Vec::new(),
            ddos_high_traffic_threshold: 2000,
            ddos_static_paths: Vec::new(),
        }
    }

    fn sample_log_line(ip: &str, request: &str, ua: &str) -> String {
        sample_log_line_status(ip, request, 200, ua)
    }

    fn sample_log_line_status(ip: &str, request: &str, status: u16, ua: &str) -> String {
        format!(
            r#"{} - - [10/Oct/2023:13:55:36 +0000] "{}" {} 512 "-" "{}""#,
            ip, request, status, ua
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
        let module = WebModule::new(config, dir.path().to_path_buf());
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
        let module = WebModule::new(config, dir.path().to_path_buf());
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
        let module = WebModule::new(config, dir.path().to_path_buf());
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
        let module = WebModule::new(config, dir.path().to_path_buf());
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
        let module = WebModule::new(config, dir.path().to_path_buf());
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
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(!threats.iter().any(|t| t.threat_type == ThreatType::WebDdos));
    }

    #[test]
    fn test_missing_log_file_is_handled() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config("/nonexistent/path/access.log");
        let module = WebModule::new(config, dir.path().to_path_buf());
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

    #[test]
    fn test_extract_request_method() {
        assert_eq!(extract_request_method("GET /index.html HTTP/1.1"), "GET");
        assert_eq!(extract_request_method("POST /api/login HTTP/1.1"), "POST");
        assert_eq!(extract_request_method(""), "-");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0");
        assert_eq!(format_bytes(512), "512");
        assert_eq!(format_bytes(1024), "1024");
        assert_eq!(format_bytes(1025), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
    }

    /// Generate a log line with a specific second offset (0-59) within the
    /// same minute, so that RPM calculations produce a meaningful rate.
    fn sample_log_line_at_sec(ip: &str, request: &str, status: u16, ua: &str, sec: u32) -> String {
        format!(
            r#"{} - - [10/Oct/2023:13:55:{:02} +0000] "{}" {} 512 "-" "{}""#,
            ip, sec, request, status, ua
        )
    }

    #[test]
    fn test_websocket_101_uses_high_traffic_threshold() {
        // 150 WebSocket upgrade (status 101) requests spread over 60 s → 150 RPM.
        // Normal threshold is 100, but these should count as high-traffic
        // (threshold 2000), so no DDoS is flagged.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..150u32 {
            content.push_str(&sample_log_line_at_sec(
                "10.0.0.50",
                "GET /chat HTTP/1.1",
                101,
                "Mozilla/5.0",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "WebSocket 101 traffic should not trigger DDoS at normal threshold"
        );
    }

    #[test]
    fn test_websocket_path_uses_high_traffic_threshold() {
        // 150 requests to /ws/ path (status 200, e.g. polling fallback) spread
        // over 60 s → 150 RPM. Auto-detected as high-traffic by path prefix.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..150u32 {
            content.push_str(&sample_log_line_at_sec(
                "10.0.0.51",
                "GET /ws/updates HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "WebSocket path traffic should not trigger DDoS at normal threshold"
        );
    }

    #[test]
    fn test_is_static_asset_path_classifier() {
        let no_extra: Vec<String> = Vec::new();
        // Built-in path prefixes
        assert!(is_static_asset_path(
            "/_next/static/chunks/foo.js",
            &no_extra
        ));
        assert!(is_static_asset_path("/static/app.css", &no_extra));
        assert!(is_static_asset_path("/assets/logo.svg", &no_extra));
        // Built-in extensions
        assert!(is_static_asset_path("/favicon.ico", &no_extra));
        assert!(is_static_asset_path("/anything.css", &no_extra));
        assert!(is_static_asset_path("/fonts/sans.woff2", &no_extra));
        assert!(is_static_asset_path("/img/photo.JPG", &no_extra)); // case-insensitive
                                                                    // Non-asset paths
        assert!(!is_static_asset_path("/", &no_extra));
        assert!(!is_static_asset_path("/api/data", &no_extra));
        assert!(!is_static_asset_path("/login", &no_extra));
        // User-supplied extra prefix
        let extra = vec!["/cdn/".to_string()];
        assert!(is_static_asset_path("/cdn/anything", &extra));
        assert!(!is_static_asset_path("/cdn/anything", &no_extra));
    }

    #[test]
    fn test_favicon_flood_does_not_trigger_ddos() {
        // The user-reported false positive: a Next.js page repeatedly
        // requesting /favicon.ico must NOT trigger a DDoS alert.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..300u32 {
            content.push_str(&sample_log_line_at_sec(
                "5.203.157.175",
                "GET /favicon.ico HTTP/1.1",
                200,
                "Mozilla/5.0 (Linux; Android 16) Mobile Safari/537.36",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "Repeated favicon.ico requests must not trigger DDoS"
        );
    }

    #[test]
    fn test_next_static_chunks_do_not_trigger_ddos() {
        // SPAs (Next.js, Webpack) emit dozens of /_next/static/* requests per
        // page load. These must be excluded from DDoS counting.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..300u32 {
            content.push_str(&sample_log_line_at_sec(
                "5.203.157.175",
                "GET /_next/static/chunks/foo.js HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "/_next/static/* requests must not trigger DDoS"
        );
    }

    #[test]
    fn test_real_world_mixed_page_load_does_not_trigger_ddos() {
        // Reproduce the user-reported event:
        // 165 favicon.ico + 50 /api/data interleaved over 46 s.
        // The static favicon hits are excluded; the 50 /api/data hits
        // (~65 RPM over 46 s) stay under the 100/min test threshold → no DDoS.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..165u32 {
            content.push_str(&sample_log_line_at_sec(
                "5.203.157.175",
                "GET /favicon.ico HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 46,
            ));
            content.push('\n');
        }
        for i in 0..50u32 {
            content.push_str(&sample_log_line_at_sec(
                "5.203.157.175",
                "GET /api/data HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 46,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "Mixed page load (favicon + light API) must not trigger DDoS"
        );
    }

    #[test]
    fn test_sse_path_uses_high_traffic_threshold() {
        // 300 requests to /v1/chat/completions over 60 s → 300 RPM.
        // Auto-detected as SSE/streaming → uses high-traffic threshold (2000),
        // so no DDoS at this rate.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..300u32 {
            content.push_str(&sample_log_line_at_sec(
                "10.0.0.60",
                "POST /v1/chat/completions HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "SSE/chat completions path must not trigger DDoS at normal threshold"
        );
    }

    #[test]
    fn test_static_query_string_stripped() {
        // Cache-busted asset like /app.css?v=1.2.3 must still be classified
        // as static (the query string is stripped before extension match).
        let no_extra: Vec<String> = Vec::new();
        // The classifier sees the path after query stripping happens in the
        // detection loop, so confirm both forms here.
        assert!(is_static_asset_path("/app.css", &no_extra));
        // Bare path with query-string-like extension portion would not match
        // — but the loop strips the query before calling, so this is a
        // documentation test, not a regression check.
    }

    #[test]
    fn test_user_configured_static_path_excluded() {
        // User adds /cdn/ to ddos_static_paths in aegis.toml. 300 requests
        // there over 60 s should not flag, even though they're high-volume.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..300u32 {
            content.push_str(&sample_log_line_at_sec(
                "10.0.0.61",
                "GET /cdn/image-no-extension HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let mut config = test_config(log_path.to_str().unwrap());
        config.ddos_static_paths = vec!["/cdn/".to_string()];
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            !threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "User-configured static paths must be excluded from DDoS counting"
        );
    }

    #[test]
    fn test_normal_path_still_triggers_ddos() {
        // 150 normal requests (status 200, non-WS path) spread over 60 s →
        // 150 RPM, which exceeds the 100/min threshold → DDoS flagged.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let mut content = String::new();
        for i in 0..150u32 {
            content.push_str(&sample_log_line_at_sec(
                "10.0.0.52",
                "GET /api/data HTTP/1.1",
                200,
                "Mozilla/5.0",
                i % 60,
            ));
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let config = test_config(log_path.to_str().unwrap());
        let module = WebModule::new(config, dir.path().to_path_buf());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let threats = rt.block_on(module.scan()).unwrap();
        assert!(
            threats.iter().any(|t| t.threat_type == ThreatType::WebDdos),
            "Normal path traffic should still trigger DDoS above threshold"
        );
    }
}
