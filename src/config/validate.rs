use std::net::IpAddr;
use std::path::Path;

use crate::config::defaults::resolve_path;
use crate::config::schema::AegisConfig;
use crate::core::scheduler::Scheduler;
use crate::core::threat::{ThreatSeverity, ThreatType};

/// Result of validating an Aegis configuration.
#[derive(Debug, Default)]
pub struct ValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate the full Aegis configuration, returning errors and warnings.
pub fn validate_config(config: &AegisConfig) -> ValidationResult {
    let mut result = ValidationResult::default();

    // General
    validate_general(config, &mut result);
    // Network
    validate_network(config, &mut result);
    // Process
    validate_process(config, &mut result);
    // File integrity
    validate_file_integrity(config, &mut result);
    // Auth
    validate_auth(config, &mut result);
    // Web
    validate_web(config, &mut result);
    // Threat intel
    validate_threat_intel(config, &mut result);
    // Response
    validate_response(config, &mut result);
    // Alerting
    validate_alerting(config, &mut result);
    // Anomaly (if present in config)
    validate_anomaly(config, &mut result);
    // Honeypot (if present in config)
    validate_honeypot(config, &mut result);
    // Dashboard (if present in config)
    validate_dashboard(config, &mut result);

    result
}

fn validate_general(config: &AegisConfig, result: &mut ValidationResult) {
    let valid_modules = [
        "network",
        "process",
        "file_integrity",
        "auth",
        "web",
        "threat_intel",
        "anomaly",
        "honeypot",
        "cert",
        "dns",
        "rootkit",
        "ssh_session",
        "tls_fingerprint",
        "yara_scan",
    ];
    for module in &config.general.modules {
        if !valid_modules.contains(&module.as_str()) {
            result.errors.push(format!(
                "[general] Unknown module name: '{}'. Valid modules: {}",
                module,
                valid_modules.join(", ")
            ));
        }
    }

    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.general.log_level.as_str()) {
        result.errors.push(format!(
            "[general] Invalid log_level: '{}'. Valid levels: {}",
            config.general.log_level,
            valid_levels.join(", ")
        ));
    }

    if Scheduler::parse_duration(&config.general.dedup_ttl).is_err() {
        result.errors.push(format!(
            "[general] Invalid dedup_ttl: '{}'. Use format like '1h', '30m', '0s'",
            config.general.dedup_ttl
        ));
    }

    // Warning: check if data_dir is writable
    let data_dir = resolve_path(&config.general.data_dir);
    if data_dir.exists()
        && data_dir
            .metadata()
            .map(|m| m.permissions().readonly())
            .unwrap_or(false)
    {
        result.warnings.push(format!(
            "[general] data_dir '{}' is not writable",
            data_dir.display()
        ));
    }
}

fn validate_network(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.network.enabled {
        return;
    }
    if config.network.syn_flood_threshold == 0 {
        result.warnings.push(
            "[network] syn_flood_threshold is 0, SYN flood detection effectively disabled"
                .to_string(),
        );
    }
    if config.network.port_scan_threshold == 0 {
        result.warnings.push(
            "[network] port_scan_threshold is 0, port scan detection effectively disabled"
                .to_string(),
        );
    }
    for port in &config.network.known_outbound_ports {
        if *port == 0 {
            result.errors.push(
                "[network] known_outbound_ports contains port 0, which is invalid".to_string(),
            );
        }
    }
    // v2.6.1: validate excluded_destinations CIDRs and refuse public ranges.
    // This list is meant for "obviously not a remote attacker" address space
    // (loopback, link-local, optionally an internal management VLAN). Letting
    // it cover public CIDRs would silently disable threat detection for those
    // IPs — exactly the failure mode the safety pin exists to prevent.
    for cidr_str in &config.network.excluded_destinations {
        let parsed: Result<ipnet::IpNet, _> = cidr_str.parse();
        let parsed = match parsed {
            Ok(n) => n,
            Err(_) => match cidr_str.parse::<IpAddr>() {
                Ok(ip) => ipnet::IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap(),
                Err(_) => {
                    result.errors.push(format!(
                        "[network] Invalid excluded_destinations CIDR: '{}'",
                        cidr_str
                    ));
                    continue;
                }
            },
        };
        // Refuse any entry whose network address is not in a private/loopback
        // /link-local/ULA range. Reuses util::ip::is_private which already
        // covers RFC1918 + loopback + link-local + ULA. A public CIDR here
        // is almost certainly a misconfiguration: it would disable network
        // detection AND block_ip() against that range entirely.
        if !crate::util::ip::is_private(&parsed.network()) {
            result.errors.push(format!(
                "[network] excluded_destinations entry '{}' is not loopback/link-local/private; \
                 refusing to disable detection for a public range. Use [response] whitelist \
                 (user-curated never-block) or [response] well_known_destinations (CDN ranges) \
                 for public IPs.",
                cidr_str
            ));
        }
    }
}

fn validate_process(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.process.enabled {
        return;
    }
    if config.process.miner_cpu_threshold <= 0.0 || config.process.miner_cpu_threshold > 100.0 {
        result.errors.push(format!(
            "[process] miner_cpu_threshold must be between 0 and 100, got {}",
            config.process.miner_cpu_threshold
        ));
    }
    for dir in &config.process.suspicious_dirs {
        let path = Path::new(dir);
        if !path.is_absolute() {
            result.warnings.push(format!(
                "[process] suspicious_dirs entry '{}' is not an absolute path",
                dir
            ));
        }
    }
}

fn validate_file_integrity(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.file_integrity.enabled {
        return;
    }
    for wp in &config.file_integrity.watch_paths {
        let path = resolve_path(wp);
        if !path.exists() {
            result.warnings.push(format!(
                "[file_integrity] watch_path '{}' does not exist",
                wp
            ));
        }
    }
}

fn validate_auth(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.auth.enabled {
        return;
    }
    if config.auth.brute_force_threshold == 0 {
        result.warnings.push(
            "[auth] brute_force_threshold is 0, brute force detection effectively disabled"
                .to_string(),
        );
    }
    for lp in &config.auth.log_paths {
        let path = Path::new(lp);
        if !path.exists() {
            result.warnings.push(format!(
                "[auth] log_path '{}' does not exist (may be normal on some distros)",
                lp
            ));
        }
    }
}

fn validate_web(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.web.enabled {
        return;
    }
    for lp in &config.web.access_log_paths {
        let path = Path::new(lp);
        if !path.exists() {
            result
                .warnings
                .push(format!("[web] access_log_path '{}' does not exist", lp));
        }
    }
    if config.web.ddos_threshold == 0 {
        result
            .warnings
            .push("[web] ddos_threshold is 0, DDoS detection effectively disabled".to_string());
    }
    if config.web.ddos_high_traffic_paths.is_empty() {
        result.warnings.push(
            "[web] ddos_high_traffic_paths is empty — WebSocket/streaming paths will use auto-detection. \
             Set explicitly for better control (e.g. [\"/ws/\", \"/api/chat\"])"
                .to_string(),
        );
    }
}

fn validate_threat_intel(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.threat_intel.enabled {
        return;
    }
    if Scheduler::parse_duration(&config.threat_intel.update_interval).is_err() {
        result.errors.push(format!(
            "[threat_intel] Invalid update_interval: '{}'. Use format like '6h', '30m'",
            config.threat_intel.update_interval
        ));
    }
    for (name, feed) in &config.threat_intel.feeds {
        if feed.enabled && feed.url.is_empty() {
            result.errors.push(format!(
                "[threat_intel.feeds.{}] Feed is enabled but URL is empty",
                name
            ));
        }
        if feed.enabled && !feed.url.starts_with("http://") && !feed.url.starts_with("https://") {
            result.errors.push(format!(
                "[threat_intel.feeds.{}] Feed URL does not start with http:// or https://",
                name
            ));
        }
        if feed.weight > 100 {
            result.errors.push(format!(
                "[threat_intel.feeds.{}] Weight {} exceeds maximum of 100",
                name, feed.weight
            ));
        }
    }
}

fn validate_response(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.response.enabled {
        return;
    }
    let valid_backends = ["iptables", "nftables", "ufw"];
    if !valid_backends.contains(&config.response.firewall_backend.as_str()) {
        result.errors.push(format!(
            "[response] Invalid firewall_backend: '{}'. Valid: {}",
            config.response.firewall_backend,
            valid_backends.join(", ")
        ));
    }

    if Scheduler::parse_duration(&config.response.default_block_duration).is_err() {
        result.errors.push(format!(
            "[response] Invalid default_block_duration: '{}'",
            config.response.default_block_duration
        ));
    }

    for cidr_str in &config.response.whitelist {
        if cidr_str.parse::<ipnet::IpNet>().is_err() && cidr_str.parse::<IpAddr>().is_err() {
            result
                .errors
                .push(format!("[response] Invalid whitelist CIDR: '{}'", cidr_str));
        }
    }

    let valid_actions = ["log", "alert", "block", "kill", "block+kill", "quarantine"];
    for (key, action) in &config.response.overrides {
        if ThreatType::from_config_key(key).is_none() {
            result.warnings.push(format!(
                "[response.overrides] Unknown threat type key: '{}'",
                key
            ));
        }
        if !valid_actions.contains(&action.to_lowercase().as_str()) {
            result.errors.push(format!(
                "[response.overrides] Invalid action '{}' for key '{}'. Valid: {}",
                action,
                key,
                valid_actions.join(", ")
            ));
        }
    }

    // Repeat offender validation
    if config.response.repeat_offender_threshold > 0 {
        if Scheduler::parse_duration(&config.response.repeat_offender_window).is_err() {
            result.errors.push(format!(
                "[response] Invalid repeat_offender_window: '{}'. Use format like '30d', '7d'",
                config.response.repeat_offender_window
            ));
        }
    } else {
        result.warnings.push(
            "[response] repeat_offender_threshold is 0, auto-escalation to permanent ban is disabled"
                .to_string(),
        );
    }
    if config.response.max_strike_records == 0 {
        result.warnings.push(
            "[response] max_strike_records is 0, strike history will not be retained".to_string(),
        );
    }

    // GeoIP validation
    if config.response.geoip.enabled {
        let db_path = resolve_path(&config.response.geoip.database_path);
        if !db_path.exists() {
            result.errors.push(format!(
                "[response.geoip] Database file not found: '{}'",
                db_path.display()
            ));
        }
        if config.response.geoip.blocked_countries.is_empty()
            && config.response.geoip.allowed_countries.is_empty()
        {
            result.warnings.push(
                "[response.geoip] GeoIP enabled but no blocked or allowed countries configured"
                    .to_string(),
            );
        }
    }
}

fn validate_alerting(config: &AegisConfig, result: &mut ValidationResult) {
    // Email
    if config.alerting.email.enabled {
        if config.alerting.email.smtp_host.is_empty()
            || config.alerting.email.smtp_host == "smtp.example.com"
        {
            result
                .errors
                .push("[alerting.email] Email enabled but smtp_host is not configured".to_string());
        }
        if config.alerting.email.to.is_empty() {
            result.errors.push(
                "[alerting.email] Email enabled but no recipients (to) configured".to_string(),
            );
        }
        if config.alerting.email.from.is_empty()
            || config.alerting.email.from == "aegis@yourdomain.com"
        {
            result.warnings.push(
                "[alerting.email] Email 'from' address appears to be the default placeholder"
                    .to_string(),
            );
        }
        if ThreatSeverity::from_str_loose(&config.alerting.email.min_severity).is_none() {
            result.errors.push(format!(
                "[alerting.email] Invalid min_severity: '{}'",
                config.alerting.email.min_severity
            ));
        }
        if Scheduler::parse_duration(&config.alerting.email.cooldown).is_err() {
            result.errors.push(format!(
                "[alerting.email] Invalid cooldown duration: '{}'",
                config.alerting.email.cooldown
            ));
        }
        // Warning if no password env var is set
        if std::env::var("AEGIS_SMTP_PASSWORD").is_err()
            && std::env::var("SMTP_PASSWORD").is_err()
            && config.alerting.email.smtp_password.is_empty()
        {
            result.warnings.push(
                "[alerting.email] No SMTP password set (AEGIS_SMTP_PASSWORD env var or config)"
                    .to_string(),
            );
        }
    }

    // Webhook
    if config.alerting.webhook.enabled {
        if config.alerting.webhook.url.is_empty() {
            result
                .errors
                .push("[alerting.webhook] Webhook enabled but URL is empty".to_string());
        } else if !config.alerting.webhook.url.starts_with("http://")
            && !config.alerting.webhook.url.starts_with("https://")
        {
            result.errors.push(
                "[alerting.webhook] Webhook URL does not start with http:// or https://"
                    .to_string(),
            );
        }
        if ThreatSeverity::from_str_loose(&config.alerting.webhook.min_severity).is_none() {
            result.errors.push(format!(
                "[alerting.webhook] Invalid min_severity: '{}'",
                config.alerting.webhook.min_severity
            ));
        }
    }

    // Slack
    if config.alerting.slack.enabled {
        if config.alerting.slack.webhook_url.is_empty() {
            result
                .errors
                .push("[alerting.slack] Slack enabled but webhook_url is empty".to_string());
        }
        if ThreatSeverity::from_str_loose(&config.alerting.slack.min_severity).is_none() {
            result.errors.push(format!(
                "[alerting.slack] Invalid min_severity: '{}'",
                config.alerting.slack.min_severity
            ));
        }
    }

    // Telegram
    if config.alerting.telegram.enabled {
        let token = std::env::var("AEGIS_TELEGRAM_BOT_TOKEN")
            .unwrap_or_else(|_| config.alerting.telegram.bot_token.clone());
        if token.is_empty() {
            result.errors.push(
                "[alerting.telegram] Telegram enabled but bot_token is empty (set AEGIS_TELEGRAM_BOT_TOKEN env var)"
                    .to_string(),
            );
        }
        if config.alerting.telegram.chat_id.is_empty() {
            result
                .errors
                .push("[alerting.telegram] Telegram enabled but chat_id is empty".to_string());
        }
        if ThreatSeverity::from_str_loose(&config.alerting.telegram.min_severity).is_none() {
            result.errors.push(format!(
                "[alerting.telegram] Invalid min_severity: '{}'",
                config.alerting.telegram.min_severity
            ));
        }
    }
}

fn validate_anomaly(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.anomaly.enabled {
        return;
    }
    if config.anomaly.normal_login_hours.len() != 2 {
        result.errors.push(
            "[anomaly] normal_login_hours must have exactly 2 elements [start, end]".to_string(),
        );
    } else {
        let start = config.anomaly.normal_login_hours[0];
        let end = config.anomaly.normal_login_hours[1];
        if start > 23 || end > 23 {
            result.errors.push(format!(
                "[anomaly] normal_login_hours values must be 0-23, got [{}, {}]",
                start, end
            ));
        }
    }
}

fn validate_honeypot(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.honeypot.enabled {
        return;
    }
    if config.honeypot.ports.is_empty() {
        result
            .warnings
            .push("[honeypot] Honeypot enabled but no ports configured".to_string());
    }
    for port in &config.honeypot.ports {
        if *port == 0 || *port == 22 {
            result.errors.push(format!(
                "[honeypot] Port {} is invalid or conflicts with real SSH",
                port
            ));
        }
        if *port < 1024 {
            result.warnings.push(format!(
                "[honeypot] Port {} requires root/CAP_NET_BIND_SERVICE",
                port
            ));
        }
    }
}

fn validate_dashboard(config: &AegisConfig, result: &mut ValidationResult) {
    if !config.dashboard.enabled {
        return;
    }
    if config.dashboard.port == 0 {
        result
            .errors
            .push("[dashboard] Port 0 is invalid".to_string());
    }
    if config.dashboard.bind != "127.0.0.1" && config.dashboard.bind != "::1" {
        result.warnings.push(format!(
            "[dashboard] bind address '{}' is not localhost - dashboard will be network accessible",
            config.dashboard.bind
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::AegisConfig;

    #[test]
    fn test_default_config_validates() {
        let config = AegisConfig::default();
        let result = validate_config(&config);
        // Default config should have no errors (may have warnings for missing files)
        assert!(result.errors.is_empty(), "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_invalid_module_name() {
        let mut config = AegisConfig::default();
        config
            .general
            .modules
            .push("nonexistent_module".to_string());
        let result = validate_config(&config);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("nonexistent_module")));
    }

    #[test]
    fn test_invalid_log_level() {
        let mut config = AegisConfig::default();
        config.general.log_level = "verbose".to_string();
        let result = validate_config(&config);
        assert!(result.errors.iter().any(|e| e.contains("log_level")));
    }

    #[test]
    fn test_invalid_firewall_backend() {
        let mut config = AegisConfig::default();
        config.response.firewall_backend = "pf".to_string();
        let result = validate_config(&config);
        assert!(result.errors.iter().any(|e| e.contains("firewall_backend")));
    }

    #[test]
    fn test_invalid_whitelist_cidr() {
        let mut config = AegisConfig::default();
        config.response.whitelist.push("not-a-cidr".to_string());
        let result = validate_config(&config);
        assert!(result.errors.iter().any(|e| e.contains("whitelist CIDR")));
    }

    #[test]
    fn test_invalid_repeat_offender_window() {
        let mut config = AegisConfig::default();
        config.response.repeat_offender_threshold = 3;
        config.response.repeat_offender_window = "invalid".to_string();
        let result = validate_config(&config);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("repeat_offender_window")));
    }

    #[test]
    fn test_zero_threshold_warning() {
        let mut config = AegisConfig::default();
        config.response.repeat_offender_threshold = 0;
        let result = validate_config(&config);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("auto-escalation")));
    }

    #[test]
    fn test_email_enabled_no_host() {
        let mut config = AegisConfig::default();
        config.alerting.email.enabled = true;
        let result = validate_config(&config);
        assert!(result.errors.iter().any(|e| e.contains("smtp_host")));
    }

    #[test]
    fn test_webhook_enabled_no_url() {
        let mut config = AegisConfig::default();
        config.alerting.webhook.enabled = true;
        let result = validate_config(&config);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Webhook enabled but URL")));
    }
}
