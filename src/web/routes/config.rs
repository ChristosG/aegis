use std::collections::HashSet;
use std::path::Path;

use axum::{
    extract::State,
    response::{Html, Json},
};
use tracing::{info, warn};

use crate::config::defaults::find_config_path;
use crate::util::proc_parse;
use crate::web::server::AppContext;
use crate::web::templates;

/// Sections allowed for generic config updates (everything except dashboard).
/// Supports dot-notation: "alerting.email" → doc["alerting"]["email"].
/// Also allows "threat_intel.feeds.*" for per-feed updates (validated dynamically).
const ALLOWED_SECTIONS: &[&str] = &[
    "general",
    "network",
    "process",
    "file_integrity",
    "auth",
    "web",
    "threat_intel",
    "response",
    "response.geoip",
    "alerting",
    "alerting.email",
    "alerting.slack",
    "alerting.telegram",
    "alerting.webhook",
    "anomaly",
    "honeypot",
    "cert",
];

/// All valid module names for toggle endpoint.
const VALID_MODULES: &[&str] = &[
    "network",
    "process",
    "file_integrity",
    "auth",
    "web",
    "threat_intel",
    "anomaly",
    "honeypot",
    "cert",
];

// ─── Existing endpoints ───────────────────────────────────────────────────────

/// Return sanitized config (masks sensitive fields).
pub async fn api_config(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let config = &*ctx.config;
    let mut config_json = serde_json::to_value(config).unwrap_or(serde_json::json!({}));

    // Sanitize sensitive fields
    if let Some(obj) = config_json.as_object_mut() {
        if let Some(alerting) = obj.get_mut("alerting").and_then(|a| a.as_object_mut()) {
            if let Some(email) = alerting.get_mut("email").and_then(|e| e.as_object_mut()) {
                if email.contains_key("smtp_password") {
                    email.insert("smtp_password".to_string(), serde_json::json!("***"));
                }
            }
            if let Some(telegram) = alerting.get_mut("telegram").and_then(|t| t.as_object_mut()) {
                if telegram.contains_key("bot_token") {
                    telegram.insert("bot_token".to_string(), serde_json::json!("***"));
                }
            }
            if let Some(slack) = alerting.get_mut("slack").and_then(|s| s.as_object_mut()) {
                if let Some(url) = slack.get("webhook_url").and_then(|u| u.as_str()) {
                    if !url.is_empty() {
                        slack.insert("webhook_url".to_string(), serde_json::json!("***"));
                    }
                }
            }
            if let Some(webhook) = alerting.get_mut("webhook").and_then(|w| w.as_object_mut()) {
                if let Some(url) = webhook.get("url").and_then(|u| u.as_str()) {
                    if !url.is_empty() {
                        webhook.insert("url".to_string(), serde_json::json!("***"));
                    }
                }
            }
        }
        // Mask GeoIP license key
        if let Some(response) = obj.get_mut("response").and_then(|r| r.as_object_mut()) {
            if let Some(geoip) = response.get_mut("geoip").and_then(|g| g.as_object_mut()) {
                if let Some(key) = geoip.get("maxmind_license_key").and_then(|k| k.as_str()) {
                    if !key.is_empty() {
                        geoip.insert("maxmind_license_key".to_string(), serde_json::json!("***"));
                    }
                }
            }
        }
        // Mask dashboard token file path
        if let Some(dashboard) = obj.get_mut("dashboard").and_then(|d| d.as_object_mut()) {
            dashboard.remove("token_file");
        }
    }

    Json(config_json)
}

/// Render config page — minimal skeleton, JS builds editable forms via /api/config.
pub async fn config_page(State(ctx): State<AppContext>) -> Html<String> {
    let content = r#"
        <div style="margin-bottom:16px;display:flex;gap:8px;align-items:center">
            <button onclick="validateConfig()">Validate Config</button>
            <button class="btn-restart" onclick="restartAegis()">Restart Aegis</button>
        </div>
        <div id="config-sections">Loading...</div>
    "#;

    Html(templates::render_config_page(content, &ctx.api_token))
}

/// Config validation API endpoint.
pub async fn api_check(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let result = crate::config::validate::validate_config(&ctx.config);

    Json(serde_json::json!({
        "valid": result.is_ok(),
        "errors": result.errors,
        "warnings": result.warnings,
    }))
}

// ─── Generic config update ────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ConfigUpdateRequest {
    section: String,
    updates: serde_json::Map<String, serde_json::Value>,
}

/// POST /api/config — Update a config section.
pub async fn api_config_update(
    State(_ctx): State<AppContext>,
    Json(payload): Json<ConfigUpdateRequest>,
) -> Json<serde_json::Value> {
    // Validate section name (static list + dynamic threat_intel.feeds.*)
    let is_feed_section = payload.section.starts_with("threat_intel.feeds.");
    if !ALLOWED_SECTIONS.contains(&payload.section.as_str()) && !is_feed_section {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Invalid section: '{}'. Allowed: {}, threat_intel.feeds.*", payload.section, ALLOWED_SECTIONS.join(", "))
        }));
    }

    // Load config file
    let config_path = match find_config_path(None) {
        Some(p) => p,
        None => {
            return Json(serde_json::json!({
                "status": "error",
                "message": "No config file found."
            }));
        }
    };

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to read config file");
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to read config: {}", e)
            }));
        }
    };

    let mut doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Failed to parse config file");
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to parse config: {}", e)
            }));
        }
    };

    // Navigate to the correct table using dot-notation
    let section_parts: Vec<&str> = payload.section.split('.').collect();

    // Ensure tables exist along the path
    if !section_parts.is_empty() && !doc.contains_key(section_parts[0]) {
        doc[section_parts[0]] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if section_parts.len() >= 2 {
        if let Some(t1) = doc[section_parts[0]].as_table_mut() {
            if !t1.contains_key(section_parts[1]) {
                t1[section_parts[1]] = toml_edit::Item::Table(toml_edit::Table::new());
            }
        }
    }
    if section_parts.len() >= 3 {
        if let Some(t1) = doc[section_parts[0]].as_table_mut() {
            if let Some(t2) = t1[section_parts[1]].as_table_mut() {
                if !t2.contains_key(section_parts[2]) {
                    t2[section_parts[2]] = toml_edit::Item::Table(toml_edit::Table::new());
                }
            }
        }
    }

    // Apply updates
    for (key, val) in &payload.updates {
        // Skip masked secrets sent back unchanged
        if val.as_str() == Some("***") {
            continue;
        }

        let toml_item = match json_to_toml_value(val) {
            Some(item) => item,
            None => {
                return Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Unsupported value type for key '{}'. Objects and null are not supported.", key)
                }));
            }
        };

        match section_parts.len() {
            1 => {
                doc[section_parts[0]][key.as_str()] = toml_item;
            }
            2 => {
                doc[section_parts[0]][section_parts[1]][key.as_str()] = toml_item;
            }
            3 => {
                doc[section_parts[0]][section_parts[1]][section_parts[2]][key.as_str()] = toml_item;
            }
            _ => {
                return Json(serde_json::json!({
                    "status": "error",
                    "message": "Section nesting deeper than 3 levels is not supported."
                }));
            }
        }
    }

    // Write to disk
    if let Err(e) = std::fs::write(&config_path, doc.to_string()) {
        warn!(error = %e, "Failed to write config file");
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to write config: {}", e)
        }));
    }

    // Re-validate
    let warnings = match std::fs::read_to_string(&config_path) {
        Ok(raw) => match toml::from_str::<crate::config::schema::AegisConfig>(&raw) {
            Ok(cfg) => {
                let result = crate::config::validate::validate_config(&cfg);
                result.warnings
            }
            Err(_) => vec![],
        },
        Err(_) => vec![],
    };

    Json(serde_json::json!({
        "status": "ok",
        "requires_restart": true,
        "warnings": warnings,
    }))
}

/// Convert a JSON value to a toml_edit Item.
fn json_to_toml_value(val: &serde_json::Value) -> Option<toml_edit::Item> {
    match val {
        serde_json::Value::Bool(b) => Some(toml_edit::value(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(toml_edit::value(i))
            } else {
                n.as_f64().map(toml_edit::value)
            }
        }
        serde_json::Value::String(s) => Some(toml_edit::value(s.as_str())),
        serde_json::Value::Array(arr) => {
            let mut toml_arr = toml_edit::Array::new();
            for item in arr {
                match item {
                    serde_json::Value::Bool(b) => toml_arr.push(*b),
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            toml_arr.push(i);
                        } else if let Some(f) = n.as_f64() {
                            toml_arr.push(f);
                        }
                    }
                    serde_json::Value::String(s) => toml_arr.push(s.as_str()),
                    _ => return None,
                }
            }
            Some(toml_edit::value(toml_arr))
        }
        serde_json::Value::Object(map) => {
            let mut table = toml_edit::InlineTable::new();
            for (k, v) in map {
                match v {
                    serde_json::Value::Bool(b) => {
                        table.insert(k, (*b).into());
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            table.insert(k, i.into());
                        } else if let Some(f) = n.as_f64() {
                            table.insert(k, f.into());
                        }
                    }
                    serde_json::Value::String(s) => {
                        table.insert(k, s.as_str().into());
                    }
                    _ => return None,
                }
            }
            Some(toml_edit::value(table))
        }
        _ => None,
    }
}

// ─── Module toggle ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ModuleToggleRequest {
    module: String,
    enabled: bool,
}

/// POST /api/module/toggle — Enable/disable a module and sync the modules list.
pub async fn api_module_toggle(
    State(_ctx): State<AppContext>,
    Json(payload): Json<ModuleToggleRequest>,
) -> Json<serde_json::Value> {
    if !VALID_MODULES.contains(&payload.module.as_str()) {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Invalid module: '{}'. Valid: {}", payload.module, VALID_MODULES.join(", "))
        }));
    }

    let config_path = match find_config_path(None) {
        Some(p) => p,
        None => {
            return Json(serde_json::json!({
                "status": "error",
                "message": "No config file found."
            }));
        }
    };

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to read config file");
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to read config: {}", e)
            }));
        }
    };

    let mut doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Failed to parse config file");
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to parse config: {}", e)
            }));
        }
    };

    // Ensure the module section exists
    if !doc.contains_key(&payload.module) {
        doc[&payload.module] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc[&payload.module]["enabled"] = toml_edit::value(payload.enabled);

    // Auto-sync [general].modules list
    if !doc.contains_key("general") {
        doc["general"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    // Read current modules list
    let current_modules: Vec<String> = doc["general"]
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let has_module = current_modules.iter().any(|m| m == &payload.module);

    if payload.enabled && !has_module {
        // Add module to list
        let mut new_arr = toml_edit::Array::new();
        for m in &current_modules {
            new_arr.push(m.as_str());
        }
        new_arr.push(payload.module.as_str());
        doc["general"]["modules"] = toml_edit::value(new_arr);
    } else if !payload.enabled && has_module {
        // Remove module from list
        let mut new_arr = toml_edit::Array::new();
        for m in &current_modules {
            if m != &payload.module {
                new_arr.push(m.as_str());
            }
        }
        doc["general"]["modules"] = toml_edit::value(new_arr);
    }

    if let Err(e) = std::fs::write(&config_path, doc.to_string()) {
        warn!(error = %e, "Failed to write config file");
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to write config: {}", e)
        }));
    }

    let state_str = if payload.enabled {
        "enabled"
    } else {
        "disabled"
    };

    Json(serde_json::json!({
        "status": "ok",
        "requires_restart": true,
        "message": format!("Module '{}' {}. Restart aegis to apply.", payload.module, state_str)
    }))
}

// ─── Smart discovery: ports ───────────────────────────────────────────────────

/// Common attack-target ports for honeypot suggestions.
const HONEYPOT_CANDIDATE_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (23, "Telnet"),
    (25, "SMTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (445, "SMB"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (2222, "alt-SSH"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (4444, "Metasploit"),
    (5432, "Postgres"),
    (5555, "ADB"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (9200, "Elasticsearch"),
    (27017, "MongoDB"),
];

/// GET /api/discover/ports — Discover listening ports and suggest honeypot ports.
pub async fn api_discover_ports(State(_ctx): State<AppContext>) -> Json<serde_json::Value> {
    let mut listening_ports: HashSet<u16> = HashSet::new();

    for proc_path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let path = Path::new(proc_path);
        if let Ok(content) = proc_parse::read_proc_file(path) {
            for line in content.lines().skip(1) {
                if let Ok((_lip, lport, _rip, _rport, state)) = proc_parse::parse_tcp_line(line) {
                    if state == proc_parse::tcp_state::LISTEN && lport > 0 {
                        listening_ports.insert(lport);
                    }
                }
            }
        }
    }

    let mut listening_sorted: Vec<u16> = listening_ports.iter().copied().collect();
    listening_sorted.sort();

    let suggested: Vec<serde_json::Value> = HONEYPOT_CANDIDATE_PORTS
        .iter()
        .filter(|(port, _)| !listening_ports.contains(port))
        .map(|(port, label)| serde_json::json!({ "port": port, "service": label }))
        .collect();

    Json(serde_json::json!({
        "listening_ports": listening_sorted,
        "suggested_honeypot_ports": suggested,
    }))
}

// ─── Smart discovery: nginx SSL domains ───────────────────────────────────────

/// GET /api/discover/domains — Scan nginx configs for SSL-enabled domains.
pub async fn api_discover_domains(State(_ctx): State<AppContext>) -> Json<serde_json::Value> {
    let mut domains: HashSet<String> = HashSet::new();
    let mut errors: Vec<String> = Vec::new();

    let config_dirs = ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"];
    let single_files = ["/etc/nginx/nginx.conf"];

    let mut files_to_scan: Vec<std::path::PathBuf> = Vec::new();

    for dir in &config_dirs {
        let path = Path::new(dir);
        if path.is_dir() {
            match std::fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            files_to_scan.push(p);
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Cannot read {}: {}", dir, e));
                }
            }
        }
    }

    for f in &single_files {
        let path = Path::new(f);
        if path.is_file() {
            files_to_scan.push(path.to_path_buf());
        }
    }

    for file_path in &files_to_scan {
        match std::fs::read_to_string(file_path) {
            Ok(content) => {
                parse_nginx_ssl_domains(&content, &mut domains);
            }
            Err(e) => {
                errors.push(format!("Cannot read {}: {}", file_path.display(), e));
            }
        }
    }

    let mut domain_list: Vec<String> = domains.into_iter().collect();
    domain_list.sort();

    Json(serde_json::json!({
        "domains": domain_list,
        "errors": errors,
    }))
}

// ─── Restart endpoint ─────────────────────────────────────────────────────────

/// POST /api/restart — Restart the aegis daemon via systemctl.
///
/// Safe because: aegis already runs as root, the WebUI is localhost-only with
/// token auth, and an attacker with the token can already modify config files.
/// This just applies changes without requiring SSH access.
pub async fn api_restart(State(_ctx): State<AppContext>) -> Json<serde_json::Value> {
    info!("Restart requested via WebUI");

    // Spawn the restart in a background task with a short delay
    // so the HTTP response can be sent before the process is killed.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        info!("Executing systemctl restart aegis");
        let _ = std::process::Command::new("systemctl")
            .args(["restart", "aegis"])
            .spawn();
    });

    Json(serde_json::json!({
        "status": "ok",
        "message": "Restarting aegis... The page will reconnect automatically."
    }))
}

/// Heuristic parser for nginx configs: find server blocks with both
/// server_name and ssl_certificate directives.
fn parse_nginx_ssl_domains(content: &str, domains: &mut HashSet<String>) {
    // Track state per server block (approximation: brace depth)
    let mut depth: i32 = 0;
    let mut in_server_block = false;
    let mut server_names: Vec<String> = Vec::new();
    let mut has_ssl = false;
    let mut server_depth: i32 = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Track brace depth
        let opens = trimmed.chars().filter(|&c| c == '{').count() as i32;
        let closes = trimmed.chars().filter(|&c| c == '}').count() as i32;

        if trimmed.starts_with("server") && trimmed.contains('{') && !in_server_block {
            in_server_block = true;
            server_names.clear();
            has_ssl = false;
            server_depth = depth;
        }

        depth += opens;
        depth -= closes;

        if in_server_block {
            // Parse server_name directive
            if trimmed.starts_with("server_name") {
                let names_part = trimmed
                    .trim_start_matches("server_name")
                    .trim_end_matches(';')
                    .trim();
                for name in names_part.split_whitespace() {
                    let name = name.trim();
                    // Filter out catch-all and dot-prefixed patterns
                    if name != "_" && !name.starts_with('.') && !name.is_empty() {
                        server_names.push(name.to_string());
                    }
                }
            }

            // Detect SSL
            if trimmed.starts_with("ssl_certificate") && !trimmed.starts_with("ssl_certificate_key")
            {
                has_ssl = true;
            }
            if trimmed.contains("listen") && trimmed.contains("ssl") {
                has_ssl = true;
            }

            // Check if server block closed
            if depth <= server_depth {
                if has_ssl {
                    for name in &server_names {
                        domains.insert(name.clone());
                    }
                }
                in_server_block = false;
                server_names.clear();
                has_ssl = false;
            }
        }
    }
}
