use axum::{
    extract::State,
    response::{Html, Json},
};

use crate::core::threat::ThreatSeverity;
use crate::web::server::AppContext;
use crate::web::templates;

pub async fn status_page(State(ctx): State<AppContext>) -> Html<String> {
    let state = ctx.state.read().await;
    let config = &ctx.config;

    let all_modules = [
        ("network", config.network.enabled),
        ("process", config.process.enabled),
        ("file_integrity", config.file_integrity.enabled),
        ("auth", config.auth.enabled),
        ("web", config.web.enabled),
        ("threat_intel", config.threat_intel.enabled),
        ("anomaly", config.anomaly.enabled),
        ("honeypot", config.honeypot.enabled),
    ];

    let mut module_cards = String::new();
    for (name, enabled) in &all_modules {
        let label = name.replace('_', " ");
        let label = label
            .split(' ')
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().to_string() + c.as_str(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let (badge_class, badge_text) = if *enabled {
            ("status-enabled", "Enabled")
        } else {
            ("status-disabled", "Disabled")
        };
        let in_config = config.general.modules.contains(&name.to_string());
        let config_note = if *enabled && !in_config {
            r#" <span style="color:var(--accent-gold);font-size:11px">(not in modules list)</span>"#
        } else {
            ""
        };
        module_cards.push_str(&format!(
            r#"<div class="module-card">
                <h4>{label}{config_note}</h4>
                <span class="status-badge {badge_class}">{badge_text}</span>
            </div>"#,
        ));
    }

    // Threat breakdown by type
    let mut type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut top_ips: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for t in &state.threats {
        *type_counts.entry(format!("{}", t.threat_type)).or_insert(0) += 1;
        if let Some(ip) = t.source_ip {
            *top_ips.entry(ip.to_string()).or_insert(0) += 1;
        }
    }

    let mut top_ips_sorted: Vec<_> = top_ips.into_iter().collect();
    top_ips_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    top_ips_sorted.truncate(10);

    let mut top_ips_rows = String::new();
    for (ip, count) in &top_ips_sorted {
        top_ips_rows.push_str(&format!(
            r#"<tr>
                <td>{ip}</td>
                <td>{count}</td>
                <td><button class="btn-sm" onclick="blockIp('{ip}')">Block</button></td>
            </tr>"#,
        ));
    }

    let counts = state.threat_counts();
    let posture = format!("{}", state.posture);

    let hostname = nix::sys::utsname::uname()
        .map(|u| u.nodename().to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let kernel = nix::sys::utsname::uname()
        .map(|u| u.release().to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let content = format!(
        r#"
        <div class="cards">
            <div class="card">
                <div class="card-label">Hostname</div>
                <div class="card-value" style="font-size:16px">{hostname}</div>
            </div>
            <div class="card">
                <div class="card-label">Kernel</div>
                <div class="card-value" style="font-size:16px">{kernel}</div>
            </div>
            <div class="card">
                <div class="card-label">Security Posture</div>
                <div class="card-value" style="font-size:16px">{posture}</div>
            </div>
            <div class="card">
                <div class="card-label">Total Threats</div>
                <div class="card-value">{total_threats}</div>
            </div>
        </div>
        <div class="section">
            <h3>Module Health</h3>
            <div class="module-grid">{module_cards}</div>
        </div>
        <div class="section">
            <h3>Threat Breakdown</h3>
            <div class="cards">
                <div class="card">
                    <div class="card-label critical">Critical</div>
                    <div class="card-value">{critical}</div>
                </div>
                <div class="card">
                    <div class="card-label high">High</div>
                    <div class="card-value">{high}</div>
                </div>
                <div class="card">
                    <div class="card-label medium">Medium</div>
                    <div class="card-value">{medium}</div>
                </div>
                <div class="card">
                    <div class="card-label low">Low</div>
                    <div class="card-value">{low}</div>
                </div>
                <div class="card">
                    <div class="card-label info">Info</div>
                    <div class="card-value">{info_count}</div>
                </div>
            </div>
        </div>
        <div class="section">
            <h3>Top Attacking IPs</h3>
            <table class="threats-table">
                <thead><tr><th>IP Address</th><th>Threat Count</th><th>Actions</th></tr></thead>
                <tbody>{top_ips_rows}</tbody>
            </table>
        </div>
        "#,
        hostname = templates::html_escape_pub(&hostname),
        kernel = templates::html_escape_pub(&kernel),
        posture = posture,
        total_threats = state.threats.len(),
        module_cards = module_cards,
        critical = counts.get(&ThreatSeverity::Critical).copied().unwrap_or(0),
        high = counts.get(&ThreatSeverity::High).copied().unwrap_or(0),
        medium = counts.get(&ThreatSeverity::Medium).copied().unwrap_or(0),
        low = counts.get(&ThreatSeverity::Low).copied().unwrap_or(0),
        info_count = counts.get(&ThreatSeverity::Info).copied().unwrap_or(0),
        top_ips_rows = top_ips_rows,
    );

    Html(templates::render_status_page(&content, &ctx.api_token))
}

pub async fn api_status(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let config = &ctx.config;
    let counts = state.threat_counts();

    let modules: Vec<_> = [
        ("network", config.network.enabled),
        ("process", config.process.enabled),
        ("file_integrity", config.file_integrity.enabled),
        ("auth", config.auth.enabled),
        ("web", config.web.enabled),
        ("threat_intel", config.threat_intel.enabled),
        ("anomaly", config.anomaly.enabled),
        ("honeypot", config.honeypot.enabled),
    ]
    .iter()
    .map(|(name, enabled)| serde_json::json!({ "name": name, "enabled": enabled }))
    .collect();

    let hostname = nix::sys::utsname::uname()
        .map(|u| u.nodename().to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let kernel = nix::sys::utsname::uname()
        .map(|u| u.release().to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Json(serde_json::json!({
        "hostname": hostname,
        "kernel": kernel,
        "posture": format!("{}", state.posture),
        "total_threats": state.threats.len(),
        "blocked_ips": state.blocked_ips.len(),
        "modules": modules,
        "severity": {
            "critical": counts.get(&ThreatSeverity::Critical).copied().unwrap_or(0),
            "high": counts.get(&ThreatSeverity::High).copied().unwrap_or(0),
            "medium": counts.get(&ThreatSeverity::Medium).copied().unwrap_or(0),
            "low": counts.get(&ThreatSeverity::Low).copied().unwrap_or(0),
            "info": counts.get(&ThreatSeverity::Info).copied().unwrap_or(0),
        },
    }))
}
