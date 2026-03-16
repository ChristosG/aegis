use axum::{
    extract::State,
    response::{Html, Json},
};

use crate::core::threat::ThreatSeverity;
use crate::storage::StorageMetrics;
use crate::web::server::AppContext;
use crate::web::templates;

/// Format bytes into a human-readable string (e.g. "12.3 MB").
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Build the storage HTML section from metrics.
fn render_storage_section(m: &StorageMetrics) -> String {
    let age_text = match m.oldest_threat_age_days {
        Some(0) => "today".to_string(),
        Some(1) => "1 day".to_string(),
        Some(d) => format!("{} days", d),
        None => "n/a".to_string(),
    };

    let log_pct = if m.max_log_size > 0 {
        (m.active_log.size as f64 / m.max_log_size as f64 * 100.0).min(100.0) as u32
    } else {
        0
    };
    let bar_color = if log_pct > 80 {
        "var(--accent-red)"
    } else if log_pct > 50 {
        "var(--accent-gold)"
    } else {
        "var(--accent-green)"
    };

    let mut rotated_rows = String::new();
    for (i, f) in m.rotated_logs.iter().enumerate() {
        rotated_rows.push_str(&format!(
            "<tr><td>threats.jsonl.{}</td><td>{}</td></tr>",
            i + 1,
            format_bytes(f.size)
        ));
    }
    if m.rotated_logs.is_empty() {
        rotated_rows
            .push_str(r#"<tr><td colspan="2" style="opacity:0.5">No rotated logs</td></tr>"#);
    }

    format!(
        r#"
        <div class="section">
            <h3>Storage</h3>
            <div class="cards">
                <div class="card">
                    <div class="card-label">Total Disk Usage</div>
                    <div class="card-value" style="font-size:18px">{total}</div>
                </div>
                <div class="card">
                    <div class="card-label">Threat Logs</div>
                    <div class="card-value" style="font-size:18px">{log_total}</div>
                </div>
                <div class="card">
                    <div class="card-label">Rotated Files</div>
                    <div class="card-value">{rotated_count} / {max_files}</div>
                </div>
                <div class="card">
                    <div class="card-label">Oldest Event</div>
                    <div class="card-value" style="font-size:16px">{age_text}</div>
                </div>
            </div>

            <div style="margin:16px 0">
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span style="font-size:13px">Active log: <strong>{active_size}</strong></span>
                    <span style="font-size:13px">{log_pct}% of {max_size} limit</span>
                </div>
                <div style="background:var(--card-bg);border-radius:6px;height:10px;overflow:hidden">
                    <div style="width:{log_pct}%;height:100%;background:{bar_color};border-radius:6px;transition:width 0.3s"></div>
                </div>
            </div>

            <table class="threats-table" style="margin-top:12px">
                <thead><tr><th>File</th><th>Size</th></tr></thead>
                <tbody>
                    <tr><td>threats.jsonl (active)</td><td>{active_size}</td></tr>
                    {rotated_rows}
                    <tr><td>block_list.json</td><td>{block_size}</td></tr>
                    <tr><td>seen_fingerprints.json</td><td>{seen_size}</td></tr>
                    <tr><td>baseline.json</td><td>{baseline_size}</td></tr>
                    <tr><td>feeds/</td><td>{feeds_size}</td></tr>
                    <tr><td>quarantine/</td><td>{quarantine_size}</td></tr>
                </tbody>
            </table>

            <div style="margin-top:16px">
                <button class="btn-sm" onclick="cleanupStorage()" style="background:var(--accent-red)">
                    Purge Old Logs &amp; Dedup Cache
                </button>
                <span id="cleanup-result" style="margin-left:12px;font-size:13px"></span>
            </div>
            <p style="font-size:12px;opacity:0.5;margin-top:8px">
                Cleanup removes rotated log files and the dedup fingerprint cache.
                Active log, baseline, and block list are preserved.
            </p>
        </div>
        <script>
        function cleanupStorage() {{
            if (!confirm('Purge rotated threat logs and dedup cache?')) return;
            var token = document.querySelector('meta[name=api-token]');
            var headers = {{'Content-Type':'application/json'}};
            if (token && token.content) headers['Authorization'] = 'Bearer ' + token.content;
            fetch('/api/storage/cleanup', {{method:'POST', headers: headers}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    document.getElementById('cleanup-result').textContent =
                        'Freed ' + d.freed_human + '. Refresh to see updated metrics.';
                }})
                .catch(function(e) {{
                    document.getElementById('cleanup-result').textContent = 'Error: ' + e;
                }});
        }}
        </script>
        "#,
        total = format_bytes(m.total_bytes),
        log_total = format_bytes(m.total_log_bytes),
        rotated_count = m.rotated_logs.len(),
        max_files = m.max_log_files,
        age_text = age_text,
        active_size = format_bytes(m.active_log.size),
        log_pct = log_pct,
        max_size = format_bytes(m.max_log_size),
        bar_color = bar_color,
        rotated_rows = rotated_rows,
        block_size = format_bytes(m.block_list.size),
        seen_size = format_bytes(m.seen_threats.size),
        baseline_size = format_bytes(m.baseline.size),
        feeds_size = format_bytes(m.feeds_size),
        quarantine_size = format_bytes(m.quarantine_size),
    )
}

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
        ("cert", config.cert.enabled),
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
        {storage_section}
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
        storage_section = render_storage_section(&ctx.storage.storage_metrics()),
    );

    let token = if ctx.auth_required {
        &ctx.api_token
    } else {
        ""
    };
    Html(templates::render_status_page(&content, token))
}

pub async fn api_storage(State(ctx): State<AppContext>) -> Json<StorageMetrics> {
    Json(ctx.storage.storage_metrics())
}

pub async fn api_storage_cleanup(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    match ctx.storage.cleanup_storage() {
        Ok(freed) => Json(serde_json::json!({
            "ok": true,
            "freed_bytes": freed,
            "freed_human": format_bytes(freed),
        })),
        Err(e) => Json(serde_json::json!({
            "ok": false,
            "error": e.to_string(),
        })),
    }
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
        ("cert", config.cert.enabled),
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
