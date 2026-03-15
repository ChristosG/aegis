use crate::core::state::AppState;
use crate::core::threat::ThreatSeverity;

const STYLE: &str = include_str!("static/style.css");
const APP_JS: &str = include_str!("static/app.js");

fn page_wrapper(title: &str, content: &str, token: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Aegis Dashboard</title>
    <style>{STYLE}</style>
</head>
<body>
    <nav class="sidebar">
        <div class="logo">AEGIS</div>
        <a href="/?token={token}" class="nav-link">Dashboard</a>
        <a href="/threats?token={token}" class="nav-link">Threats</a>
        <a href="/firewall?token={token}" class="nav-link">Firewall</a>
    </nav>
    <main class="content">
        <header class="top-bar">
            <h1>{title}</h1>
            <span class="version">v{version}</span>
        </header>
        <div class="main-content">
            {content}
        </div>
    </main>
    <div id="modal-overlay" class="modal-overlay" style="display:none" onclick="closeModal(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h3 id="modal-title"></h3>
                <button class="modal-close" onclick="hideModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body"></div>
            <div class="modal-footer" id="modal-footer"></div>
        </div>
    </div>
    <script>const API_TOKEN = "{token}";</script>
    <script>{APP_JS}</script>
</body>
</html>"#,
        title = title,
        content = content,
        token = token,
        version = env!("CARGO_PKG_VERSION"),
    )
}

pub fn render_dashboard(state: &AppState, token: &str) -> String {
    let counts = state.threat_counts();
    let critical = counts.get(&ThreatSeverity::Critical).copied().unwrap_or(0);
    let high = counts.get(&ThreatSeverity::High).copied().unwrap_or(0);
    let medium = counts.get(&ThreatSeverity::Medium).copied().unwrap_or(0);
    let low = counts.get(&ThreatSeverity::Low).copied().unwrap_or(0);
    let info_count = counts.get(&ThreatSeverity::Info).copied().unwrap_or(0);

    let posture_class = match state.posture {
        crate::core::state::SecurityPosture::Secure => "posture-secure",
        crate::core::state::SecurityPosture::Guarded => "posture-guarded",
        crate::core::state::SecurityPosture::Elevated => "posture-elevated",
        crate::core::state::SecurityPosture::High => "posture-high",
        crate::core::state::SecurityPosture::Critical => "posture-critical",
    };

    let recent_threats: String = state
        .threats
        .iter()
        .rev()
        .take(30)
        .map(|t| {
            let sev_class = severity_class(t.severity);
            let sev_lower = format!("{}", t.severity).to_lowercase();
            let ip = t.source_ip.map_or("N/A".to_string(), |ip| ip.to_string());
            let full_desc = html_escape(&t.description);
            format!(
                r#"<tr data-severity="{sev_lower}">
                    <td class="{sev_class}">{severity}</td>
                    <td>{threat_type}</td>
                    <td class="has-tooltip" data-tooltip="{full_desc}">{description}</td>
                    <td>{ip}</td>
                    <td>{time}</td>
                </tr>"#,
                sev_lower = sev_lower,
                sev_class = sev_class,
                severity = t.severity,
                threat_type = t.threat_type,
                full_desc = full_desc,
                description = truncate(&t.description, 80),
                ip = ip,
                time = t.timestamp.format("%H:%M:%S"),
            )
        })
        .collect();

    let content = format!(
        r#"
        <div class="cards">
            <div class="card {posture_class}" id="card-posture">
                <div class="card-label">Security Posture</div>
                <div class="card-value" data-stat="posture">{posture}</div>
            </div>
            <div class="card">
                <div class="card-label">Total Threats</div>
                <div class="card-value" data-stat="total-threats">{total}</div>
            </div>
            <div class="card">
                <div class="card-label">Blocked IPs</div>
                <div class="card-value" data-stat="blocked-ips">{blocked}</div>
            </div>
            <div class="card">
                <div class="card-label">Scans Run</div>
                <div class="card-value" data-stat="scans-run">{scans}</div>
            </div>
        </div>
        <div class="severity-breakdown">
            <h3>Severity Breakdown</h3>
            <div class="severity-bars">
                <div class="sev-row sev-filter-btn" data-filter-sev="critical" onclick="filterBySeverity('critical')"><span class="sev-label critical">Critical</span><span class="sev-count" data-sev="critical">{critical}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="high" onclick="filterBySeverity('high')"><span class="sev-label high">High</span><span class="sev-count" data-sev="high">{high}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="medium" onclick="filterBySeverity('medium')"><span class="sev-label medium">Medium</span><span class="sev-count" data-sev="medium">{medium}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="low" onclick="filterBySeverity('low')"><span class="sev-label low">Low</span><span class="sev-count" data-sev="low">{low}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="info" onclick="filterBySeverity('info')"><span class="sev-label info">Info</span><span class="sev-count" data-sev="info">{info_count}</span></div>
            </div>
        </div>
        <div class="actions">
            <h3>Quick Actions</h3>
            <button onclick="triggerScan()">Run Scan</button>
            <button onclick="triggerAutoRespond()">Auto-Respond</button>
            <button onclick="exportReport()">Export Report</button>
        </div>
        <div class="section">
            <h3>Recent Threats</h3>
            <div id="live-threats"></div>
            <div id="filter-bar" class="filter-bar" style="display:none"></div>
            <table class="threats-table" id="dashboard-threats-table">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('dashboard-threats-table',0)">Severity</th>
                        <th class="sortable" onclick="sortTable('dashboard-threats-table',1)">Type</th>
                        <th class="sortable" onclick="sortTable('dashboard-threats-table',2)">Description</th>
                        <th class="sortable" onclick="sortTable('dashboard-threats-table',3)">Source IP</th>
                        <th class="sortable" onclick="sortTable('dashboard-threats-table',4)">Time</th>
                    </tr>
                </thead>
                <tbody id="recent-threats-body">{recent_threats}</tbody>
            </table>
        </div>
        "#,
        posture_class = posture_class,
        posture = state.posture,
        total = state.threats.len(),
        blocked = state.blocked_ips.len(),
        scans = state.stats.scans_run,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info_count = info_count,
        recent_threats = recent_threats,
    );

    page_wrapper("Dashboard", &content, token)
}

pub fn render_threats_page(state: &AppState, token: &str) -> String {
    let rows: String = state
        .threats
        .iter()
        .rev()
        .map(|t| {
            let sev_class = severity_class(t.severity);
            let sev_lower = format!("{}", t.severity).to_lowercase();
            let ip = t.source_ip.map_or("N/A".to_string(), |ip| ip.to_string());
            let responded = if t.auto_responded { "Yes" } else { "No" };
            let full_desc = html_escape(&t.description);
            format!(
                r#"<tr data-severity="{sev_lower}">
                    <td class="{sev_class}">{severity}</td>
                    <td>{threat_type}</td>
                    <td class="has-tooltip" data-tooltip="{full_desc}">{description}</td>
                    <td>{ip}</td>
                    <td>{module}</td>
                    <td>{responded}</td>
                    <td>{time}</td>
                    <td>
                        {block_btn}
                    </td>
                </tr>"#,
                sev_lower = sev_lower,
                sev_class = sev_class,
                severity = t.severity,
                threat_type = t.threat_type,
                full_desc = full_desc,
                description = truncate(&t.description, 60),
                ip = ip,
                module = t.source_module,
                responded = responded,
                time = t.timestamp.format("%Y-%m-%d %H:%M:%S"),
                block_btn = if t.source_ip.is_some() {
                    format!(
                        r#"<button class="btn-sm" onclick="blockIp('{}')">Block</button>"#,
                        ip
                    )
                } else {
                    String::new()
                },
            )
        })
        .collect();

    let counts = state.threat_counts();
    let critical = counts.get(&ThreatSeverity::Critical).copied().unwrap_or(0);
    let high = counts.get(&ThreatSeverity::High).copied().unwrap_or(0);
    let medium = counts.get(&ThreatSeverity::Medium).copied().unwrap_or(0);
    let low = counts.get(&ThreatSeverity::Low).copied().unwrap_or(0);
    let info_count = counts.get(&ThreatSeverity::Info).copied().unwrap_or(0);

    let content = format!(
        r#"
        <div id="live-threats"></div>
        <div class="severity-breakdown">
            <h3>Severity Filter</h3>
            <div class="severity-bars">
                <div class="sev-row sev-filter-btn" data-filter-sev="critical" onclick="filterBySeverity('critical')"><span class="sev-label critical">Critical</span><span class="sev-count">{critical}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="high" onclick="filterBySeverity('high')"><span class="sev-label high">High</span><span class="sev-count">{high}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="medium" onclick="filterBySeverity('medium')"><span class="sev-label medium">Medium</span><span class="sev-count">{medium}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="low" onclick="filterBySeverity('low')"><span class="sev-label low">Low</span><span class="sev-count">{low}</span></div>
                <div class="sev-row sev-filter-btn" data-filter-sev="info" onclick="filterBySeverity('info')"><span class="sev-label info">Info</span><span class="sev-count">{info_count}</span></div>
            </div>
        </div>
        <div id="filter-bar" class="filter-bar" style="display:none"></div>
        <table class="threats-table" id="threats-page-table">
            <thead>
                <tr>
                    <th class="sortable" onclick="sortTable('threats-page-table',0)">Severity</th>
                    <th class="sortable" onclick="sortTable('threats-page-table',1)">Type</th>
                    <th class="sortable" onclick="sortTable('threats-page-table',2)">Description</th>
                    <th class="sortable" onclick="sortTable('threats-page-table',3)">Source IP</th>
                    <th class="sortable" onclick="sortTable('threats-page-table',4)">Module</th>
                    <th class="sortable" onclick="sortTable('threats-page-table',5)">Responded</th>
                    <th class="sortable" onclick="sortTable('threats-page-table',6)">Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="threats-table-body">{rows}</tbody>
        </table>
        "#,
        rows = rows,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info_count = info_count,
    );

    page_wrapper("Threats", &content, token)
}

pub fn render_firewall_page(state: &AppState, token: &str) -> String {
    let block_rows: String = state
        .blocked_ips
        .values()
        .map(|b| {
            let expired = b
                .expires_at
                .is_some_and(|exp| exp < chrono::Utc::now());
            let expires_str = b
                .expires_at
                .map_or("Never".to_string(), |exp| exp.format("%Y-%m-%d %H:%M:%S").to_string());
            let row_class = if expired { r#" class="row-expired""# } else { "" };
            let expired_tag = if expired { " (expired)" } else { "" };
            let auto_str = if b.auto { "Yes" } else { "No" };
            format!(
                r#"<tr{row_class}>
                    <td>{ip}</td>
                    <td>{reason}</td>
                    <td>{blocked_at}</td>
                    <td>{expires}{expired_tag}</td>
                    <td>{auto_str}</td>
                    <td><button class="btn-sm" onclick="fwUnblock('{ip}')">Unblock</button></td>
                </tr>"#,
                row_class = row_class,
                ip = b.ip,
                reason = html_escape(&b.reason),
                blocked_at = b.blocked_at.format("%Y-%m-%d %H:%M:%S"),
                expires = expires_str,
                expired_tag = expired_tag,
                auto_str = auto_str,
            )
        })
        .collect();

    let wl_rows: String = state
        .config
        .response
        .whitelist
        .iter()
        .map(|cidr| {
            format!(
                r#"<tr>
                    <td>{cidr}</td>
                    <td><button class="btn-sm" onclick="fwRemoveWhitelist('{cidr}')">Remove</button></td>
                </tr>"#,
                cidr = html_escape(cidr),
            )
        })
        .collect();

    let content = format!(
        r#"
        <div class="section">
            <h3>Block IP</h3>
            <div class="fw-form">
                <input type="text" id="block-ip-input" class="fw-input" placeholder="IP address" />
                <input type="text" id="block-reason-input" class="fw-input fw-input-wide" placeholder="Reason (optional)" />
                <input type="text" id="block-duration-input" class="fw-input" placeholder="Duration (default: 24h)" />
                <button onclick="fwBlockIp()">Block</button>
            </div>
        </div>
        <div class="section">
            <h3>Blocked IPs <span class="section-count" id="block-count">{block_count}</span></h3>
            <table class="threats-table" id="blocks-table">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('blocks-table',0)">IP</th>
                        <th class="sortable" onclick="sortTable('blocks-table',1)">Reason</th>
                        <th class="sortable" onclick="sortTable('blocks-table',2)">Blocked At</th>
                        <th class="sortable" onclick="sortTable('blocks-table',3)">Expires</th>
                        <th class="sortable" onclick="sortTable('blocks-table',4)">Auto</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="blocks-table-body">{block_rows}</tbody>
            </table>
        </div>
        <div class="section">
            <h3>Add to Whitelist</h3>
            <div class="fw-form">
                <input type="text" id="wl-cidr-input" class="fw-input fw-input-wide" placeholder="IP or CIDR (e.g. 10.0.0.0/8)" />
                <button onclick="fwAddWhitelist()">Add</button>
            </div>
        </div>
        <div class="section">
            <h3>Whitelisted CIDRs <span class="section-count" id="wl-count">{wl_count}</span></h3>
            <table class="threats-table" id="whitelist-table">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('whitelist-table',0)">CIDR</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="whitelist-table-body">{wl_rows}</tbody>
            </table>
        </div>
        "#,
        block_count = state.blocked_ips.len(),
        block_rows = block_rows,
        wl_count = state.config.response.whitelist.len(),
        wl_rows = wl_rows,
    );

    page_wrapper("Firewall", &content, token)
}

fn severity_class(sev: ThreatSeverity) -> &'static str {
    match sev {
        ThreatSeverity::Critical => "sev-critical",
        ThreatSeverity::High => "sev-high",
        ThreatSeverity::Medium => "sev-medium",
        ThreatSeverity::Low => "sev-low",
        ThreatSeverity::Info => "sev-info",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
