use crate::core::state::AppState;
use crate::core::threat::ThreatSeverity;

const STYLE: &str = include_str!("static/style.css");
const APP_JS: &str = include_str!("static/app.js");

fn page_wrapper(title: &str, content: &str, token: &str, current_page: &str) -> String {
    let init_done = std::path::Path::new("/etc/aegis/.init_done").exists();
    let init_banner = if init_done {
        ""
    } else {
        r#"<div style="background:#d29922;color:#0d1117;padding:10px 16px;font-size:13px;font-weight:600;text-align:center;border-radius:6px;margin-bottom:16px">
            System hardening not configured. Run <code style="background:rgba(0,0,0,0.15);padding:2px 6px;border-radius:3px">sudo aegis init</code> for full setup (kernel hardening, fail2ban, file integrity baseline).
        </div>"#
    };

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
    <div class="sidebar-overlay" id="sidebar-overlay" onclick="toggleSidebar()"></div>
    <nav class="sidebar" id="sidebar" role="navigation" aria-label="Main navigation">
        <div class="logo">AEGIS</div>
        <a href="/?token={token}" class="nav-link{dash_active}">Dashboard</a>
        <a href="/threats?token={token}" class="nav-link{threats_active}">Threats</a>
        <a href="/firewall?token={token}" class="nav-link{firewall_active}">Firewall</a>
        <a href="/status?token={token}" class="nav-link{status_active}">Status</a>
        <a href="/config?token={token}" class="nav-link{config_active}">Config</a>
        <a href="/logs?token={token}" class="nav-link{logs_active}">Logs</a>
    </nav>
    <main class="content" role="main">
        <header class="top-bar">
            <div style="display:flex;align-items:center;gap:12px">
                <button class="hamburger" onclick="toggleSidebar()" aria-label="Toggle navigation">&#9776;</button>
                <h1>{title}</h1>
            </div>
            <span class="version">v{version}</span>
        </header>
        <div class="main-content">
            {init_banner}
            {content}
        </div>
    </main>
    <div id="modal-overlay" class="modal-overlay" style="display:none" onclick="closeModal(event)" role="dialog" aria-modal="true">
        <div class="modal" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h3 id="modal-title"></h3>
                <button class="modal-close" onclick="hideModal()" aria-label="Close">&times;</button>
            </div>
            <div class="modal-body" id="modal-body"></div>
            <div class="modal-footer" id="modal-footer"></div>
        </div>
    </div>
    <div id="tooltip-popup" class="tooltip-popup" style="display:none"></div>
    <script>const API_TOKEN = "{token}";</script>
    <script>{APP_JS}</script>
</body>
</html>"#,
        title = title,
        content = content,
        token = token,
        init_banner = init_banner,
        version = env!("CARGO_PKG_VERSION"),
        dash_active = if current_page == "dashboard" {
            " active"
        } else {
            ""
        },
        threats_active = if current_page == "threats" {
            " active"
        } else {
            ""
        },
        firewall_active = if current_page == "firewall" {
            " active"
        } else {
            ""
        },
        status_active = if current_page == "status" {
            " active"
        } else {
            ""
        },
        config_active = if current_page == "config" {
            " active"
        } else {
            ""
        },
        logs_active = if current_page == "logs" {
            " active"
        } else {
            ""
        },
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
            let threat_type_snake = format!("{}", t.threat_type)
                .to_lowercase()
                .replace(' ', "_");
            let ip = t.source_ip.map_or("N/A".to_string(), |ip| ip.to_string());
            let full_desc = html_escape(&t.description);
            let threat_json = html_escape(&threat_to_json(t));
            format!(
                r#"<tr data-severity="{sev_lower}" data-threat-type="{threat_type_snake}" data-threat-json="{threat_json}" class="clickable-row">
                    <td class="{sev_class}">{severity}</td>
                    <td>{threat_type}</td>
                    <td class="has-tooltip" data-tooltip="{full_desc}">{description}</td>
                    <td>{ip}</td>
                    <td data-ts="{iso}">{time}</td>
                </tr>"#,
                sev_lower = sev_lower,
                threat_type_snake = threat_type_snake,
                threat_json = threat_json,
                sev_class = sev_class,
                severity = t.severity,
                threat_type = t.threat_type,
                full_desc = full_desc,
                description = truncate(&t.description, 80),
                ip = ip,
                iso = t.timestamp.to_rfc3339(),
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
            <button onclick="viewReport()">View Report</button>
        </div>
        <div class="section">
            <h3 style="display:inline">Recent Threats</h3>
            <button class="btn-toggle active" id="fi-toggle-dash" onclick="toggleFileIntegrity()">Show File Integrity</button>
            <div id="live-threats"></div>
            <div class="search-bar">
                <input type="text" class="search-input" id="search-input" placeholder="Search threats..." oninput="onSearchInput()" />
            </div>
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
            <div class="pagination" id="pagination-dashboard"></div>
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

    page_wrapper("Dashboard", &content, token, "dashboard")
}

pub fn render_threats_page(state: &AppState, token: &str) -> String {
    let rows: String = state
        .threats
        .iter()
        .rev()
        .map(|t| {
            let sev_class = severity_class(t.severity);
            let sev_lower = format!("{}", t.severity).to_lowercase();
            let threat_type_snake = format!("{}", t.threat_type)
                .to_lowercase()
                .replace(' ', "_");
            let ip = t.source_ip.map_or("N/A".to_string(), |ip| ip.to_string());
            let responded = if t.auto_responded { "Yes" } else { "No" };
            let full_desc = html_escape(&t.description);
            let threat_json = html_escape(&threat_to_json(t));
            format!(
                r#"<tr data-severity="{sev_lower}" data-threat-type="{threat_type_snake}" data-threat-json="{threat_json}" class="clickable-row">
                    <td class="{sev_class}">{severity}</td>
                    <td>{threat_type}</td>
                    <td class="has-tooltip" data-tooltip="{full_desc}">{description}</td>
                    <td>{ip}</td>
                    <td>{module}</td>
                    <td>{responded}</td>
                    <td data-ts="{iso}">{time}</td>
                    <td>
                        {block_btn}
                    </td>
                </tr>"#,
                sev_lower = sev_lower,
                threat_type_snake = threat_type_snake,
                threat_json = threat_json,
                sev_class = sev_class,
                severity = t.severity,
                threat_type = t.threat_type,
                full_desc = full_desc,
                description = truncate(&t.description, 60),
                ip = ip,
                module = t.source_module,
                responded = responded,
                iso = t.timestamp.to_rfc3339(),
                time = t.timestamp.format("%Y-%m-%d %H:%M:%S"),
                block_btn = if t.source_ip.is_some() {
                    format!(
                        r#"<button class="btn-sm" onclick="event.stopPropagation();blockIp('{}')">Block</button>"#,
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
        <div style="margin-bottom:12px">
            <button class="btn-toggle active" id="fi-toggle-threats" onclick="toggleFileIntegrity()">Show File Integrity</button>
        </div>
        <div class="search-bar">
            <input type="text" class="search-input" id="search-input" placeholder="Search threats..." oninput="onSearchInput()" />
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
        <div class="pagination" id="pagination-threats"></div>
        "#,
        rows = rows,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info_count = info_count,
    );

    page_wrapper("Threats", &content, token, "threats")
}

pub fn render_firewall_page(state: &AppState, token: &str, fi_enabled: bool) -> String {
    let threshold = state.config.response.repeat_offender_threshold;
    let block_rows: String = state
        .blocked_ips
        .values()
        .map(|b| {
            let expired = b.expires_at.is_some_and(|exp| exp < chrono::Utc::now());
            let expires_str = b.expires_at.map_or("Never".to_string(), |exp| {
                exp.format("%Y-%m-%d %H:%M:%S").to_string()
            });
            let expires_data_ts = b.expires_at.map_or(String::new(), |exp| {
                format!(r#" data-ts="{}""#, exp.to_rfc3339())
            });
            let row_class = if expired {
                r#" class="row-expired""#
            } else {
                ""
            };
            let expired_tag = if expired { " (expired)" } else { "" };
            let auto_str = if b.auto { "Yes" } else { "No" };
            let strike_info = state.strike_history.get(&b.ip);
            let strikes = strike_info.map_or(0, |r| r.strikes.len());
            let escalated = strike_info.is_some_and(|r| r.escalated);
            let strikes_str = if escalated {
                format!(
                    r#"<span style="color:#f85149;font-weight:600">{} (PERMA)</span>"#,
                    strikes
                )
            } else if threshold > 0 {
                format!("{}/{}", strikes, threshold)
            } else {
                format!("{}", strikes)
            };
            format!(
                r#"<tr{row_class}>
                    <td>{ip}</td>
                    <td>{reason}</td>
                    <td data-ts="{blocked_at_iso}">{blocked_at}</td>
                    <td{expires_data_ts}>{expires}{expired_tag}</td>
                    <td>{strikes_str}</td>
                    <td>{auto_str}</td>
                    <td><button class="btn-sm" onclick="fwUnblock('{ip}')">Unblock</button></td>
                </tr>"#,
                row_class = row_class,
                ip = b.ip,
                reason = html_escape(&b.reason),
                blocked_at_iso = b.blocked_at.to_rfc3339(),
                blocked_at = b.blocked_at.format("%Y-%m-%d %H:%M:%S"),
                expires_data_ts = expires_data_ts,
                expires = expires_str,
                expired_tag = expired_tag,
                strikes_str = strikes_str,
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
                <input type="text" id="block-duration-input" class="fw-input" placeholder="Duration (24h, 7d, or forever)" />
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
                        <th class="sortable" onclick="sortTable('blocks-table',4)">Strikes</th>
                        <th class="sortable" onclick="sortTable('blocks-table',5)">Auto</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="blocks-table-body">{block_rows}</tbody>
            </table>
        </div>
        <div class="section">
            <h3>File Integrity</h3>
            <p style="color:var(--text-muted);font-size:13px;margin-bottom:12px">
                Status: <strong id="fi-status">{fi_status}</strong>
            </p>
            <button id="fi-toggle-btn" onclick="toggleFI()">{fi_btn_label}</button>
            {fi_baseline_btns}
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
        fi_status = if fi_enabled { "Enabled" } else { "Disabled" },
        fi_btn_label = if fi_enabled {
            "Disable File Integrity"
        } else {
            "Enable File Integrity"
        },
        fi_baseline_btns = if fi_enabled {
            r#"<button onclick="resetBaseline()" style="margin-left:8px">Reset Baseline</button>
            <button onclick="createBaseline()" style="margin-left:8px">Create Baseline</button>"#
        } else {
            ""
        },
        wl_count = state.config.response.whitelist.len(),
        wl_rows = wl_rows,
    );

    page_wrapper("Firewall", &content, token, "firewall")
}

pub fn render_status_page(content: &str, token: &str) -> String {
    page_wrapper("Status", content, token, "status")
}

pub fn render_config_page(content: &str, token: &str) -> String {
    page_wrapper("Configuration", content, token, "config")
}

pub fn render_logs_page(content: &str, token: &str) -> String {
    page_wrapper("Logs", content, token, "logs")
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

pub fn html_escape_pub(s: &str) -> String {
    html_escape(s)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn threat_to_json(t: &crate::core::threat::ThreatEvent) -> String {
    serde_json::to_string(t).unwrap_or_default()
}
