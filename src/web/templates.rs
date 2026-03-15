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

pub fn render_dashboard(state: &AppState) -> String {
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
        .take(10)
        .map(|t| {
            let sev_class = severity_class(t.severity);
            let ip = t.source_ip.map_or("N/A".to_string(), |ip| ip.to_string());
            format!(
                r#"<tr>
                    <td class="{sev_class}">{severity}</td>
                    <td>{threat_type}</td>
                    <td>{description}</td>
                    <td>{ip}</td>
                    <td>{time}</td>
                </tr>"#,
                sev_class = sev_class,
                severity = t.severity,
                threat_type = t.threat_type,
                description = truncate(&t.description, 80),
                ip = ip,
                time = t.timestamp.format("%H:%M:%S"),
            )
        })
        .collect();

    let content = format!(
        r#"
        <div class="cards">
            <div class="card {posture_class}">
                <div class="card-label">Security Posture</div>
                <div class="card-value">{posture}</div>
            </div>
            <div class="card">
                <div class="card-label">Total Threats</div>
                <div class="card-value">{total}</div>
            </div>
            <div class="card">
                <div class="card-label">Blocked IPs</div>
                <div class="card-value">{blocked}</div>
            </div>
            <div class="card">
                <div class="card-label">Scans Run</div>
                <div class="card-value">{scans}</div>
            </div>
        </div>
        <div class="severity-breakdown">
            <h3>Severity Breakdown</h3>
            <div class="severity-bars">
                <div class="sev-row"><span class="sev-label critical">Critical</span><span class="sev-count">{critical}</span></div>
                <div class="sev-row"><span class="sev-label high">High</span><span class="sev-count">{high}</span></div>
                <div class="sev-row"><span class="sev-label medium">Medium</span><span class="sev-count">{medium}</span></div>
                <div class="sev-row"><span class="sev-label low">Low</span><span class="sev-count">{low}</span></div>
                <div class="sev-row"><span class="sev-label info">Info</span><span class="sev-count">{info_count}</span></div>
            </div>
        </div>
        <div class="actions">
            <h3>Quick Actions</h3>
            <button onclick="triggerScan()">Run Scan</button>
            <button onclick="exportReport()">Export Report</button>
        </div>
        <div class="section">
            <h3>Recent Threats</h3>
            <div id="live-threats"></div>
            <table class="threats-table">
                <thead>
                    <tr><th>Severity</th><th>Type</th><th>Description</th><th>Source IP</th><th>Time</th></tr>
                </thead>
                <tbody>{recent_threats}</tbody>
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

    // We don't have access to the token here, use empty string
    // The token will be injected by the route handler
    page_wrapper("Dashboard", &content, "")
}

pub fn render_threats_page(state: &AppState) -> String {
    let rows: String = state
        .threats
        .iter()
        .rev()
        .map(|t| {
            let sev_class = severity_class(t.severity);
            let ip = t.source_ip.map_or("N/A".to_string(), |ip| ip.to_string());
            let responded = if t.auto_responded { "Yes" } else { "No" };
            format!(
                r#"<tr>
                    <td class="{sev_class}">{severity}</td>
                    <td>{threat_type}</td>
                    <td>{description}</td>
                    <td>{ip}</td>
                    <td>{module}</td>
                    <td>{responded}</td>
                    <td>{time}</td>
                    <td>
                        {block_btn}
                    </td>
                </tr>"#,
                sev_class = sev_class,
                severity = t.severity,
                threat_type = t.threat_type,
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

    let content = format!(
        r#"
        <div id="live-threats"></div>
        <table class="threats-table">
            <thead>
                <tr>
                    <th>Severity</th><th>Type</th><th>Description</th>
                    <th>Source IP</th><th>Module</th><th>Responded</th>
                    <th>Time</th><th>Actions</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        "#,
        rows = rows,
    );

    page_wrapper("Threats", &content, "")
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
