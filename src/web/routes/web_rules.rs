//! /web-rules — per-endpoint DDoS threshold management.
//!
//! Lets operators add/remove `[[web.endpoint_thresholds]]` rules at runtime
//! via the WebUI. Writes are persisted to the on-disk config via toml_edit
//! (preserving comments) and mirrored into the live AppState. Live-counting
//! changes still require a restart — the page surfaces this.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path as FsPath;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, Json},
};
use serde::Deserialize;

use crate::config::schema::EndpointThreshold;
use crate::web::server::AppContext;
use crate::web::templates;

// ─── HTML page ────────────────────────────────────────────────────────────

pub async fn web_rules_page(State(ctx): State<AppContext>) -> Html<String> {
    let content = r##"
        <div class="web-rules-intro">
            <p class="muted" style="margin-bottom:12px">
                Per-endpoint DDoS thresholds override the global <code>ddos_threshold</code>
                and <code>ddos_high_traffic_threshold</code> for specific paths. When a request
                matches a rule, it's counted only against that rule's limit — not the global one.
                When multiple rules could match, the <b>longest path wins</b>; on equal length,
                <b>exact beats prefix</b>.
            </p>
        </div>

        <div class="web-rules-tester">
            <h3>Path tester</h3>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                <input id="wr-test-input" type="text" placeholder="/api/positions/integrity"
                       style="flex:1;min-width:280px;padding:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px"/>
                <button onclick="webRulesTestPath()">Test</button>
            </div>
            <div id="wr-test-result" style="margin-top:8px;font-family:monospace;font-size:13px"></div>
        </div>

        <div class="web-rules-add" style="margin-top:24px">
            <h3>Add a rule</h3>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                <input id="wr-new-path" type="text" placeholder="/api/login"
                       style="flex:2;min-width:200px;padding:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px"/>
                <input id="wr-new-threshold" type="number" min="1" placeholder="500 req/min"
                       style="flex:1;min-width:120px;padding:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px"/>
                <select id="wr-new-matchtype"
                        style="padding:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px">
                    <option value="prefix">prefix</option>
                    <option value="exact">exact</option>
                </select>
                <button onclick="webRulesAdd()">Add Rule</button>
            </div>
            <div id="wr-add-result" style="margin-top:8px;font-size:13px"></div>
        </div>

        <div class="web-rules-suggest" style="margin-top:24px">
            <h3>Suggest from access.log</h3>
            <p class="muted" style="font-size:13px;margin-bottom:8px">
                Scans the most recent nginx access log entries and lists the top per-(IP, path)
                request counts that exceeded the current global threshold but came from a small
                number of IPs — likely legitimate polling clients that need a rule.
            </p>
            <button onclick="webRulesSuggest()">Scan & suggest</button>
            <div id="wr-suggest-result" style="margin-top:12px"></div>
        </div>

        <div style="margin-top:24px">
            <h3>Current rules</h3>
            <div id="wr-table">Loading...</div>
            <p class="muted" style="margin-top:12px;font-size:12px">
                Changes are saved to <code>aegis.toml</code> immediately, but Aegis must be
                restarted to pick up new rules. Use <a href="/config?token=" id="wr-config-link">Config → Restart</a>.
            </p>
        </div>
    "##;

    let token = if ctx.auth_required {
        &ctx.api_token
    } else {
        ""
    };
    Html(templates::render_web_rules_page(content, token))
}

// ─── API: list ─────────────────────────────────────────────────────────────

pub async fn api_web_rules_list(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let rules: Vec<serde_json::Value> = state
        .config
        .web
        .endpoint_thresholds
        .iter()
        .enumerate()
        .map(|(i, r)| {
            serde_json::json!({
                "index": i,
                "path": r.path,
                "threshold": r.threshold,
                "match_type": r.match_type,
            })
        })
        .collect();
    Json(serde_json::json!({
        "rules": rules,
        "ddos_threshold": state.config.web.ddos_threshold,
        "ddos_high_traffic_threshold": state.config.web.ddos_high_traffic_threshold,
    }))
}

// ─── API: add ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddRuleRequest {
    pub path: String,
    pub threshold: u32,
    pub match_type: String,
}

pub async fn api_web_rules_add(
    State(ctx): State<AppContext>,
    Json(req): Json<AddRuleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate inputs (same rules as config validator).
    let path = req.path.trim().to_string();
    if path.is_empty() || !path.starts_with('/') {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "path must be non-empty and start with /",
        })));
    }
    if req.threshold == 0 {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "threshold must be > 0",
        })));
    }
    if req.match_type != "exact" && req.match_type != "prefix" {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "match_type must be \"exact\" or \"prefix\"",
        })));
    }

    // Duplicate check (same path + match_type).
    {
        let state = ctx.state.read().await;
        if state
            .config
            .web
            .endpoint_thresholds
            .iter()
            .any(|r| r.path == path && r.match_type == req.match_type)
        {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("rule for {} ({}) already exists", path, req.match_type),
            })));
        }
    }

    // Persist.
    if let Err(e) = persist_endpoint_threshold_add(&path, req.threshold, &req.match_type) {
        tracing::error!(error = %e, "Failed to persist endpoint threshold");
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to update config file: {}", e),
        })));
    }

    // Mirror in runtime state (won't take effect until restart for actual counting,
    // but the list endpoint should reflect the new entry immediately).
    {
        let mut state = ctx.state.write().await;
        state
            .config
            .web
            .endpoint_thresholds
            .push(EndpointThreshold {
                path: path.clone(),
                threshold: req.threshold,
                match_type: req.match_type.clone(),
            });
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "added": { "path": path, "threshold": req.threshold, "match_type": req.match_type },
        "requires_restart": true,
    })))
}

// ─── API: delete ───────────────────────────────────────────────────────────

pub async fn api_web_rules_delete(
    Path(idx): Path<usize>,
    State(ctx): State<AppContext>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let removed = {
        let state = ctx.state.read().await;
        state.config.web.endpoint_thresholds.get(idx).cloned()
    };
    let removed = match removed {
        Some(r) => r,
        None => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("no rule at index {}", idx),
            })));
        }
    };

    if let Err(e) = persist_endpoint_threshold_remove(&removed.path, &removed.match_type) {
        tracing::error!(error = %e, "Failed to persist endpoint threshold removal");
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to update config file: {}", e),
        })));
    }

    {
        let mut state = ctx.state.write().await;
        // Re-find by (path, match_type) to be safe against concurrent mutations.
        state
            .config
            .web
            .endpoint_thresholds
            .retain(|r| !(r.path == removed.path && r.match_type == removed.match_type));
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "removed": { "path": removed.path, "match_type": removed.match_type },
        "requires_restart": true,
    })))
}

// ─── API: test which rule matches a given path ────────────────────────────

#[derive(Deserialize)]
pub struct TestPathQuery {
    pub path: String,
}

pub async fn api_web_rules_test(
    State(ctx): State<AppContext>,
    Query(q): Query<TestPathQuery>,
) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let rules = &state.config.web.endpoint_thresholds;
    let matched = crate::modules::web::pick_endpoint_rule(&q.path, rules);
    match matched {
        Some(idx) => {
            let r = &rules[idx];
            Json(serde_json::json!({
                "matched": true,
                "rule": {
                    "index": idx,
                    "path": r.path,
                    "threshold": r.threshold,
                    "match_type": r.match_type,
                },
                "effective_threshold": r.threshold,
            }))
        }
        None => Json(serde_json::json!({
            "matched": false,
            "effective_threshold": state.config.web.ddos_threshold,
            "fallback": "global ddos_threshold",
        })),
    }
}

// ─── API: suggest rules by scanning access.log ────────────────────────────

pub async fn api_web_rules_suggest(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let log_paths = ctx.config.web.access_log_paths.clone();
    let global_threshold = ctx.config.web.ddos_threshold as u64;
    let existing: Vec<(String, String)> = ctx
        .config
        .web
        .endpoint_thresholds
        .iter()
        .map(|r| (r.path.clone(), r.match_type.clone()))
        .collect();

    // Aggregate (ip, path) counts from the last N lines.
    // We use a simple last-N-line tail rather than full file scan.
    const TAIL_LINES: usize = 20_000;
    let mut counts: HashMap<(String, String), u64> = HashMap::new();
    let access_re =
        regex::Regex::new(r#"^(\S+) \S+ \S+ \[[^\]]+\] "([^"]*)" \d{3} \d+ "[^"]*" "[^"]*""#)
            .expect("access_re");

    for log_path in &log_paths {
        if !FsPath::new(log_path).exists() {
            continue;
        }
        if let Ok(file) = std::fs::File::open(log_path) {
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
            let start = lines.len().saturating_sub(TAIL_LINES);
            for line in &lines[start..] {
                let caps = match access_re.captures(line) {
                    Some(c) => c,
                    None => continue,
                };
                let ip = caps[1].to_string();
                let request = &caps[2];
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .split('?')
                    .next()
                    .unwrap_or("");
                if path.is_empty() {
                    continue;
                }
                // Skip obvious static assets — they're already excluded by aegis.
                if path.starts_with("/_next/static/")
                    || path.starts_with("/static/")
                    || path.starts_with("/assets/")
                {
                    continue;
                }
                *counts.entry((ip, path.to_string())).or_insert(0) += 1;
            }
        }
    }

    // Group by path: which paths have a high per-IP count AND a small number of IPs?
    let mut per_path: HashMap<String, (u64, u64)> = HashMap::new(); // (max_per_ip, unique_ips)
    let mut per_path_ips: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for ((ip, path), c) in &counts {
        let entry = per_path.entry(path.clone()).or_insert((0, 0));
        if *c > entry.0 {
            entry.0 = *c;
        }
        per_path_ips
            .entry(path.clone())
            .or_default()
            .insert(ip.clone());
    }
    for (path, ips) in &per_path_ips {
        if let Some(e) = per_path.get_mut(path) {
            e.1 = ips.len() as u64;
        }
    }

    // Filter: max-per-ip exceeded threshold AND fewer than 5 unique IPs hit that path.
    // (Lots of IPs hitting a high-volume path = real DDoS; few IPs = legitimate clients.)
    let mut suggestions: Vec<serde_json::Value> = per_path
        .iter()
        .filter(|(path, (max_per_ip, unique_ips))| {
            *max_per_ip > global_threshold
                && *unique_ips < 5
                && !existing
                    .iter()
                    .any(|(ep, _)| path.as_str() == ep.as_str() || path.starts_with(ep.as_str()))
        })
        .map(|(path, (max_per_ip, unique_ips))| {
            // Recommend ~2x the observed max as a comfortable ceiling.
            let recommended = ((*max_per_ip * 2).max(global_threshold * 2) as u32).max(50);
            serde_json::json!({
                "path": path,
                "max_requests_per_ip": max_per_ip,
                "unique_ips": unique_ips,
                "recommended_threshold": recommended,
                "recommended_match_type": "exact",
            })
        })
        .collect();
    suggestions.sort_by(|a, b| {
        b["max_requests_per_ip"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["max_requests_per_ip"].as_u64().unwrap_or(0))
    });
    suggestions.truncate(20);

    Json(serde_json::json!({
        "status": "ok",
        "lines_analyzed": TAIL_LINES,
        "suggestions": suggestions,
    }))
}

// ─── TOML persistence ─────────────────────────────────────────────────────

fn persist_endpoint_threshold_add(
    path: &str,
    threshold: u32,
    match_type: &str,
) -> anyhow::Result<()> {
    let config_path = crate::config::defaults::find_system_config_path()
        .ok_or_else(|| anyhow::anyhow!("No config file found"))?;
    let content = std::fs::read_to_string(&config_path)?;
    let mut doc = content.parse::<toml_edit::DocumentMut>()?;

    if !doc.contains_key("web") {
        doc["web"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    let web = doc["web"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("[web] is not a table"))?;

    // Build the array-of-tables entry if missing.
    if !web.contains_key("endpoint_thresholds") {
        web["endpoint_thresholds"] =
            toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }

    let arr = web["endpoint_thresholds"]
        .as_array_of_tables_mut()
        .ok_or_else(|| anyhow::anyhow!("endpoint_thresholds is not an array of tables"))?;

    // Duplicate check (path + match_type).
    for t in arr.iter() {
        if t.get("path").and_then(|v| v.as_str()) == Some(path)
            && t.get("match_type").and_then(|v| v.as_str()) == Some(match_type)
        {
            return Ok(()); // already there
        }
    }

    let mut tbl = toml_edit::Table::new();
    tbl["path"] = toml_edit::value(path);
    tbl["threshold"] = toml_edit::value(threshold as i64);
    tbl["match_type"] = toml_edit::value(match_type);
    arr.push(tbl);

    std::fs::write(&config_path, doc.to_string())?;
    Ok(())
}

fn persist_endpoint_threshold_remove(path: &str, match_type: &str) -> anyhow::Result<()> {
    let config_path = crate::config::defaults::find_system_config_path()
        .ok_or_else(|| anyhow::anyhow!("No config file found"))?;
    let content = std::fs::read_to_string(&config_path)?;
    let mut doc = content.parse::<toml_edit::DocumentMut>()?;

    if let Some(web) = doc.get_mut("web").and_then(|w| w.as_table_mut()) {
        if let Some(arr) = web
            .get_mut("endpoint_thresholds")
            .and_then(|w| w.as_array_of_tables_mut())
        {
            arr.retain(|t| {
                !(t.get("path").and_then(|v| v.as_str()) == Some(path)
                    && t.get("match_type").and_then(|v| v.as_str()) == Some(match_type))
            });
        }
    }

    std::fs::write(&config_path, doc.to_string())?;
    Ok(())
}
