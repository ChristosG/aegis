use axum::{
    extract::{Query, State},
    response::{Html, Json},
};

use crate::web::server::AppContext;
use crate::web::templates;

pub async fn logs_page(State(ctx): State<AppContext>) -> Html<String> {
    let content = r#"
        <div class="date-filter">
            <label for="log-from">From:</label>
            <input type="date" id="log-from" />
            <label for="log-to">To:</label>
            <input type="date" id="log-to" />
            <button onclick="loadLogs()">Filter</button>
        </div>
        <div class="search-bar">
            <input type="text" class="search-input" id="log-search" placeholder="Search logs..." oninput="filterLogTable()" />
        </div>
        <table class="threats-table" id="logs-table">
            <thead>
                <tr>
                    <th class="sortable" onclick="sortTable('logs-table',0)">Severity</th>
                    <th class="sortable" onclick="sortTable('logs-table',1)">Type</th>
                    <th class="sortable" onclick="sortTable('logs-table',2)">Description</th>
                    <th class="sortable" onclick="sortTable('logs-table',3)">Source IP</th>
                    <th class="sortable" onclick="sortTable('logs-table',4)">Module</th>
                    <th class="sortable" onclick="sortTable('logs-table',5)">Time</th>
                </tr>
            </thead>
            <tbody id="logs-table-body"></tbody>
        </table>
        <div class="pagination" id="pagination-logs"></div>
        <script>
        var logPage = 0;
        var logPerPage = 50;
        var logTotal = 0;

        function loadLogs(page) {
            if (page !== undefined) logPage = page;
            var url = '/api/logs?token=' + API_TOKEN + '&page=' + logPage + '&per_page=' + logPerPage;
            var from = document.getElementById('log-from').value;
            var to = document.getElementById('log-to').value;
            if (from) url += '&from=' + from;
            if (to) url += '&to=' + to;

            fetch(url)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    logTotal = data.total || 0;
                    var totalPages = Math.ceil(logTotal / logPerPage) || 1;
                    var tbody = document.getElementById('logs-table-body');
                    tbody.textContent = '';

                    (data.threats || []).forEach(function(t) {
                        var sev = (t.severity || '').toLowerCase();
                        var tr = document.createElement('tr');
                        tr.setAttribute('data-severity', sev);

                        var tdSev = document.createElement('td');
                        tdSev.className = 'sev-' + sev;
                        tdSev.textContent = t.severity || '';
                        tr.appendChild(tdSev);

                        var tdType = document.createElement('td');
                        tdType.textContent = formatThreatType(t.threat_type);
                        tr.appendChild(tdType);

                        var tdDesc = document.createElement('td');
                        tdDesc.textContent = truncateStr(t.description || '', 80);
                        tr.appendChild(tdDesc);

                        var tdIp = document.createElement('td');
                        tdIp.textContent = t.source_ip || 'N/A';
                        tr.appendChild(tdIp);

                        var tdMod = document.createElement('td');
                        tdMod.textContent = t.source_module || '';
                        tr.appendChild(tdMod);

                        var tdTime = document.createElement('td');
                        tdTime.textContent = formatTimeFull(t.timestamp);
                        tr.appendChild(tdTime);

                        tbody.appendChild(tr);
                    });

                    renderLogPagination(totalPages);
                })
                .catch(function() {});
        }

        function renderLogPagination(totalPages) {
            var container = document.getElementById('pagination-logs');
            container.textContent = '';
            if (totalPages <= 1) return;

            var prevBtn = document.createElement('button');
            prevBtn.textContent = 'Prev';
            prevBtn.disabled = logPage === 0;
            prevBtn.onclick = function() { loadLogs(logPage - 1); };
            container.appendChild(prevBtn);

            var info = document.createElement('span');
            info.textContent = 'Page ' + (logPage + 1) + ' of ' + totalPages + ' (' + logTotal + ' total)';
            container.appendChild(info);

            var nextBtn = document.createElement('button');
            nextBtn.textContent = 'Next';
            nextBtn.disabled = logPage >= totalPages - 1;
            nextBtn.onclick = function() { loadLogs(logPage + 1); };
            container.appendChild(nextBtn);
        }

        function filterLogTable() {
            var search = document.getElementById('log-search').value.toLowerCase();
            var rows = document.querySelectorAll('#logs-table-body tr');
            rows.forEach(function(row) {
                var text = row.textContent.toLowerCase();
                row.style.display = text.indexOf(search) >= 0 ? '' : 'none';
            });
        }

        loadLogs(0);
        </script>
    "#;

    let token = if ctx.auth_required {
        &ctx.api_token
    } else {
        ""
    };
    Html(templates::render_logs_page(content, token))
}

#[derive(serde::Deserialize)]
pub struct LogsParams {
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default = "default_per_page")]
    pub per_page: Option<usize>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

fn default_per_page() -> Option<usize> {
    Some(50)
}

pub async fn api_logs(
    State(ctx): State<AppContext>,
    Query(params): Query<LogsParams>,
) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let page = params.page.unwrap_or(0);
    let per_page = params.per_page.unwrap_or(50).min(200);

    let mut threats: Vec<_> = state.threats.iter().rev().collect();

    // Date filtering
    if let Some(from_str) = &params.from {
        if let Ok(from_date) = chrono::NaiveDate::parse_from_str(from_str, "%Y-%m-%d") {
            let from_dt = from_date.and_hms_opt(0, 0, 0).unwrap().and_utc();
            threats.retain(|t| t.timestamp >= from_dt);
        }
    }
    if let Some(to_str) = &params.to {
        if let Ok(to_date) = chrono::NaiveDate::parse_from_str(to_str, "%Y-%m-%d") {
            let to_dt = to_date.and_hms_opt(23, 59, 59).unwrap().and_utc();
            threats.retain(|t| t.timestamp <= to_dt);
        }
    }

    let total = threats.len();
    let start = page * per_page;
    let page_threats: Vec<_> = threats.into_iter().skip(start).take(per_page).collect();

    Json(serde_json::json!({
        "total": total,
        "page": page,
        "per_page": per_page,
        "threats": page_threats,
    }))
}
