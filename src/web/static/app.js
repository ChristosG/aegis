// === Modal System ===
function showModal(title, bodyHtml, footerHtml) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = bodyHtml;
    document.getElementById('modal-footer').innerHTML = footerHtml || '';
    document.getElementById('modal-overlay').style.display = 'flex';
}

function hideModal() {
    document.getElementById('modal-overlay').style.display = 'none';
}

function closeModal(e) {
    if (e.target === document.getElementById('modal-overlay')) hideModal();
}

function showConfirm(title, message, onConfirm) {
    showModal(title, '<p id="modal-confirm-msg"></p>',
        '<button class="btn-modal-cancel" onclick="hideModal()">Cancel</button>' +
        '<button class="btn-modal-confirm" id="modal-confirm-btn">Confirm</button>'
    );
    document.getElementById('modal-confirm-msg').textContent = message;
    document.getElementById('modal-confirm-btn').onclick = function() {
        hideModal();
        onConfirm();
    };
}

function showResult(title, message, isError) {
    var cls = isError ? 'modal-error' : 'modal-success';
    showModal(title, '<p class="' + cls + '" id="modal-result-msg"></p>',
        '<button class="btn-modal-cancel" onclick="hideModal()">Close</button>'
    );
    document.getElementById('modal-result-msg').textContent = message;
}

// === Keyboard: Escape closes modal ===
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        hideModal();
        // Also close sidebar on mobile
        var sidebar = document.getElementById('sidebar');
        if (sidebar) sidebar.classList.remove('open');
        var overlay = document.getElementById('sidebar-overlay');
        if (overlay) overlay.classList.remove('open');
    }
});

// === Mobile Sidebar Toggle ===
function toggleSidebar() {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    if (sidebar) sidebar.classList.toggle('open');
    if (overlay) overlay.classList.toggle('open');
}

// === Tooltip System (JS-managed, viewport-aware) ===
(function() {
    var popup = document.getElementById('tooltip-popup');
    if (!popup) return;

    document.addEventListener('mouseenter', function(e) {
        var el = e.target.closest('.has-tooltip');
        if (!el) return;
        var text = el.getAttribute('data-tooltip');
        if (!text) return;
        popup.textContent = text;
        popup.style.display = 'block';
        positionTooltip(el, popup);
    }, true);

    document.addEventListener('mouseleave', function(e) {
        var el = e.target.closest('.has-tooltip');
        if (!el) return;
        popup.style.display = 'none';
    }, true);

    function positionTooltip(el, popup) {
        var rect = el.getBoundingClientRect();
        var popH = popup.offsetHeight;
        var popW = popup.offsetWidth;
        var top = rect.bottom + 4;
        var left = rect.left;

        // Flip above if near bottom
        if (top + popH > window.innerHeight - 8) {
            top = rect.top - popH - 4;
        }
        // Align right if near right edge
        if (left + popW > window.innerWidth - 8) {
            left = window.innerWidth - popW - 8;
        }
        if (left < 4) left = 4;

        popup.style.top = top + 'px';
        popup.style.left = left + 'px';
    }
})();

// === Threat Type Explanations ===
var THREAT_EXPLANATIONS = {
    'syn_flood': 'High volume of half-open TCP connections (SYN without ACK). Indicates a SYN flood denial-of-service attack targeting your server.',
    'port_scan': 'A single IP is probing multiple ports on your server, typically to discover running services before an attack.',
    'suspicious_connection': 'An outbound connection to an unusual or unexpected destination that doesn\'t match normal traffic patterns.',
    'c2_beacon': 'Regular, periodic outbound connections to the same host — a pattern used by malware to check in with a command-and-control server.',
    'crypto_miner': 'A process is using excessive CPU in a pattern consistent with cryptocurrency mining software.',
    'reverse_shell': 'A process has redirected its stdin/stdout to a network socket — classic indicator of a reverse shell backdoor.',
    'suspicious_binary': 'An executable is running from a temporary or world-writable directory (/tmp, /dev/shm) where binaries shouldn\'t normally run.',
    'brute_force': 'Multiple failed login attempts from the same IP in a short window, indicating a password-guessing attack.',
    'root_login': 'A successful login to the root account was detected. This may be expected or may indicate compromise.',
    'login_anomaly': 'A login event that doesn\'t match established patterns — unusual user, unexpected authentication method, or first-time access.',
    'file_modified': 'A monitored system file was changed. Could be a legitimate update or unauthorized tampering.',
    'file_added': 'A new file appeared in a monitored directory. Check if it\'s from a legitimate package update.',
    'file_deleted': 'A monitored system file was removed. Could indicate tampering or cleanup by an attacker.',
    'scanner_probe': 'HTTP requests matching known vulnerability scanner signatures (nikto, sqlmap, nuclei, etc.).',
    'web_ddos': 'An IP is sending an abnormally high rate of HTTP requests, potentially a DDoS or aggressive scraping attack.',
    'sql_injection': 'An HTTP request contains SQL injection patterns (UNION SELECT, OR 1=1, etc.) attempting to exploit database queries.',
    'path_traversal': 'An HTTP request contains directory traversal sequences (../) attempting to access files outside the web root.',
    'threat_intel_match': 'An IP connected to your server that appears on one or more threat intelligence blacklists.',
    'tor_exit': 'Traffic from a known Tor exit node. Not necessarily malicious, but often used to anonymize attacks.',
    'unusual_login_time': 'A user logged in outside the configured normal hours. May indicate a compromised account being used by an attacker in a different timezone.',
    'cron_modified': 'A cron job file was changed. Attackers commonly install cron persistence to survive reboots.',
    'sudoers_modified': 'The sudoers configuration was altered. Could indicate privilege escalation setup by an attacker.',
    'new_user_created': 'A new user account was created on the system. Verify this was intentional.',
    'honeypot_connection': 'An IP connected to a honeypot port — a decoy service with no legitimate use. This is almost certainly malicious probing.',
    'connection_rate_exceeded': 'An IP exceeded the configured connection rate limit. May indicate scanning, brute-force, or DDoS activity.',
    'cert_expiring_soon': 'A monitored TLS certificate is approaching its expiry date and needs renewal.',
    'kernel_module_loaded': 'A kernel module was loaded. Rootkits often use kernel modules to hide their presence.',
    'new_outbound_destination': 'A process on this machine connected to an IP/port it hasn\'t contacted before. Check the process name in the details — common programs like browsers or package managers are usually harmless. Unknown processes reaching out could indicate malware.'
};

// === Sort & Filter State ===
var sortState = {};
var currentFilter = null;
var searchText = '';
var fileIntegrityHidden = true;
var currentPage = {};
var ROWS_PER_PAGE = 50;

var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function sortTable(tableId, colIndex) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;

    var state = sortState[tableId] || {};
    if (state.col === colIndex) {
        state.dir = state.dir === 'asc' ? 'desc' : 'asc';
    } else {
        state.col = colIndex;
        state.dir = 'asc';
    }
    sortState[tableId] = state;

    var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    var isSeverityCol = colIndex === 0;

    rows.sort(function(a, b) {
        var aText = (a.cells[colIndex] && a.cells[colIndex].textContent.trim().toLowerCase()) || '';
        var bText = (b.cells[colIndex] && b.cells[colIndex].textContent.trim().toLowerCase()) || '';

        var cmp;
        if (isSeverityCol) {
            cmp = (SEV_RANK[aText] || 0) - (SEV_RANK[bText] || 0);
        } else {
            cmp = aText.localeCompare(bText);
        }
        return state.dir === 'asc' ? cmp : -cmp;
    });

    rows.forEach(function(row) { tbody.appendChild(row); });
    updateSortArrows(tableId);
    applyFilter();
}

function updateSortArrows(tableId) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var ths = table.querySelectorAll('thead th');
    ths.forEach(function(th) {
        var arrow = th.querySelector('.sort-arrow');
        if (arrow) arrow.remove();
    });

    var state = sortState[tableId];
    if (!state || state.col === undefined) return;
    var th = ths[state.col];
    if (!th) return;
    var span = document.createElement('span');
    span.className = 'sort-arrow';
    span.textContent = state.dir === 'asc' ? ' \u25B2' : ' \u25BC';
    th.appendChild(span);
}

// === Search ===
function onSearchInput() {
    var input = document.getElementById('search-input');
    searchText = input ? input.value.toLowerCase() : '';
    resetPagination();
    applyFilter();
}

// === Severity Filtering ===
function filterBySeverity(severity) {
    if (currentFilter === severity) {
        clearFilter();
        return;
    }
    currentFilter = severity;
    resetPagination();
    applyFilter();
    updateFilterBar();
    updateFilterButtons();
}

function clearFilter() {
    currentFilter = null;
    resetPagination();
    applyFilter();
    updateFilterBar();
    updateFilterButtons();
}

function applyFilter() {
    var tbodies = document.querySelectorAll('#recent-threats-body, #threats-table-body');
    tbodies.forEach(function(tbody) {
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        var visibleRows = [];

        rows.forEach(function(row) {
            var sevMatch = !currentFilter || row.getAttribute('data-severity') === currentFilter;
            var threatType = row.getAttribute('data-threat-type') || '';
            var fiMatch = !fileIntegrityHidden || !threatType.startsWith('file_');

            // Search filter: check cell text + tooltip
            var searchMatch = true;
            if (searchText) {
                var rowText = '';
                for (var i = 0; i < row.cells.length; i++) {
                    rowText += row.cells[i].textContent + ' ';
                    var tooltip = row.cells[i].getAttribute('data-tooltip');
                    if (tooltip) rowText += tooltip + ' ';
                }
                searchMatch = rowText.toLowerCase().indexOf(searchText) >= 0;
            }

            if (sevMatch && fiMatch && searchMatch) {
                visibleRows.push(row);
            } else {
                row.style.display = 'none';
            }
        });

        // Apply pagination to visible rows
        var tableId = tbody.closest('table') ? tbody.closest('table').id : '';
        var paginationId = '';
        if (tableId === 'dashboard-threats-table') paginationId = 'pagination-dashboard';
        else if (tableId === 'threats-page-table') paginationId = 'pagination-threats';

        if (paginationId) {
            var page = currentPage[paginationId] || 0;
            var totalPages = Math.ceil(visibleRows.length / ROWS_PER_PAGE) || 1;
            if (page >= totalPages) page = totalPages - 1;
            currentPage[paginationId] = page;

            var start = page * ROWS_PER_PAGE;
            var end = start + ROWS_PER_PAGE;

            visibleRows.forEach(function(row, i) {
                row.style.display = (i >= start && i < end) ? '' : 'none';
            });

            renderPagination(paginationId, page, totalPages, visibleRows.length);
        } else {
            visibleRows.forEach(function(row) { row.style.display = ''; });
        }
    });
}

// === Pagination ===
function resetPagination() {
    currentPage = {};
}

function renderPagination(containerId, page, totalPages, totalItems) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.textContent = '';

    if (totalPages <= 1) return;

    var prevBtn = document.createElement('button');
    prevBtn.textContent = 'Prev';
    prevBtn.disabled = page === 0;
    prevBtn.onclick = function() {
        currentPage[containerId] = Math.max(0, page - 1);
        applyFilter();
    };
    container.appendChild(prevBtn);

    var info = document.createElement('span');
    info.textContent = 'Page ' + (page + 1) + ' of ' + totalPages + ' (' + totalItems + ' items)';
    container.appendChild(info);

    var nextBtn = document.createElement('button');
    nextBtn.textContent = 'Next';
    nextBtn.disabled = page >= totalPages - 1;
    nextBtn.onclick = function() {
        currentPage[containerId] = Math.min(totalPages - 1, page + 1);
        applyFilter();
    };
    container.appendChild(nextBtn);
}

function toggleFileIntegrity() {
    fileIntegrityHidden = !fileIntegrityHidden;
    var btns = document.querySelectorAll('.btn-toggle');
    btns.forEach(function(btn) {
        if (fileIntegrityHidden) {
            btn.classList.add('active');
            btn.textContent = 'Show File Integrity';
        } else {
            btn.classList.remove('active');
            btn.textContent = 'Hide File Integrity';
        }
    });
    resetPagination();
    applyFilter();
}

function updateFilterBar() {
    var bars = document.querySelectorAll('#filter-bar');
    bars.forEach(function(bar) {
        if (currentFilter) {
            bar.style.display = 'flex';
            var label = currentFilter.charAt(0).toUpperCase() + currentFilter.slice(1);
            bar.textContent = '';
            var span = document.createElement('span');
            span.textContent = 'Showing:';
            bar.appendChild(span);
            var tag = document.createElement('span');
            tag.className = 'filter-tag';
            tag.textContent = label + ' ';
            var closeBtn = document.createElement('button');
            closeBtn.className = 'filter-clear';
            closeBtn.textContent = '\u00D7';
            closeBtn.onclick = clearFilter;
            tag.appendChild(closeBtn);
            bar.appendChild(tag);
        } else {
            bar.style.display = 'none';
            bar.textContent = '';
        }
    });
}

function updateFilterButtons() {
    var btns = document.querySelectorAll('.sev-filter-btn');
    btns.forEach(function(btn) {
        if (currentFilter && btn.getAttribute('data-filter-sev') === currentFilter) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
}

// === WebSocket for live threat updates ===
(function() {
    var liveCont = document.getElementById('live-threats');
    if (!liveCont) return;

    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var ws = new WebSocket(proto + '//' + location.host + '/ws/threats?token=' + API_TOKEN);

    ws.onmessage = function(e) {
        try {
            var t = JSON.parse(e.data);
            var div = document.createElement('div');
            div.className = 'live-event';
            div.textContent = '[' + t.severity + '] ' + t.threat_type + ' - ' + t.description;
            liveCont.prepend(div);
            while (liveCont.children.length > 20) {
                liveCont.removeChild(liveCont.lastChild);
            }
            var sevEl = document.querySelector('[data-sev="' + t.severity + '"]');
            if (sevEl) {
                sevEl.textContent = parseInt(sevEl.textContent) + 1;
            }
            var totalEl = document.querySelector('[data-stat="total-threats"]');
            if (totalEl) {
                totalEl.textContent = parseInt(totalEl.textContent) + 1;
            }
        } catch(err) {}
    };

    ws.onclose = function() {
        var div = document.createElement('div');
        div.className = 'live-event';
        div.textContent = 'WebSocket disconnected. Refresh to reconnect.';
        liveCont.prepend(div);
    };
})();

// === Auto-refresh every 15s ===
(function() {
    var hasDashboard = !!document.querySelector('[data-stat="total-threats"]');
    var hasThreatsPage = !!document.getElementById('threats-table-body');
    var hasFirewallPage = !!document.getElementById('blocks-table-body');

    if (hasDashboard || hasThreatsPage) applyFilter();

    if (!hasDashboard && !hasThreatsPage && !hasFirewallPage) return;

    setInterval(function() {
        if (hasDashboard) refreshStats();
        if (hasDashboard || hasThreatsPage) refreshThreatTable();
        if (hasFirewallPage) refreshFirewallTables();
    }, 15000);
})();

// === Threat Detail Modal ===
document.addEventListener('click', function(e) {
    var row = e.target.closest('tr.clickable-row');
    if (!row) return;
    if (e.target.closest('button')) return;

    var jsonStr = row.getAttribute('data-threat-json');
    if (!jsonStr) return;

    try {
        var t = JSON.parse(jsonStr);
        showThreatDetail(t);
    } catch(err) {}
});

function showThreatDetail(t) {
    var body = document.createElement('div');

    // Detail grid
    var grid = document.createElement('div');
    grid.className = 'detail-grid';
    var fields = [
        ['ID', t.id || ''],
        ['Type', formatThreatType(t.threat_type)],
        ['Severity', t.severity || ''],
        ['Module', t.source_module || ''],
        ['Source IP', t.source_ip || 'N/A'],
        ['Target', t.target || 'N/A'],
        ['Time', formatTimeFull(t.timestamp)],
        ['Responded', t.auto_responded ? 'Yes' : 'No']
    ];
    fields.forEach(function(f) {
        var label = document.createElement('span');
        label.className = 'detail-label';
        label.textContent = f[0];
        grid.appendChild(label);
        var value = document.createElement('span');
        value.className = 'detail-value';
        if (f[0] === 'Severity') value.className += ' sev-' + (t.severity || '').toLowerCase();
        value.textContent = f[1];
        grid.appendChild(value);
    });
    body.appendChild(grid);

    // Description
    var descSection = document.createElement('div');
    descSection.className = 'detail-section';
    var descH4 = document.createElement('h4');
    descH4.textContent = 'Description';
    descSection.appendChild(descH4);
    var descP = document.createElement('p');
    descP.textContent = t.description || '';
    descSection.appendChild(descP);
    body.appendChild(descSection);

    // Details key-value
    if (t.details && Object.keys(t.details).length > 0) {
        var detailSection = document.createElement('div');
        detailSection.className = 'detail-section';
        var detailH4 = document.createElement('h4');
        detailH4.textContent = 'Details';
        detailSection.appendChild(detailH4);
        var detailGrid = document.createElement('div');
        detailGrid.className = 'detail-grid';
        for (var key in t.details) {
            var dk = document.createElement('span');
            dk.className = 'detail-label';
            dk.textContent = key;
            detailGrid.appendChild(dk);
            var dv = document.createElement('span');
            dv.className = 'detail-value';
            dv.textContent = t.details[key];
            detailGrid.appendChild(dv);
        }
        detailSection.appendChild(detailGrid);
        body.appendChild(detailSection);
    }

    // Set modal content using DOM
    document.getElementById('modal-title').textContent = 'Threat Details';
    var modalBody = document.getElementById('modal-body');
    modalBody.textContent = '';
    modalBody.appendChild(body);

    // Footer
    var footer = document.getElementById('modal-footer');
    footer.textContent = '';
    if (t.source_ip) {
        var blockBtn = document.createElement('button');
        blockBtn.className = 'btn-modal-confirm';
        blockBtn.textContent = 'Block IP';
        var ipStr = t.source_ip;
        blockBtn.onclick = function() { hideModal(); blockIp(ipStr); };
        footer.appendChild(blockBtn);
    }
    var copyBtn = document.createElement('button');
    copyBtn.className = 'btn-modal-cancel';
    copyBtn.textContent = 'Copy Details';
    copyBtn.onclick = function() { copyThreatDetails(); };
    footer.appendChild(copyBtn);
    var closeBtn = document.createElement('button');
    closeBtn.className = 'btn-modal-cancel';
    closeBtn.textContent = 'Close';
    closeBtn.onclick = hideModal;
    footer.appendChild(closeBtn);

    document.getElementById('modal-overlay').style.display = 'flex';
    window._currentThreatDetail = t;
}

function copyThreatDetails() {
    if (window._currentThreatDetail) {
        var text = JSON.stringify(window._currentThreatDetail, null, 2);
        navigator.clipboard.writeText(text).then(function() {
            showResult('Copied', 'Threat details copied to clipboard', false);
        }).catch(function() {
            showResult('Copy Failed', 'Could not copy to clipboard', true);
        });
    }
}

// === Table Refresh ===
function refreshThreatTable() {
    fetch('/api/threats?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data.threats) return;

            var dashTbody = document.getElementById('recent-threats-body');
            if (dashTbody) {
                var dashThreats = data.threats.slice(-30).reverse();
                rebuildTbody(dashTbody, dashThreats, buildDashboardRow);
            }

            var fullTbody = document.getElementById('threats-table-body');
            if (fullTbody) {
                rebuildTbody(fullTbody, data.threats.slice().reverse(), buildThreatsPageRow);
            }

            if (dashTbody && sortState['dashboard-threats-table']) {
                var s = sortState['dashboard-threats-table'];
                sortState['dashboard-threats-table'] = { col: s.col, dir: s.dir === 'asc' ? 'desc' : 'asc' };
                sortTable('dashboard-threats-table', s.col);
            }
            if (fullTbody && sortState['threats-page-table']) {
                var s2 = sortState['threats-page-table'];
                sortState['threats-page-table'] = { col: s2.col, dir: s2.dir === 'asc' ? 'desc' : 'asc' };
                sortTable('threats-page-table', s2.col);
            }
            applyFilter();
        })
        .catch(function() {});
}

function rebuildTbody(tbody, threats, rowBuilder) {
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    threats.forEach(function(t) {
        var tr = rowBuilder(t);
        tbody.appendChild(tr);
    });
}

function buildDashboardRow(t) {
    var sev = (t.severity || '').toLowerCase();
    var ip = t.source_ip || 'N/A';
    var desc = t.description || '';
    var ts = formatTime(t.timestamp);

    var tr = document.createElement('tr');
    tr.setAttribute('data-severity', sev);
    tr.setAttribute('data-threat-type', t.threat_type || '');
    tr.setAttribute('data-threat-json', JSON.stringify(t));
    tr.className = 'clickable-row';

    var tdSev = document.createElement('td');
    tdSev.className = 'sev-' + sev;
    tdSev.textContent = t.severity || '';
    tr.appendChild(tdSev);

    var tdType = document.createElement('td');
    tdType.textContent = formatThreatType(t.threat_type);
    var typeExplain = THREAT_EXPLANATIONS[t.threat_type];
    if (typeExplain) {
        tdType.className = 'has-tooltip';
        tdType.setAttribute('data-tooltip', typeExplain);
    }
    tr.appendChild(tdType);

    var tdDesc = document.createElement('td');
    tdDesc.className = 'has-tooltip';
    tdDesc.setAttribute('data-tooltip', desc);
    tdDesc.textContent = truncateStr(desc, 80);
    tr.appendChild(tdDesc);

    var tdIp = document.createElement('td');
    tdIp.textContent = ip;
    tr.appendChild(tdIp);

    var tdTime = document.createElement('td');
    tdTime.textContent = ts;
    tr.appendChild(tdTime);

    return tr;
}

function buildThreatsPageRow(t) {
    var sev = (t.severity || '').toLowerCase();
    var ip = t.source_ip || 'N/A';
    var desc = t.description || '';
    var responded = t.auto_responded ? 'Yes' : 'No';
    var ts = formatTimeFull(t.timestamp);

    var tr = document.createElement('tr');
    tr.setAttribute('data-severity', sev);
    tr.setAttribute('data-threat-type', t.threat_type || '');
    tr.setAttribute('data-threat-json', JSON.stringify(t));
    tr.className = 'clickable-row';

    var tdSev = document.createElement('td');
    tdSev.className = 'sev-' + sev;
    tdSev.textContent = t.severity || '';
    tr.appendChild(tdSev);

    var tdType = document.createElement('td');
    tdType.textContent = formatThreatType(t.threat_type);
    var typeExplain2 = THREAT_EXPLANATIONS[t.threat_type];
    if (typeExplain2) {
        tdType.className = 'has-tooltip';
        tdType.setAttribute('data-tooltip', typeExplain2);
    }
    tr.appendChild(tdType);

    var tdDesc = document.createElement('td');
    tdDesc.className = 'has-tooltip';
    tdDesc.setAttribute('data-tooltip', desc);
    tdDesc.textContent = truncateStr(desc, 60);
    tr.appendChild(tdDesc);

    var tdIp = document.createElement('td');
    tdIp.textContent = ip;
    tr.appendChild(tdIp);

    var tdMod = document.createElement('td');
    tdMod.textContent = t.source_module || '';
    tr.appendChild(tdMod);

    var tdResp = document.createElement('td');
    tdResp.textContent = responded;
    tr.appendChild(tdResp);

    var tdTime = document.createElement('td');
    tdTime.textContent = ts;
    tr.appendChild(tdTime);

    var tdActions = document.createElement('td');
    if (t.source_ip) {
        var btn = document.createElement('button');
        btn.className = 'btn-sm';
        btn.textContent = 'Block';
        btn.onclick = function(e) { e.stopPropagation(); blockIp(ip); };
        tdActions.appendChild(btn);
    }
    tr.appendChild(tdActions);

    return tr;
}

// === Actions ===
function triggerScan() {
    var modules = ['network', 'process', 'file_integrity', 'auth', 'web', 'threat_intel', 'anomaly', 'honeypot'];

    var container = document.createElement('div');
    var p = document.createElement('p');
    p.textContent = 'Select modules to scan:';
    container.appendChild(p);

    var checkboxDiv = document.createElement('div');
    checkboxDiv.style.margin = '12px 0';
    modules.forEach(function(m) {
        var label = document.createElement('label');
        label.style.cssText = 'display:block;padding:4px 0;cursor:pointer;font-size:13px';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'scan-module-cb';
        cb.value = m;
        cb.checked = true;
        cb.style.marginRight = '8px';
        label.appendChild(cb);
        var text = m.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
        label.appendChild(document.createTextNode(text));
        checkboxDiv.appendChild(label);
    });
    container.appendChild(checkboxDiv);

    document.getElementById('modal-title').textContent = 'Run Scan';
    var modalBody = document.getElementById('modal-body');
    modalBody.textContent = '';
    modalBody.appendChild(container);

    var footer = document.getElementById('modal-footer');
    footer.textContent = '';
    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn-modal-cancel';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.onclick = hideModal;
    footer.appendChild(cancelBtn);
    var goBtn = document.createElement('button');
    goBtn.className = 'btn-modal-confirm';
    goBtn.style.background = 'var(--btn-green)';
    goBtn.textContent = 'Scan';
    goBtn.onclick = function() {
        var selected = [];
        document.querySelectorAll('.scan-module-cb:checked').forEach(function(cb) {
            selected.push(cb.value);
        });
        executeScan(selected);
    };
    footer.appendChild(goBtn);

    document.getElementById('modal-overlay').style.display = 'flex';
}

function executeScan(modules) {
    showModal('Running Scan', '<p>Scanning selected modules...</p>', '');
    var opts = { method: 'POST', headers: { 'Content-Type': 'application/json' } };
    if (modules && modules.length > 0) {
        opts.body = JSON.stringify({ modules: modules });
    }
    fetch('/api/scan?token=' + API_TOKEN, opts)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var container = document.createElement('div');
            var p = document.createElement('p');
            p.textContent = 'Scan complete: ' + data.threats_found + ' threat(s) found.';
            container.appendChild(p);

            if (data.threats && data.threats.length > 0) {
                var table = document.createElement('table');
                table.className = 'threats-table';
                table.style.marginTop = '12px';
                table.style.width = '100%';

                var thead = document.createElement('thead');
                var headerRow = document.createElement('tr');
                ['Severity', 'Type', 'Source IP', 'Module', 'Description'].forEach(function(h) {
                    var th = document.createElement('th');
                    th.textContent = h;
                    headerRow.appendChild(th);
                });
                thead.appendChild(headerRow);
                table.appendChild(thead);

                var tbody = document.createElement('tbody');
                data.threats.forEach(function(t) {
                    var tr = document.createElement('tr');
                    var tdSev = document.createElement('td');
                    tdSev.className = 'sev-' + (t.severity || '').toLowerCase();
                    tdSev.textContent = t.severity || '';
                    tr.appendChild(tdSev);

                    var tdType = document.createElement('td');
                    tdType.textContent = formatThreatType(t.threat_type);
                    var scanExplain = THREAT_EXPLANATIONS[t.threat_type];
                    if (scanExplain) {
                        tdType.className = 'has-tooltip';
                        tdType.setAttribute('data-tooltip', scanExplain);
                    }
                    tr.appendChild(tdType);

                    var tdIp = document.createElement('td');
                    tdIp.textContent = t.source_ip || 'N/A';
                    tr.appendChild(tdIp);

                    var tdMod = document.createElement('td');
                    tdMod.textContent = t.source_module || '';
                    tr.appendChild(tdMod);

                    var tdDesc = document.createElement('td');
                    tdDesc.textContent = t.description || '';
                    tr.appendChild(tdDesc);

                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                container.appendChild(table);
            }

            document.getElementById('modal-body').textContent = '';
            document.getElementById('modal-body').appendChild(container);
            document.getElementById('modal-footer').textContent = '';
            var closeBtn = document.createElement('button');
            closeBtn.className = 'btn-modal-cancel';
            closeBtn.textContent = 'Close';
            closeBtn.onclick = hideModal;
            document.getElementById('modal-footer').appendChild(closeBtn);

            refreshStats();
            refreshThreatTable();
        })
        .catch(function(err) {
            showResult('Scan Failed', 'Error: ' + err, true);
        });
}

function triggerAutoRespond() {
    showConfirm('Auto-Respond', 'Run automated response on all unresponded threats?', function() {
        showModal('Auto-Responding', '<p>Processing threats...</p>', '');
        fetch('/api/respond?token=' + API_TOKEN, { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var container = document.createElement('div');
                var p = document.createElement('p');
                p.textContent = 'Responded to ' + data.responded + ' threat(s).';
                container.appendChild(p);

                if (data.results && data.results.length > 0) {
                    var table = document.createElement('table');
                    table.className = 'threats-table';
                    table.style.marginTop = '12px';
                    table.style.width = '100%';

                    var thead = document.createElement('thead');
                    var headerRow = document.createElement('tr');
                    ['Threat', 'Action', 'Result'].forEach(function(h) {
                        var th = document.createElement('th');
                        th.textContent = h;
                        headerRow.appendChild(th);
                    });
                    thead.appendChild(headerRow);
                    table.appendChild(thead);

                    var tbody = document.createElement('tbody');
                    data.results.forEach(function(r) {
                        var result = r.result || r.error || 'unknown';
                        var tr = document.createElement('tr');

                        var tdId = document.createElement('td');
                        tdId.textContent = r.threat_id;
                        tr.appendChild(tdId);

                        var tdAction = document.createElement('td');
                        tdAction.textContent = r.action;
                        tr.appendChild(tdAction);

                        var tdResult = document.createElement('td');
                        if (r.error) tdResult.className = 'modal-error';
                        tdResult.textContent = truncateStr(result, 50);
                        tr.appendChild(tdResult);

                        tbody.appendChild(tr);
                    });
                    table.appendChild(tbody);
                    container.appendChild(table);
                }

                document.getElementById('modal-body').textContent = '';
                document.getElementById('modal-body').appendChild(container);
                document.getElementById('modal-footer').textContent = '';
                var closeBtn = document.createElement('button');
                closeBtn.className = 'btn-modal-cancel';
                closeBtn.textContent = 'Close';
                closeBtn.onclick = hideModal;
                document.getElementById('modal-footer').appendChild(closeBtn);

                refreshStats();
                refreshThreatTable();
            })
            .catch(function(err) {
                showResult('Auto-Respond Failed', 'Error: ' + err, true);
            });
    });
}

function exportReport() {
    window.open('/report.pdf?token=' + API_TOKEN, '_blank');
}

function viewReport() {
    showModal('Loading Report', '<p>Generating report...</p>', '');
    fetch('/api/report?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var text = data.report || JSON.stringify(data, null, 2);
            var pre = document.createElement('pre');
            pre.style.cssText = 'white-space:pre-wrap;font-family:monospace;font-size:12px;line-height:1.5;max-height:60vh;overflow-y:auto';
            pre.textContent = text;

            document.getElementById('modal-title').textContent = 'Security Report';
            var modalBody = document.getElementById('modal-body');
            modalBody.textContent = '';
            modalBody.appendChild(pre);
            var footer = document.getElementById('modal-footer');
            footer.textContent = '';
            var closeBtn = document.createElement('button');
            closeBtn.className = 'btn-modal-cancel';
            closeBtn.textContent = 'Close';
            closeBtn.onclick = hideModal;
            footer.appendChild(closeBtn);
        })
        .catch(function(err) {
            showResult('Report Failed', 'Error: ' + err, true);
        });
}

function blockIp(ip) {
    showConfirm('Block IP', 'Block IP address ' + ip + '?', function() {
        fetch('/api/block?token=' + API_TOKEN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        })
        .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
        .then(function(res) {
            if (res.ok) {
                showResult('IP Blocked', 'Successfully blocked ' + ip, false);
                refreshStats();
            } else {
                showResult('Block Failed', res.data.message || 'Unknown error', true);
            }
        })
        .catch(function(err) {
            showResult('Block Failed', 'Error: ' + err, true);
        });
    });
}

function unblockIp(ip) {
    showConfirm('Unblock IP', 'Unblock IP address ' + ip + '?', function() {
        fetch('/api/unblock?token=' + API_TOKEN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        })
        .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
        .then(function(res) {
            if (res.ok) {
                showResult('IP Unblocked', 'Successfully unblocked ' + ip, false);
                refreshStats();
            } else {
                showResult('Unblock Failed', res.data.message || 'Unknown error', true);
            }
        })
        .catch(function(err) {
            showResult('Unblock Failed', 'Error: ' + err, true);
        });
    });
}

// === Baseline Reset & Create ===
function resetBaseline() {
    showConfirm('Reset Baseline',
        'This will reset the file integrity baseline. All current files will be accepted as normal. Continue?',
        function() {
            showModal('Resetting Baseline', '<p>Deleting baseline and pending changes...</p>', '');
            fetch('/api/baseline/reset?token=' + API_TOKEN, { method: 'POST' })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.status === 'ok' || data.status === 'partial') {
                        showResult('Baseline Reset', data.message, data.status === 'partial');
                    } else {
                        showResult('Reset Failed', data.message || 'Unknown error', true);
                    }
                })
                .catch(function(err) {
                    showResult('Reset Failed', 'Error: ' + err, true);
                });
        }
    );
}

function createBaseline() {
    showConfirm('Create Baseline',
        'This will hash all watched files and create a new baseline. Continue?',
        function() {
            showModal('Creating Baseline', '<p>Hashing files...</p>', '');
            fetch('/api/baseline/create?token=' + API_TOKEN, { method: 'POST' })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.status === 'ok') {
                        showResult('Baseline Created', 'Hashed ' + (data.files_hashed || 0) + ' files', false);
                    } else {
                        showResult('Baseline Failed', data.message || 'Unknown error', true);
                    }
                })
                .catch(function(err) {
                    showResult('Baseline Failed', 'Error: ' + err, true);
                });
        }
    );
}

// === File Integrity Toggle ===
function toggleFI() {
    var statusEl = document.getElementById('fi-status');
    var currentlyEnabled = statusEl && statusEl.textContent === 'Enabled';
    var action = currentlyEnabled ? 'off' : 'on';
    var label = currentlyEnabled ? 'Disable' : 'Enable';

    showConfirm(label + ' File Integrity',
        label + ' file integrity monitoring? A restart of aegis is required for changes to take effect.',
        function() {
            fetch('/api/file-integrity/toggle?action=' + action + '&token=' + API_TOKEN, { method: 'POST' })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.status === 'ok') {
                        showResult('File Integrity ' + (data.fi_enabled ? 'Enabled' : 'Disabled'),
                            data.message, false);
                        if (statusEl) statusEl.textContent = data.fi_enabled ? 'Enabled' : 'Disabled';
                        var btn = document.getElementById('fi-toggle-btn');
                        if (btn) btn.textContent = data.fi_enabled ? 'Disable File Integrity' : 'Enable File Integrity';
                    } else {
                        showResult('Toggle Failed', data.message || 'Unknown error', true);
                    }
                })
                .catch(function(err) {
                    showResult('Toggle Failed', 'Error: ' + err, true);
                });
        }
    );
}

// === Config Validation ===
function validateConfig() {
    showModal('Validating Config', '<p>Checking configuration...</p>', '');
    fetch('/api/check?token=' + API_TOKEN, { method: 'POST' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var container = document.createElement('div');
            var p = document.createElement('p');
            p.className = data.valid ? 'modal-success' : 'modal-error';
            p.textContent = data.valid ? 'Configuration is valid.' : 'Configuration has errors.';
            container.appendChild(p);

            if (data.errors && data.errors.length > 0) {
                var errSection = document.createElement('div');
                errSection.className = 'detail-section';
                var errH4 = document.createElement('h4');
                errH4.textContent = 'Errors';
                errSection.appendChild(errH4);
                var errUl = document.createElement('ul');
                data.errors.forEach(function(e) {
                    var li = document.createElement('li');
                    li.className = 'modal-error';
                    li.textContent = e;
                    errUl.appendChild(li);
                });
                errSection.appendChild(errUl);
                container.appendChild(errSection);
            }
            if (data.warnings && data.warnings.length > 0) {
                var warnSection = document.createElement('div');
                warnSection.className = 'detail-section';
                var warnH4 = document.createElement('h4');
                warnH4.textContent = 'Warnings';
                warnSection.appendChild(warnH4);
                var warnUl = document.createElement('ul');
                data.warnings.forEach(function(w) {
                    var li = document.createElement('li');
                    li.style.color = 'var(--accent-gold)';
                    li.textContent = w;
                    warnUl.appendChild(li);
                });
                warnSection.appendChild(warnUl);
                container.appendChild(warnSection);
            }

            document.getElementById('modal-title').textContent = 'Config Validation';
            var modalBody = document.getElementById('modal-body');
            modalBody.textContent = '';
            modalBody.appendChild(container);
            var footer = document.getElementById('modal-footer');
            footer.textContent = '';
            var closeBtn = document.createElement('button');
            closeBtn.className = 'btn-modal-cancel';
            closeBtn.textContent = 'Close';
            closeBtn.onclick = hideModal;
            footer.appendChild(closeBtn);
        })
        .catch(function(err) {
            showResult('Validation Failed', 'Error: ' + err, true);
        });
}

// === Firewall Page ===
function fwBlockIp() {
    var ip = document.getElementById('block-ip-input').value.trim();
    if (!ip) return;
    var reason = document.getElementById('block-reason-input').value.trim() || undefined;
    var duration = document.getElementById('block-duration-input').value.trim() || undefined;

    var payload = { ip: ip };
    if (reason) payload.reason = reason;
    if (duration) payload.duration = duration;

    fetch('/api/block?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
    .then(function(res) {
        if (res.ok) {
            document.getElementById('block-ip-input').value = '';
            document.getElementById('block-reason-input').value = '';
            document.getElementById('block-duration-input').value = '';
            refreshFirewallTables();
        } else {
            showResult('Block Failed', res.data.message || 'Unknown error', true);
        }
    })
    .catch(function(err) {
        showResult('Block Failed', 'Error: ' + err, true);
    });
}

function fwUnblock(ip) {
    showConfirm('Unblock IP', 'Unblock IP address ' + ip + '?', function() {
        fetch('/api/unblock?token=' + API_TOKEN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        })
        .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
        .then(function(res) {
            if (res.ok) {
                refreshFirewallTables();
            } else {
                showResult('Unblock Failed', res.data.message || 'Unknown error', true);
            }
        })
        .catch(function(err) {
            showResult('Unblock Failed', 'Error: ' + err, true);
        });
    });
}

function fwAddWhitelist() {
    var cidr = document.getElementById('wl-cidr-input').value.trim();
    if (!cidr) return;

    fetch('/api/whitelist?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidr: cidr })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            document.getElementById('wl-cidr-input').value = '';
            refreshFirewallTables();
        } else {
            showResult('Whitelist Failed', data.message || 'Unknown error', true);
        }
    })
    .catch(function(err) {
        showResult('Whitelist Failed', 'Error: ' + err, true);
    });
}

function fwRemoveWhitelist(cidr) {
    showConfirm('Remove from Whitelist', 'Remove ' + cidr + ' from whitelist?', function() {
        fetch('/api/whitelist/' + encodeURIComponent(cidr) + '?token=' + API_TOKEN, {
            method: 'DELETE'
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'ok') {
                refreshFirewallTables();
            } else {
                showResult('Remove Failed', data.message || 'Unknown error', true);
            }
        })
        .catch(function(err) {
            showResult('Remove Failed', 'Error: ' + err, true);
        });
    });
}

function refreshFirewallTables() {
    fetch('/api/blocks?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var tbody = document.getElementById('blocks-table-body');
            if (!tbody || !data.blocked_ips) return;
            while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

            data.blocked_ips.forEach(function(b) {
                var now = new Date();
                var expiresAt = b.expires_at ? new Date(b.expires_at) : null;
                var expired = expiresAt && expiresAt < now;

                var tr = document.createElement('tr');
                if (expired) tr.className = 'row-expired';

                var tdIp = document.createElement('td');
                tdIp.textContent = b.ip;
                tr.appendChild(tdIp);

                var tdReason = document.createElement('td');
                tdReason.textContent = b.reason || '';
                tr.appendChild(tdReason);

                var tdBlocked = document.createElement('td');
                tdBlocked.textContent = formatTimeFull(b.blocked_at);
                tr.appendChild(tdBlocked);

                var tdExpires = document.createElement('td');
                tdExpires.textContent = expiresAt ? formatTimeFull(b.expires_at) : 'Never';
                if (expired) tdExpires.textContent += ' (expired)';
                tr.appendChild(tdExpires);

                var tdAuto = document.createElement('td');
                tdAuto.textContent = b.auto ? 'Yes' : 'No';
                tr.appendChild(tdAuto);

                var tdActions = document.createElement('td');
                var btn = document.createElement('button');
                btn.className = 'btn-sm';
                btn.textContent = 'Unblock';
                btn.onclick = function() { fwUnblock(b.ip); };
                tdActions.appendChild(btn);
                tr.appendChild(tdActions);

                tbody.appendChild(tr);
            });

            var countEl = document.getElementById('block-count');
            if (countEl) countEl.textContent = data.blocked_ips.length;

            if (sortState['blocks-table']) {
                var s = sortState['blocks-table'];
                sortState['blocks-table'] = { col: s.col, dir: s.dir === 'asc' ? 'desc' : 'asc' };
                sortTable('blocks-table', s.col);
            }
        })
        .catch(function() {});

    fetch('/api/whitelist?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var tbody = document.getElementById('whitelist-table-body');
            if (!tbody || !data.whitelist) return;
            while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

            data.whitelist.forEach(function(cidr) {
                var tr = document.createElement('tr');

                var tdCidr = document.createElement('td');
                tdCidr.textContent = cidr;
                tr.appendChild(tdCidr);

                var tdActions = document.createElement('td');
                var btn = document.createElement('button');
                btn.className = 'btn-sm';
                btn.textContent = 'Remove';
                btn.onclick = function() { fwRemoveWhitelist(cidr); };
                tdActions.appendChild(btn);
                tr.appendChild(tdActions);

                tbody.appendChild(tr);
            });

            var countEl = document.getElementById('wl-count');
            if (countEl) countEl.textContent = data.whitelist.length;

            if (sortState['whitelist-table']) {
                var s = sortState['whitelist-table'];
                sortState['whitelist-table'] = { col: s.col, dir: s.dir === 'asc' ? 'desc' : 'asc' };
                sortTable('whitelist-table', s.col);
            }
        })
        .catch(function() {});
}

// === Helpers ===
function refreshStats() {
    fetch('/api/stats?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var el;
            el = document.querySelector('[data-stat="posture"]');
            if (el) {
                el.textContent = data.posture;
                var card = document.getElementById('card-posture');
                if (card) {
                    card.className = 'card posture-' + data.posture.toLowerCase();
                }
            }
            el = document.querySelector('[data-stat="total-threats"]');
            if (el) el.textContent = data.total_threats;
            el = document.querySelector('[data-stat="blocked-ips"]');
            if (el) el.textContent = data.blocked_ips;
            el = document.querySelector('[data-stat="scans-run"]');
            if (el) el.textContent = data.scans_run;
            if (data.severity) {
                for (var sev in data.severity) {
                    el = document.querySelector('[data-sev="' + sev + '"]');
                    if (el) el.textContent = data.severity[sev];
                }
            }
        })
        .catch(function() {});
}

function truncateStr(s, max) {
    if (!s) return '';
    return s.length > max ? s.substring(0, max) + '...' : s;
}

function formatThreatType(tt) {
    if (!tt) return '';
    return tt.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
}

function formatTime(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

function formatTimeFull(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' +
        pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

function pad2(n) {
    return n < 10 ? '0' + n : '' + n;
}

// === Localize server-rendered UTC timestamps to user's timezone ===
function localizeTimestamps() {
    document.querySelectorAll('[data-ts]').forEach(function(el) {
        var ts = el.getAttribute('data-ts');
        if (!ts) return;
        var d = new Date(ts);
        if (isNaN(d.getTime())) return;
        var cur = el.textContent.trim();
        if (/^\d{2}:\d{2}:\d{2}$/.test(cur)) {
            el.textContent = formatTime(ts);
        } else {
            var suffix = '';
            var match = cur.match(/(\s*\(.*\))$/);
            if (match) suffix = match[1];
            el.textContent = formatTimeFull(ts) + suffix;
        }
    });
}
localizeTimestamps();

// === Add threat type tooltips to server-rendered rows ===
(function() {
    document.querySelectorAll('tr[data-threat-type]').forEach(function(row) {
        var typeKey = row.getAttribute('data-threat-type');
        var explain = THREAT_EXPLANATIONS[typeKey];
        if (explain && row.cells[1] && !row.cells[1].getAttribute('data-tooltip')) {
            row.cells[1].className = (row.cells[1].className || '') + ' has-tooltip';
            row.cells[1].setAttribute('data-tooltip', explain);
        }
    });
})();

// === Config page toggle sections ===
function toggleConfigSection(el) {
    var section = el.closest('.config-section');
    if (section) section.classList.toggle('open');
}

// === Editable Config Page ===

var ALL_MODULES = ['network', 'process', 'file_integrity', 'auth', 'web', 'threat_intel', 'anomaly', 'honeypot', 'cert'];

var SCANNER_AGENT_PRESETS = ['nikto', 'sqlmap', 'nmap', 'masscan', 'zgrab', 'gobuster', 'dirbuster', 'wfuzz', 'nuclei', 'httpx', 'dirsearch', 'ffuf', 'burpsuite', 'acunetix', 'w3af', 'arachni'];

var CONFIG_SCHEMA = {
    general: { modules: 'module_checklist', log_level: 'string', data_dir: 'string', dedup_ttl: 'string' },
    network: { enabled: 'bool', syn_flood_threshold: 'number', port_scan_threshold: 'number',
               port_scan_window: 'number', known_outbound_ports: 'number_array',
               c2_beacon_threshold: 'number', c2_beacon_window: 'number', connection_rate_threshold: 'number' },
    process: { enabled: 'bool', miner_cpu_threshold: 'number', miner_names: 'string_array',
               suspicious_dirs: 'string_array', detect_reverse_shells: 'bool' },
    file_integrity: { enabled: 'module_toggle', watch_paths: 'string_array', exclude_paths: 'string_array',
                      baseline_path: 'string', use_inotify: 'bool' },
    auth: { enabled: 'bool', brute_force_threshold: 'number', brute_force_window: 'number',
            alert_root_login: 'bool', alert_new_ip: 'bool', log_paths: 'string_array' },
    web: { enabled: 'bool', access_log_paths: 'string_array', ddos_threshold: 'number',
           detect_sqli: 'bool', detect_path_traversal: 'bool', detect_scanners: 'bool',
           scanner_agents: 'string_array_suggest' },
    threat_intel: { enabled: 'bool', feed_dir: 'string', update_on_scan: 'bool', update_interval: 'string', feeds: 'feeds_editor' },
    response: { enabled: 'bool', dry_run: 'bool', max_blocks_per_minute: 'number',
                default_block_duration: 'string', max_firewall_rules: 'number',
                firewall_backend: 'string', whitelist: 'skip' },
    'response.geoip': { enabled: 'bool', database_path: 'string', maxmind_license_key: 'secret',
                        blocked_countries: 'string_array', allowed_countries: 'string_array' },
    alerting: { terminal: 'bool', log_file: 'string' },
    'alerting.email': { enabled: 'bool', smtp_host: 'string', smtp_port: 'number',
                        smtp_username: 'string', smtp_password: 'secret', use_tls: 'bool',
                        from: 'string', to: 'string_array', subject_prefix: 'string',
                        min_severity: 'string', cooldown: 'string' },
    'alerting.slack': { enabled: 'bool', webhook_url: 'secret', min_severity: 'string' },
    'alerting.telegram': { enabled: 'bool', bot_token: 'secret', chat_id: 'string', min_severity: 'string' },
    'alerting.webhook': { enabled: 'bool', url: 'secret', min_severity: 'string' },
    anomaly: { enabled: 'module_toggle', normal_login_hours: 'number_array', watch_cron: 'bool',
               watch_sudoers: 'bool', watch_user_changes: 'bool' },
    honeypot: { enabled: 'module_toggle', ports: 'number_array', auto_block: 'bool', linger_seconds: 'number' },
    cert: { enabled: 'module_toggle', domains: 'string_array', warn_days: 'number' }
};

function flattenConfig(configJson) {
    var flat = {};
    for (var key in configJson) {
        if (key === 'dashboard') continue;
        var val = configJson[key];
        if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
            flat[key] = {};
            for (var subkey in val) {
                var subval = val[subkey];
                if (typeof subval === 'object' && subval !== null && !Array.isArray(subval)) {
                    flat[key + '.' + subkey] = subval;
                } else {
                    flat[key][subkey] = subval;
                }
            }
        } else {
            flat[key] = val;
        }
    }
    return flat;
}

function titleCase(s) {
    return s.replace(/[._]/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
}

function renderConfigPage() {
    var container = document.getElementById('config-sections');
    if (!container) return;

    container.textContent = 'Loading configuration...';

    fetch('/api/config?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(configJson) {
            container.textContent = '';
            var flat = flattenConfig(configJson);

            Object.keys(CONFIG_SCHEMA).forEach(function(sectionKey) {
                var schema = CONFIG_SCHEMA[sectionKey];
                var data = flat[sectionKey] || {};
                var section = (schema === 'skip')
                    ? renderReadOnlySection(sectionKey, data)
                    : renderEditableSection(sectionKey, schema, data);
                container.appendChild(section);
            });
        })
        .catch(function(err) {
            container.textContent = 'Failed to load config: ' + err;
        });
}

function makeSectionHeader(title) {
    var header = document.createElement('div');
    header.className = 'config-section-header';
    var titleSpan = document.createElement('span');
    titleSpan.textContent = title;
    header.appendChild(titleSpan);
    var arrow = document.createElement('span');
    arrow.style.color = 'var(--text-muted)';
    arrow.textContent = '\u25BE';
    header.appendChild(arrow);
    return header;
}

function renderReadOnlySection(sectionKey, data) {
    var section = document.createElement('div');
    section.className = 'config-section';

    var header = makeSectionHeader(titleCase(sectionKey));
    header.onclick = function() { section.classList.toggle('open'); };
    section.appendChild(header);

    var body = document.createElement('div');
    body.className = 'config-section-body';

    if (typeof data === 'object' && data !== null) {
        for (var key in data) {
            var row = document.createElement('div');
            row.className = 'config-row';
            var keySpan = document.createElement('span');
            keySpan.className = 'config-key';
            keySpan.textContent = key;
            row.appendChild(keySpan);
            var valSpan = document.createElement('span');
            valSpan.className = 'config-value';
            var val = data[key];
            valSpan.textContent = typeof val === 'object' ? JSON.stringify(val) : String(val);
            row.appendChild(valSpan);
            body.appendChild(row);
        }
    }

    var note = document.createElement('p');
    note.style.cssText = 'color:var(--text-muted);font-size:12px;margin-top:8px';
    note.textContent = 'This section is read-only in the web UI. Edit the TOML file directly.';
    body.appendChild(note);

    section.appendChild(body);
    return section;
}

function renderEditableSection(sectionKey, schema, data) {
    var section = document.createElement('div');
    section.className = 'config-section';
    section.id = 'config-section-' + sectionKey.replace('.', '-');

    var header = makeSectionHeader(titleCase(sectionKey));
    header.onclick = function() { section.classList.toggle('open'); };
    section.appendChild(header);

    var body = document.createElement('div');
    body.className = 'config-section-body';

    var feedback = document.createElement('div');
    feedback.className = 'config-feedback';
    feedback.id = 'feedback-' + sectionKey.replace('.', '-');
    body.appendChild(feedback);

    Object.keys(schema).forEach(function(key) {
        var fieldType = schema[key];
        var value = data[key];

        if (fieldType === 'skip') {
            var row = document.createElement('div');
            row.className = 'config-edit-row';
            var lbl = document.createElement('label');
            lbl.className = 'config-edit-label';
            lbl.textContent = key;
            row.appendChild(lbl);
            var valSpan = document.createElement('span');
            valSpan.className = 'config-value';
            valSpan.style.fontSize = '13px';
            valSpan.textContent = value != null ? (Array.isArray(value) ? value.join(', ') : String(value)) : '';
            row.appendChild(valSpan);
            body.appendChild(row);
            return;
        }

        var row = document.createElement('div');
        row.className = 'config-edit-row';

        var label = document.createElement('label');
        label.className = 'config-edit-label';
        label.textContent = key.replace(/_/g, ' ');
        row.appendChild(label);

        var inputWrap = document.createElement('div');
        inputWrap.className = 'config-edit-input';

        if (fieldType === 'module_checklist') {
            inputWrap.appendChild(createModuleChecklist(sectionKey, key, Array.isArray(value) ? value : []));
        } else if (fieldType === 'feeds_editor') {
            // Feeds editor is rendered after the normal fields
        } else if (fieldType === 'bool' || fieldType === 'module_toggle') {
            inputWrap.appendChild(createToggle(sectionKey, key, fieldType, !!value));
        } else if (fieldType === 'number') {
            var input = document.createElement('input');
            input.type = 'number';
            input.className = 'cfg-input';
            input.id = 'cfg-' + sectionKey.replace('.', '-') + '-' + key;
            input.value = value != null ? value : '';
            inputWrap.appendChild(input);
        } else if (fieldType === 'string') {
            var input = document.createElement('input');
            input.type = 'text';
            input.className = 'cfg-input';
            input.id = 'cfg-' + sectionKey.replace('.', '-') + '-' + key;
            input.value = value != null ? value : '';
            inputWrap.appendChild(input);
        } else if (fieldType === 'secret') {
            var input = document.createElement('input');
            input.type = 'password';
            input.className = 'cfg-input';
            input.id = 'cfg-' + sectionKey.replace('.', '-') + '-' + key;
            input.placeholder = 'unchanged';
            input.value = value != null ? value : '';
            inputWrap.appendChild(input);
        } else if (fieldType === 'string_array' || fieldType === 'number_array') {
            inputWrap.appendChild(createTagInput(sectionKey, key, fieldType, Array.isArray(value) ? value : []));
        } else if (fieldType === 'string_array_suggest') {
            inputWrap.appendChild(createTagInputWithSuggest(sectionKey, key, Array.isArray(value) ? value : [], SCANNER_AGENT_PRESETS));
        }

        row.appendChild(inputWrap);
        body.appendChild(row);
    });

    // Feeds editor for threat_intel
    if (sectionKey === 'threat_intel' && data.feeds && typeof data.feeds === 'object') {
        var feedsDiv = document.createElement('div');
        feedsDiv.id = 'feeds-editor';
        feedsDiv.style.marginTop = '12px';

        var feedsTitle = document.createElement('div');
        feedsTitle.style.cssText = 'font-weight:600;font-size:13px;color:var(--text-primary);margin-bottom:8px;border-bottom:1px solid var(--border-primary);padding-bottom:4px';
        feedsTitle.textContent = 'Threat Intelligence Feeds';
        feedsDiv.appendChild(feedsTitle);

        for (var feedName in data.feeds) {
            feedsDiv.appendChild(createFeedCard(feedName, data.feeds[feedName]));
        }
        body.appendChild(feedsDiv);
    }

    // Discovery buttons
    if (sectionKey === 'honeypot') {
        var discBtn = document.createElement('button');
        discBtn.className = 'btn-discover';
        discBtn.textContent = 'Discover Ports';
        discBtn.onclick = function() { discoverPorts(); };
        body.appendChild(discBtn);
    }
    if (sectionKey === 'cert') {
        var discBtn = document.createElement('button');
        discBtn.className = 'btn-discover';
        discBtn.textContent = 'Discover Domains';
        discBtn.onclick = function() { discoverDomains(); };
        body.appendChild(discBtn);
    }

    var saveBtn = document.createElement('button');
    saveBtn.className = 'btn-save-section';
    saveBtn.textContent = 'Save ' + titleCase(sectionKey);
    saveBtn.onclick = function() { saveConfigSection(sectionKey, schema); };
    body.appendChild(saveBtn);

    section.appendChild(body);
    return section;
}

function createToggle(sectionKey, key, fieldType, checked) {
    var wrap = document.createElement('label');
    wrap.className = 'toggle-switch';

    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = checked;
    cb.id = 'cfg-' + sectionKey.replace('.', '-') + '-' + key;

    if (fieldType === 'module_toggle') {
        cb.onchange = function() { toggleModule(sectionKey, cb.checked); };
    }

    wrap.appendChild(cb);
    var slider = document.createElement('span');
    slider.className = 'toggle-slider';
    wrap.appendChild(slider);
    return wrap;
}

function createTagInput(sectionKey, key, fieldType, values) {
    var container = document.createElement('div');
    container.className = 'tag-input-container';
    container.id = 'tags-' + sectionKey.replace('.', '-') + '-' + key;
    container.setAttribute('data-field-type', fieldType);

    values.forEach(function(v) { addTag(container, String(v)); });

    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'tag-add-input';
    input.placeholder = fieldType === 'number_array' ? 'Add number...' : 'Add item...';
    input.onkeydown = function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            var val = input.value.trim();
            if (!val) return;
            if (fieldType === 'number_array' && isNaN(Number(val))) {
                input.style.borderColor = 'var(--accent-red)';
                return;
            }
            input.style.borderColor = '';
            addTag(container, val);
            input.value = '';
        }
    };
    container.appendChild(input);
    return container;
}

function addTag(container, value) {
    var input = container.querySelector('.tag-add-input');
    var pill = document.createElement('span');
    pill.className = 'tag-pill';
    pill.setAttribute('data-value', value);
    pill.textContent = value + ' ';
    var close = document.createElement('button');
    close.className = 'tag-remove';
    close.textContent = '\u00D7';
    close.onclick = function() { pill.remove(); };
    pill.appendChild(close);
    if (input) {
        container.insertBefore(pill, input);
    } else {
        container.appendChild(pill);
    }
}

function getTagValues(container) {
    var pills = container.querySelectorAll('.tag-pill');
    var values = [];
    pills.forEach(function(p) { values.push(p.getAttribute('data-value')); });
    return values;
}

function saveConfigSection(sectionKey, schema) {
    var updates = {};
    Object.keys(schema).forEach(function(key) {
        var fieldType = schema[key];
        if (fieldType === 'skip' || fieldType === 'feeds_editor') return;

        var elId = 'cfg-' + sectionKey.replace('.', '-') + '-' + key;

        if (fieldType === 'module_checklist') {
            var container = document.getElementById('module-checklist');
            if (container) {
                var selected = [];
                container.querySelectorAll('input[type="checkbox"]:checked').forEach(function(cb) {
                    selected.push(cb.value);
                });
                updates[key] = selected;
            }
        } else if (fieldType === 'bool' || fieldType === 'module_toggle') {
            var el = document.getElementById(elId);
            if (el) updates[key] = el.checked;
        } else if (fieldType === 'number') {
            var el = document.getElementById(elId);
            if (el && el.value !== '') updates[key] = Number(el.value);
        } else if (fieldType === 'string') {
            var el = document.getElementById(elId);
            if (el) updates[key] = el.value;
        } else if (fieldType === 'secret') {
            var el = document.getElementById(elId);
            if (el) updates[key] = el.value;
        } else if (fieldType === 'string_array' || fieldType === 'string_array_suggest') {
            var tc = document.getElementById('tags-' + sectionKey.replace('.', '-') + '-' + key);
            if (tc) updates[key] = getTagValues(tc);
        } else if (fieldType === 'number_array') {
            var tc = document.getElementById('tags-' + sectionKey.replace('.', '-') + '-' + key);
            if (tc) updates[key] = getTagValues(tc).map(function(v) { return Number(v); });
        }
    });

    var feedbackId = 'feedback-' + sectionKey.replace('.', '-');
    var feedback = document.getElementById(feedbackId);
    if (feedback) {
        feedback.textContent = 'Saving...';
        feedback.className = 'config-feedback';
    }

    fetch('/api/config?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ section: sectionKey, updates: updates })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (!feedback) return;
        if (data.status === 'ok') {
            feedback.textContent = 'Saved. Restart aegis to apply changes.';
            feedback.className = 'config-feedback config-feedback-ok';
            if (data.warnings && data.warnings.length > 0) {
                feedback.textContent += ' Warnings: ' + data.warnings.join('; ');
                feedback.className = 'config-feedback config-feedback-warn';
            }
        } else {
            feedback.textContent = 'Error: ' + (data.message || 'Unknown error');
            feedback.className = 'config-feedback config-feedback-err';
        }
    })
    .catch(function(err) {
        if (feedback) {
            feedback.textContent = 'Error: ' + err;
            feedback.className = 'config-feedback config-feedback-err';
        }
    });
}

function toggleModule(module, enabled) {
    fetch('/api/module/toggle?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ module: module, enabled: enabled })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showResult('Module Updated', data.message, false);
        } else {
            showResult('Toggle Failed', data.message || 'Unknown error', true);
        }
    })
    .catch(function(err) {
        showResult('Toggle Failed', 'Error: ' + err, true);
    });
}

function discoverPorts() {
    showModal('Discovering Ports', '<p>Scanning listening ports...</p>', '');
    fetch('/api/discover/ports?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var body = document.createElement('div');

            var listeningP = document.createElement('p');
            listeningP.style.marginBottom = '12px';
            var listeningB = document.createElement('strong');
            listeningB.textContent = 'Currently listening: ';
            listeningP.appendChild(listeningB);
            listeningP.appendChild(document.createTextNode((data.listening_ports || []).join(', ')));
            body.appendChild(listeningP);

            var suggestP = document.createElement('p');
            var suggestB = document.createElement('strong');
            suggestB.textContent = 'Suggested honeypot ports (not in use):';
            suggestP.appendChild(suggestB);
            suggestP.style.marginBottom = '8px';
            body.appendChild(suggestP);

            var checkboxDiv = document.createElement('div');
            checkboxDiv.style.margin = '8px 0';
            (data.suggested_honeypot_ports || []).forEach(function(item) {
                var port = item.port || item;
                var service = item.service || '';
                var label = document.createElement('label');
                label.style.cssText = 'display:block;padding:3px 0;cursor:pointer;font-size:13px';
                var cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.className = 'discover-port-cb';
                cb.value = port;
                cb.style.marginRight = '8px';
                label.appendChild(cb);
                label.appendChild(document.createTextNode(port + (service ? ' (' + service + ')' : '')));
                checkboxDiv.appendChild(label);
            });
            body.appendChild(checkboxDiv);

            document.getElementById('modal-title').textContent = 'Port Discovery';
            var modalBody = document.getElementById('modal-body');
            modalBody.textContent = '';
            modalBody.appendChild(body);

            var footer = document.getElementById('modal-footer');
            footer.textContent = '';
            var applyBtn = document.createElement('button');
            applyBtn.style.background = 'var(--btn-green)';
            applyBtn.textContent = 'Apply Selected';
            applyBtn.onclick = function() {
                var selected = [];
                document.querySelectorAll('.discover-port-cb:checked').forEach(function(cb) {
                    selected.push(cb.value);
                });
                applyDiscoveredPorts(selected);
                hideModal();
            };
            footer.appendChild(applyBtn);
            var closeBtn = document.createElement('button');
            closeBtn.className = 'btn-modal-cancel';
            closeBtn.textContent = 'Cancel';
            closeBtn.onclick = hideModal;
            footer.appendChild(closeBtn);
        })
        .catch(function(err) {
            showResult('Discovery Failed', 'Error: ' + err, true);
        });
}

function applyDiscoveredPorts(ports) {
    var tagContainer = document.getElementById('tags-honeypot-ports');
    if (!tagContainer) return;
    ports.forEach(function(port) {
        var existing = getTagValues(tagContainer);
        if (existing.indexOf(String(port)) === -1) {
            addTag(tagContainer, String(port));
        }
    });
}

function discoverDomains() {
    showModal('Discovering Domains', '<p>Scanning nginx configs...</p>', '');
    fetch('/api/discover/domains?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var body = document.createElement('div');

            if (data.errors && data.errors.length > 0) {
                var errP = document.createElement('p');
                errP.style.cssText = 'color:var(--accent-gold);margin-bottom:8px;font-size:12px';
                errP.textContent = 'Notes: ' + data.errors.join('; ');
                body.appendChild(errP);
            }

            var domains = data.domains || [];
            if (domains.length === 0) {
                var noP = document.createElement('p');
                noP.textContent = 'No SSL domains found in nginx configs.';
                body.appendChild(noP);
            } else {
                var p = document.createElement('p');
                var pB = document.createElement('strong');
                pB.textContent = 'SSL domains found:';
                p.appendChild(pB);
                p.style.marginBottom = '8px';
                body.appendChild(p);

                var checkboxDiv = document.createElement('div');
                checkboxDiv.style.margin = '8px 0';
                domains.forEach(function(domain) {
                    var label = document.createElement('label');
                    label.style.cssText = 'display:block;padding:3px 0;cursor:pointer;font-size:13px';
                    var cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.className = 'discover-domain-cb';
                    cb.value = domain;
                    cb.checked = true;
                    cb.style.marginRight = '8px';
                    label.appendChild(cb);
                    label.appendChild(document.createTextNode(domain));
                    checkboxDiv.appendChild(label);
                });
                body.appendChild(checkboxDiv);
            }

            document.getElementById('modal-title').textContent = 'Domain Discovery';
            var modalBody = document.getElementById('modal-body');
            modalBody.textContent = '';
            modalBody.appendChild(body);

            var footer = document.getElementById('modal-footer');
            footer.textContent = '';
            if (domains.length > 0) {
                var applyBtn = document.createElement('button');
                applyBtn.style.background = 'var(--btn-green)';
                applyBtn.textContent = 'Apply Selected';
                applyBtn.onclick = function() {
                    var selected = [];
                    document.querySelectorAll('.discover-domain-cb:checked').forEach(function(cb) {
                        selected.push(cb.value);
                    });
                    applyDiscoveredDomains(selected);
                    hideModal();
                };
                footer.appendChild(applyBtn);
            }
            var closeBtn = document.createElement('button');
            closeBtn.className = 'btn-modal-cancel';
            closeBtn.textContent = 'Close';
            closeBtn.onclick = hideModal;
            footer.appendChild(closeBtn);
        })
        .catch(function(err) {
            showResult('Discovery Failed', 'Error: ' + err, true);
        });
}

function applyDiscoveredDomains(domains) {
    var tagContainer = document.getElementById('tags-cert-domains');
    if (!tagContainer) return;
    domains.forEach(function(domain) {
        var existing = getTagValues(tagContainer);
        if (existing.indexOf(domain) === -1) {
            addTag(tagContainer, domain);
        }
    });
}

// === Module checklist (for general.modules) ===
function createModuleChecklist(sectionKey, key, selected) {
    var container = document.createElement('div');
    container.className = 'module-checklist';
    container.id = 'module-checklist';

    ALL_MODULES.forEach(function(mod) {
        var label = document.createElement('label');
        label.className = 'checklist-item';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = mod;
        cb.checked = selected.indexOf(mod) >= 0;
        label.appendChild(cb);
        label.appendChild(document.createTextNode(' ' + mod.replace(/_/g, ' ')));
        container.appendChild(label);
    });
    return container;
}

// === Tag input with suggestion dropdown ===
function createTagInputWithSuggest(sectionKey, key, values, presets) {
    var outer = document.createElement('div');

    var tagContainer = createTagInput(sectionKey, key, 'string_array', values);
    outer.appendChild(tagContainer);

    // Suggestion buttons
    var suggestDiv = document.createElement('div');
    suggestDiv.className = 'tag-suggestions';
    var suggestLabel = document.createElement('span');
    suggestLabel.textContent = 'Add: ';
    suggestLabel.style.cssText = 'font-size:11px;color:var(--text-muted)';
    suggestDiv.appendChild(suggestLabel);

    presets.forEach(function(preset) {
        var btn = document.createElement('button');
        btn.className = 'tag-suggest-btn';
        btn.textContent = preset;
        btn.onclick = function() {
            var existing = getTagValues(tagContainer);
            if (existing.indexOf(preset) === -1) {
                addTag(tagContainer, preset);
            }
        };
        suggestDiv.appendChild(btn);
    });
    outer.appendChild(suggestDiv);
    return outer;
}

// === Feed card for threat_intel feeds ===
function createFeedCard(feedName, feedData) {
    var card = document.createElement('div');
    card.className = 'feed-card';
    card.id = 'feed-card-' + feedName;

    var header = document.createElement('div');
    header.className = 'feed-card-header';
    header.onclick = function() { card.classList.toggle('open'); };

    var nameSpan = document.createElement('span');
    nameSpan.className = 'feed-card-name';
    nameSpan.textContent = feedName;
    header.appendChild(nameSpan);

    var toggleWrap = document.createElement('label');
    toggleWrap.className = 'toggle-switch';
    toggleWrap.onclick = function(e) { e.stopPropagation(); };
    var toggleCb = document.createElement('input');
    toggleCb.type = 'checkbox';
    toggleCb.checked = !!feedData.enabled;
    toggleCb.id = 'feed-enabled-' + feedName;
    toggleWrap.appendChild(toggleCb);
    var slider = document.createElement('span');
    slider.className = 'toggle-slider';
    toggleWrap.appendChild(slider);
    header.appendChild(toggleWrap);

    card.appendChild(header);

    var body = document.createElement('div');
    body.className = 'feed-card-body';

    // URL field
    var urlRow = document.createElement('div');
    urlRow.className = 'config-edit-row';
    var urlLabel = document.createElement('label');
    urlLabel.className = 'config-edit-label';
    urlLabel.textContent = 'url';
    urlRow.appendChild(urlLabel);
    var urlWrap = document.createElement('div');
    urlWrap.className = 'config-edit-input';
    var urlInput = document.createElement('input');
    urlInput.type = 'text';
    urlInput.className = 'cfg-input';
    urlInput.id = 'feed-url-' + feedName;
    urlInput.value = feedData.url || '';
    urlInput.style.maxWidth = '100%';
    urlWrap.appendChild(urlInput);
    urlRow.appendChild(urlWrap);
    body.appendChild(urlRow);

    // Weight field
    var weightRow = document.createElement('div');
    weightRow.className = 'config-edit-row';
    var weightLabel = document.createElement('label');
    weightLabel.className = 'config-edit-label';
    weightLabel.textContent = 'weight (0-100)';
    weightRow.appendChild(weightLabel);
    var weightWrap = document.createElement('div');
    weightWrap.className = 'config-edit-input';
    var weightInput = document.createElement('input');
    weightInput.type = 'number';
    weightInput.className = 'cfg-input';
    weightInput.id = 'feed-weight-' + feedName;
    weightInput.value = feedData.weight != null ? feedData.weight : 50;
    weightInput.min = '0';
    weightInput.max = '100';
    weightWrap.appendChild(weightInput);
    weightRow.appendChild(weightWrap);
    body.appendChild(weightRow);

    // Feedback
    var feedback = document.createElement('div');
    feedback.className = 'config-feedback';
    feedback.id = 'feed-feedback-' + feedName;
    body.appendChild(feedback);

    // Save feed button
    var saveBtn = document.createElement('button');
    saveBtn.className = 'btn-save-section';
    saveBtn.style.marginTop = '8px';
    saveBtn.textContent = 'Save Feed';
    saveBtn.onclick = function() { saveFeed(feedName); };
    body.appendChild(saveBtn);

    card.appendChild(body);
    return card;
}

function saveFeed(feedName) {
    var enabledEl = document.getElementById('feed-enabled-' + feedName);
    var urlEl = document.getElementById('feed-url-' + feedName);
    var weightEl = document.getElementById('feed-weight-' + feedName);
    var feedback = document.getElementById('feed-feedback-' + feedName);

    var updates = {};
    if (enabledEl) updates.enabled = enabledEl.checked;
    if (urlEl) updates.url = urlEl.value;
    if (weightEl && weightEl.value !== '') updates.weight = Number(weightEl.value);

    if (feedback) {
        feedback.textContent = 'Saving...';
        feedback.className = 'config-feedback';
    }

    fetch('/api/config?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ section: 'threat_intel.feeds.' + feedName, updates: updates })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (!feedback) return;
        if (data.status === 'ok') {
            feedback.textContent = 'Saved. Restart aegis to apply.';
            feedback.className = 'config-feedback config-feedback-ok';
        } else {
            feedback.textContent = 'Error: ' + (data.message || 'Unknown error');
            feedback.className = 'config-feedback config-feedback-err';
        }
    })
    .catch(function(err) {
        if (feedback) {
            feedback.textContent = 'Error: ' + err;
            feedback.className = 'config-feedback config-feedback-err';
        }
    });
}

// === Restart aegis ===
function restartAegis() {
    showConfirm('Restart Aegis',
        'This will restart the aegis daemon to apply configuration changes. The page will briefly disconnect.',
        function() {
            showModal('Restarting', '', '');
            var modalBody = document.getElementById('modal-body');
            var p = document.createElement('p');
            p.textContent = 'Sending restart signal...';
            modalBody.textContent = '';
            modalBody.appendChild(p);

            fetch('/api/restart?token=' + API_TOKEN, { method: 'POST' })
                .then(function(r) { return r.json(); })
                .then(function() {
                    p.textContent = 'Restarting... reconnecting in a few seconds.';
                    // Poll for reconnection
                    var attempts = 0;
                    var poll = setInterval(function() {
                        attempts++;
                        fetch('/health')
                            .then(function(r) {
                                if (r.ok) {
                                    clearInterval(poll);
                                    showResult('Restarted', 'Aegis has restarted successfully. Reloading page...', false);
                                    setTimeout(function() { location.reload(); }, 1500);
                                }
                            })
                            .catch(function() {});
                        if (attempts > 30) {
                            clearInterval(poll);
                            showResult('Restart Timeout', 'Could not reconnect. Check aegis status manually.', true);
                        }
                    }, 2000);
                })
                .catch(function(err) {
                    showResult('Restart Failed', 'Error: ' + err, true);
                });
        }
    );
}

// Auto-init config page
(function() {
    if (document.getElementById('config-sections')) renderConfigPage();
})();
