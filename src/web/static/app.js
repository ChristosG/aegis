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
    showModal(title, '<p>' + message + '</p>',
        '<button class="btn-modal-cancel" onclick="hideModal()">Cancel</button>' +
        '<button class="btn-modal-confirm" id="modal-confirm-btn">Confirm</button>'
    );
    document.getElementById('modal-confirm-btn').onclick = function() {
        hideModal();
        onConfirm();
    };
}

function showResult(title, message, isError) {
    var cls = isError ? 'modal-error' : 'modal-success';
    showModal(title, '<p class="' + cls + '">' + message + '</p>',
        '<button class="btn-modal-cancel" onclick="hideModal()">Close</button>'
    );
}

// === Sort & Filter State ===
var sortState = {}; // keyed by tableId: { col: index, dir: 'asc'|'desc' }
var currentFilter = null; // severity string or null
var fileIntegrityHidden = true; // FI threats hidden by default

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

// === Severity Filtering ===
function filterBySeverity(severity) {
    if (currentFilter === severity) {
        clearFilter();
        return;
    }
    currentFilter = severity;
    applyFilter();
    updateFilterBar();
    updateFilterButtons();
}

function clearFilter() {
    currentFilter = null;
    applyFilter();
    updateFilterBar();
    updateFilterButtons();
}

function applyFilter() {
    var tbodies = document.querySelectorAll('#recent-threats-body, #threats-table-body');
    tbodies.forEach(function(tbody) {
        var rows = tbody.querySelectorAll('tr');
        rows.forEach(function(row) {
            var sevMatch = !currentFilter || row.getAttribute('data-severity') === currentFilter;
            var threatType = row.getAttribute('data-threat-type') || '';
            var fiMatch = !fileIntegrityHidden || !threatType.startsWith('file_');
            if (sevMatch && fiMatch) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
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
            // Increment severity counter live
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

    // Apply FI filter on page load to hide file integrity rows by default
    if (hasDashboard || hasThreatsPage) applyFilter();

    if (!hasDashboard && !hasThreatsPage && !hasFirewallPage) return;

    setInterval(function() {
        if (hasDashboard) refreshStats();
        if (hasDashboard || hasThreatsPage) refreshThreatTable();
        if (hasFirewallPage) refreshFirewallTables();
    }, 15000);
})();

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

            // Re-apply current sort and filter
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

    var tdSev = document.createElement('td');
    tdSev.className = 'sev-' + sev;
    tdSev.textContent = t.severity || '';
    tr.appendChild(tdSev);

    var tdType = document.createElement('td');
    tdType.textContent = formatThreatType(t.threat_type);
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

    var tdSev = document.createElement('td');
    tdSev.className = 'sev-' + sev;
    tdSev.textContent = t.severity || '';
    tr.appendChild(tdSev);

    var tdType = document.createElement('td');
    tdType.textContent = formatThreatType(t.threat_type);
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
        btn.onclick = function() { blockIp(ip); };
        tdActions.appendChild(btn);
    }
    tr.appendChild(tdActions);

    return tr;
}

// === Actions ===
function triggerScan() {
    showModal('Running Scan', '<p>Scanning all modules...</p>', '');
    fetch('/api/scan?token=' + API_TOKEN, { method: 'POST' })
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

// === Baseline Reset ===
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
                        // Update UI
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
    // Refresh blocked IPs
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

            // Re-apply sort if active
            if (sortState['blocks-table']) {
                var s = sortState['blocks-table'];
                sortState['blocks-table'] = { col: s.col, dir: s.dir === 'asc' ? 'desc' : 'asc' };
                sortTable('blocks-table', s.col);
            }
        })
        .catch(function() {});

    // Refresh whitelist
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

            // Re-apply sort if active
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
    // Convert snake_case to Title Case
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
        // Short format if current text is time-only (HH:MM:SS), full otherwise
        var cur = el.textContent.trim();
        if (/^\d{2}:\d{2}:\d{2}$/.test(cur)) {
            el.textContent = formatTime(ts);
        } else {
            // Preserve any suffix like " (expired)"
            var suffix = '';
            var match = cur.match(/(\s*\(.*\))$/);
            if (match) suffix = match[1];
            el.textContent = formatTimeFull(ts) + suffix;
        }
    });
}
localizeTimestamps();
