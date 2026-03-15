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

// === Config page toggle sections ===
function toggleConfigSection(el) {
    var section = el.closest('.config-section');
    if (section) section.classList.toggle('open');
}
