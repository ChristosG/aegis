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

// === Auto-refresh dashboard stats every 15s ===
(function() {
    if (!document.querySelector('[data-stat="total-threats"]')) return;

    setInterval(function() {
        fetch('/api/stats?token=' + API_TOKEN)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var el;
                el = document.querySelector('[data-stat="posture"]');
                if (el) {
                    el.textContent = data.posture;
                    // Update posture card class
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
    }, 15000);
})();

// === Actions ===
function triggerScan() {
    showModal('Running Scan', '<p>Scanning all modules...</p>', '');
    fetch('/api/scan?token=' + API_TOKEN, { method: 'POST' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var body = '<p>Scan complete: <strong>' + data.threats_found + '</strong> threat(s) found.</p>';
            if (data.threats && data.threats.length > 0) {
                body += '<table class="threats-table" style="margin-top:12px;width:100%"><thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>';
                data.threats.forEach(function(t) {
                    body += '<tr><td class="sev-' + t.severity + '">' + t.severity + '</td><td>' + t.threat_type + '</td><td>' + truncateStr(t.description, 60) + '</td></tr>';
                });
                body += '</tbody></table>';
            }
            showModal('Scan Results', body,
                '<button class="btn-modal-cancel" onclick="hideModal()">Close</button>'
            );
            refreshStats();
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
                var body = '<p>Responded to <strong>' + data.responded + '</strong> threat(s).</p>';
                if (data.results && data.results.length > 0) {
                    body += '<table class="threats-table" style="margin-top:12px;width:100%"><thead><tr><th>Threat</th><th>Action</th><th>Result</th></tr></thead><tbody>';
                    data.results.forEach(function(r) {
                        var result = r.result || r.error || 'unknown';
                        var cls = r.error ? 'modal-error' : '';
                        body += '<tr><td>' + r.threat_id + '</td><td>' + r.action + '</td><td class="' + cls + '">' + truncateStr(result, 50) + '</td></tr>';
                    });
                    body += '</tbody></table>';
                }
                showModal('Auto-Respond Results', body,
                    '<button class="btn-modal-cancel" onclick="hideModal()">Close</button>'
                );
                refreshStats();
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

// === Helpers ===
function refreshStats() {
    fetch('/api/stats?token=' + API_TOKEN)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var el;
            el = document.querySelector('[data-stat="posture"]');
            if (el) el.textContent = data.posture;
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
