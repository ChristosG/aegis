// WebSocket for live threat updates
(function() {
    const liveCont = document.getElementById('live-threats');
    if (!liveCont) return;

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(proto + '//' + location.host + '/ws/threats?token=' + API_TOKEN);

    ws.onmessage = function(e) {
        try {
            const t = JSON.parse(e.data);
            const div = document.createElement('div');
            div.className = 'live-event';
            div.textContent = '[' + t.severity + '] ' + t.threat_type + ' - ' + t.description;
            liveCont.prepend(div);
            // Keep max 20 live events
            while (liveCont.children.length > 20) {
                liveCont.removeChild(liveCont.lastChild);
            }
        } catch(err) {}
    };

    ws.onclose = function() {
        const div = document.createElement('div');
        div.className = 'live-event';
        div.textContent = 'WebSocket disconnected. Refresh to reconnect.';
        liveCont.prepend(div);
    };
})();

function triggerScan() {
    fetch('/api/scan?token=' + API_TOKEN, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            alert('Scan complete: ' + data.threats_found + ' threat(s) found');
            location.reload();
        })
        .catch(err => alert('Scan failed: ' + err));
}

function exportReport() {
    window.open('/report.pdf?token=' + API_TOKEN, '_blank');
}

function blockIp(ip) {
    if (!confirm('Block IP ' + ip + '?')) return;
    fetch('/api/block?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(r => r.json())
    .then(data => {
        alert('IP ' + ip + ' blocked');
        location.reload();
    })
    .catch(err => alert('Block failed: ' + err));
}

function unblockIp(ip) {
    if (!confirm('Unblock IP ' + ip + '?')) return;
    fetch('/api/unblock?token=' + API_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(r => r.json())
    .then(data => {
        alert('IP ' + ip + ' unblocked');
        location.reload();
    })
    .catch(err => alert('Unblock failed: ' + err));
}
