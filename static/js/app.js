// NetProbe - Frontend Logic

let scanData = null;
let currentScanId = null;

// ===== Helpers =====
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function $(id) { return document.getElementById(id); }

function showError(msg) {
    const toast = $('errorToast');
    toast.textContent = msg;
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), 5000);
}

// ===== Event Listeners (no inline handlers) =====
document.addEventListener('DOMContentLoaded', () => {
    // Tab navigation
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            $('tab-' + tab.dataset.tab).classList.add('active');
        });
    });

    // Enter key triggers scan
    $('domainInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') startScan();
    });

    // Scan button
    $('scanBtn').addEventListener('click', startScan);

    // Export button
    $('exportBtn').addEventListener('click', exportResults);

    // Report button
    $('reportBtn').addEventListener('click', openReport);

    // History drawer
    $('historyBtn').addEventListener('click', openHistory);
    $('historyCloseBtn').addEventListener('click', closeHistory);
    $('drawerOverlay').addEventListener('click', closeHistory);
    $('historyClearBtn').addEventListener('click', clearHistory);

    // "All Checks" toggle
    const allCheckbox = document.querySelector('input[value="all"]');
    allCheckbox.addEventListener('change', () => {
        const items = document.querySelectorAll('.check-item');
        items.forEach(i => { i.checked = false; i.disabled = allCheckbox.checked; });
    });

    // If any individual checkbox ticked, uncheck "all"
    document.querySelectorAll('.check-item').forEach(cb => {
        cb.addEventListener('change', () => {
            if (cb.checked) allCheckbox.checked = false;
        });
    });
});

// ===== Export Results =====
function exportResults() {
    if (!scanData) return;
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netprobe-${scanData.domain}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ===== Start Scan =====
async function startScan() {
    const domain = $('domainInput').value.trim();
    if (!domain) {
        showError('Please enter a domain name');
        return;
    }

    const allChecked = document.querySelector('input[value="all"]').checked;
    let checks = ['all'];
    if (!allChecked) {
        checks = Array.from(document.querySelectorAll('.check-item:checked')).map(c => c.value);
        if (checks.length === 0) checks = ['all'];
    }

    $('loading').classList.remove('hidden');
    $('loadingDomain').textContent = domain;
    $('results').classList.add('hidden');
    $('scanBtn').disabled = true;

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, checks }),
        });
        const data = await resp.json();

        if (!resp.ok || data.error) {
            showError(data.error || `Scan failed (${resp.status})`);
            return;
        }

        scanData = data;
        currentScanId = data.scan_id || null;
        renderResults(data);
    } catch (err) {
        showError('Network error: could not reach server');
    } finally {
        $('loading').classList.add('hidden');
        $('scanBtn').disabled = false;
    }
}

// ===== Render Results =====
function renderResults(data) {
    $('resultDomain').textContent = data.domain;
    $('resultTimestamp').textContent = new Date(data.timestamp).toLocaleString();

    renderScoreOverview(data);
    renderRecommendations(data);
    renderWhois(data.whois);
    renderDns(data.dns);
    renderDnssec(data.dnssec);
    renderSpf(data.spf);
    renderDmarc(data.dmarc);
    renderDkim(data.dkim);
    renderMtaSts(data.mta_sts);
    renderTlsrpt(data.tlsrpt);
    renderSsl(data.ssl);
    renderTlsDeep(data.tls_deep);
    renderHttpsRedirect(data.https_redirect);
    renderHeaders(data.http_headers);
    renderIpv6(data.ipv6);
    renderBlacklist(data.blacklist);
    renderPorts(data.ports);

    document.querySelectorAll('.tab')[0].click();
    $('results').classList.remove('hidden');
}

// ===== Score Overview =====
function renderScoreOverview(data) {
    const grid = $('scoreGrid');
    grid.innerHTML = '';

    const checks = [
        { label: 'DNSSEC', pass: data.dnssec?.signed },
        { label: 'SPF', pass: data.spf?.pass },
        { label: 'DMARC', pass: data.dmarc?.pass },
        { label: 'DKIM', pass: data.dkim?.pass },
        { label: 'MTA-STS', pass: data.mta_sts?.pass },
        { label: 'TLS-RPT', pass: data.tlsrpt?.pass },
        { label: 'HTTPS', pass: data.https_redirect?.pass },
        { label: 'SSL Valid', pass: data.ssl?.success && !data.ssl?.expired },
        { label: 'TLS Grade', pass: data.tls_deep?.grade && ['A+', 'A'].includes(data.tls_deep.grade), warn: data.tls_deep?.grade === 'B' },
        { label: 'Fwd Secrecy', pass: data.tls_deep?.cipher_summary?.forward_secrecy > 0 },
        { label: 'Headers', pass: data.http_headers?.score >= 50, warn: data.http_headers?.score >= 25 && data.http_headers?.score < 50 },
        { label: 'IPv6 Web', pass: data.ipv6?.web_pass },
        { label: 'IPv6 Mail', pass: data.ipv6?.mail_pass },
        { label: 'Blacklist', pass: data.blacklist && !data.blacklist?.is_listed },
    ];

    checks.forEach(c => {
        if (c.pass === undefined && !c.warn) return;
        const div = document.createElement('div');
        div.className = 'score-item';

        let badgeClass, badgeText;
        if (c.pass) { badgeClass = 'badge-pass'; badgeText = 'Pass'; }
        else if (c.warn) { badgeClass = 'badge-warn'; badgeText = 'Partial'; }
        else { badgeClass = 'badge-fail'; badgeText = 'Fail'; }

        const labelDiv = document.createElement('div');
        labelDiv.className = 'label';
        labelDiv.textContent = c.label;

        const span = document.createElement('span');
        span.className = 'badge ' + badgeClass;
        span.textContent = badgeText;

        div.appendChild(labelDiv);
        div.appendChild(span);
        grid.appendChild(div);
    });

    $('scoreOverview').classList.toggle('hidden', grid.children.length === 0);
}

// ===== WHOIS =====
function renderWhois(data) {
    const el = $('whoisContent');
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'WHOIS lookup failed')}</p>`;
        return;
    }
    const d = data.data;
    let rows = '';
    const labels = {
        domain_name: 'Domain', registrar: 'Registrar', whois_server: 'WHOIS Server',
        creation_date: 'Created', expiration_date: 'Expires', updated_date: 'Updated',
        name_servers: 'Name Servers', status: 'Status', emails: 'Contact',
        dnssec: 'DNSSEC', org: 'Organization', country: 'Country',
    };
    for (const [key, label] of Object.entries(labels)) {
        if (d[key] !== undefined && d[key] !== null) {
            let val = d[key];
            if (Array.isArray(val)) {
                val = val.map(v => escapeHtml(v)).join('<br>');
            } else {
                val = escapeHtml(val);
            }
            rows += `<tr><th>${escapeHtml(label)}</th><td>${val}</td></tr>`;
        }
    }
    el.innerHTML = `<table class="data-table">${rows}</table>`;
}

// ===== DNS =====
function renderDns(data) {
    const el = $('dnsContent');
    if (!data || Object.keys(data).length === 0) {
        el.innerHTML = '<p class="status status-fail">No DNS records found</p>';
        return;
    }
    let html = '';
    const order = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA', 'PTR'];
    for (const rtype of order) {
        if (!data[rtype]) continue;
        data[rtype].forEach(val => {
            html += `<div class="dns-record"><span class="record-type">${escapeHtml(rtype)}</span><span class="dns-value">${escapeHtml(val)}</span></div>`;
        });
    }
    el.innerHTML = html;
}

// ===== DNSSEC =====
function renderDnssec(data) {
    const el = $('dnssecContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    const cls = data.signed ? 'status-pass' : 'status-fail';
    let html = `<p class="status ${cls}">${escapeHtml(data.status)}</p>`;
    html += `<table class="data-table">
        <tr><th>DNSKEY</th><td>${data.has_dnskey ? 'Found' : 'Not found'}</td></tr>
        <tr><th>DS Record</th><td>${data.has_ds ? 'Found' : 'Not found'}</td></tr>
    </table>`;
    el.innerHTML = html;
}

// ===== SPF =====
function renderSpf(data) {
    const el = $('spfContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No SPF record found</p>';
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-warn';
    const msg = data.strict ? 'Strict policy (-all)' : data.pass ? 'SPF configured' : 'Weak SPF policy';
    let html = `<p class="status ${cls}">${escapeHtml(msg)}</p>`;
    html += `<div class="record-box">${escapeHtml(data.record)}</div>`;
    el.innerHTML = html;
}

// ===== DMARC =====
function renderDmarc(data) {
    const el = $('dmarcContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No DMARC record found</p>';
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-warn';
    let html = `<p class="status ${cls}">Policy: ${escapeHtml(data.policy)}</p>`;
    html += `<div class="record-box">${escapeHtml(data.record)}</div>`;
    el.innerHTML = html;
}

// ===== DKIM =====
function renderDkim(data) {
    const el = $('dkimContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No DKIM records found (checked common selectors)</p>';
        return;
    }
    let html = `<p class="status status-pass">${data.selectors.length} selector(s) found</p>`;
    data.selectors.forEach(s => {
        html += `<p style="margin-top:0.5rem"><strong>${escapeHtml(s.selector)}</strong>._domainkey</p>`;
        html += `<div class="record-box">${escapeHtml(s.record)}</div>`;
    });
    el.innerHTML = html;
}

// ===== MTA-STS =====
function renderMtaSts(data) {
    const el = $('mtaStsContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No MTA-STS record found</p>';
        return;
    }
    let html = '<p class="status status-pass">MTA-STS configured</p>';
    html += `<div class="record-box">${escapeHtml(data.record)}</div>`;
    el.innerHTML = html;
}

// ===== TLS-RPT =====
function renderTlsrpt(data) {
    const el = $('tlsrptContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (!data.found) {
        el.innerHTML = '<p class="status status-fail">No TLS-RPT record found</p>';
        return;
    }
    let html = '<p class="status status-pass">TLS-RPT configured</p>';
    html += `<div class="record-box">${escapeHtml(data.record)}</div>`;
    el.innerHTML = html;
}

// ===== SSL Certificate =====
function renderSsl(data) {
    const el = $('sslContent');
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'SSL check failed')}</p>`;
        return;
    }
    const expCls = data.expired ? 'status-fail' : (data.days_until_expiry < 30 ? 'status-warn' : 'status-pass');
    const expText = data.expired ? 'EXPIRED' : `${data.days_until_expiry} days remaining`;

    let html = `<p class="status ${expCls}">${escapeHtml(expText)}</p>`;
    html += `<table class="data-table">
        <tr><th>Subject</th><td>${escapeHtml(data.subject?.commonName || data.subject?.organizationName || '-')}</td></tr>
        <tr><th>Issuer</th><td>${escapeHtml(data.issuer?.organizationName || data.issuer?.commonName || '-')}</td></tr>
        <tr><th>Valid From</th><td>${escapeHtml(data.not_before)}</td></tr>
        <tr><th>Valid Until</th><td>${escapeHtml(data.not_after)}</td></tr>
        <tr><th>Protocol</th><td>${escapeHtml(data.protocol || '-')}</td></tr>
        <tr><th>Cipher</th><td>${escapeHtml(data.cipher || '-')}</td></tr>
        <tr><th>Serial</th><td style="font-family:monospace;font-size:0.8rem">${escapeHtml(data.serial_number || '-')}</td></tr>
        <tr><th>SAN</th><td>${(data.san || []).map(escapeHtml).join('<br>') || '-'}</td></tr>
    </table>`;
    el.innerHTML = html;
}

// ===== TLS Deep Scan =====
function renderTlsDeep(data) {
    const gradeCard = $('tlsGradeCard');
    const protoEl = $('tlsProtocolsContent');
    const cipherSumEl = $('tlsCipherSummary');
    const cipherEl = $('tlsCiphersContent');
    const featEl = $('tlsFeaturesContent');

    if (!data || !data.success) {
        gradeCard.style.display = 'none';
        protoEl.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'TLS scan not available')}</p>`;
        cipherSumEl.innerHTML = '';
        cipherEl.innerHTML = '';
        featEl.innerHTML = '';
        return;
    }

    gradeCard.style.display = '';
    const gradeCircle = $('tlsGradeCircle');
    const grade = data.grade || '?';
    gradeCircle.textContent = grade;
    gradeCircle.className = 'tls-grade-circle grade-' + grade.replace('+', 'plus').toLowerCase();

    const warningsEl = $('tlsWarnings');
    if (data.warnings && data.warnings.length > 0) {
        warningsEl.innerHTML = data.warnings.map(w => `<div class="tls-warning"><span class="status status-warn"></span> ${escapeHtml(w)}</div>`).join('');
    } else {
        warningsEl.innerHTML = '<div class="tls-warning"><span class="status status-pass"></span> No issues found</div>';
    }

    let protoHtml = '<div class="proto-grid">';
    const protoOrder = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];
    const deprecated = ['TLS 1.0', 'TLS 1.1'];
    for (const pname of protoOrder) {
        const p = (data.protocols || []).find(x => x.name === pname);
        if (!p) continue;
        const supported = p.supported;
        const isOld = deprecated.includes(pname);
        let cls, statusText;
        if (supported && isOld) { cls = 'proto-warn'; statusText = 'Enabled (deprecated)'; }
        else if (supported) { cls = 'proto-pass'; statusText = 'Enabled'; }
        else if (!supported && isOld) { cls = 'proto-good-disabled'; statusText = 'Disabled'; }
        else { cls = 'proto-fail'; statusText = 'Not supported'; }

        protoHtml += `<div class="proto-item ${cls}">
            <div class="proto-name">${escapeHtml(pname)}</div>
            <div class="proto-status">${escapeHtml(statusText)}</div>
            ${supported && p.cipher ? `<div class="proto-cipher">${escapeHtml(p.cipher)} (${escapeHtml(String(p.bits))} bit)</div>` : ''}
        </div>`;
    }
    protoHtml += '</div>';
    protoEl.innerHTML = protoHtml;

    const cs = data.cipher_summary || {};
    cipherSumEl.innerHTML = `<div class="cipher-summary">
        <span class="cipher-stat"><strong>${cs.total || 0}</strong> total</span>
        <span class="cipher-stat cipher-strong"><strong>${cs.strong || 0}</strong> strong</span>
        <span class="cipher-stat cipher-acceptable"><strong>${cs.acceptable || 0}</strong> acceptable</span>
        <span class="cipher-stat cipher-weak"><strong>${cs.weak || 0}</strong> weak</span>
        <span class="cipher-stat cipher-insecure"><strong>${cs.insecure || 0}</strong> insecure</span>
        <span class="cipher-stat cipher-fs"><strong>${cs.forward_secrecy || 0}</strong> PFS</span>
    </div>`;

    if (data.ciphers && data.ciphers.length > 0) {
        let cHtml = '<table class="data-table cipher-table"><thead><tr><th>Cipher Suite</th><th>Protocol</th><th>Bits</th><th>Strength</th><th>PFS</th></tr></thead><tbody>';
        for (const c of data.ciphers) {
            const strengthCls = c.strength === 'strong' ? 'badge-pass' : c.strength === 'acceptable' ? 'badge-info' : c.strength === 'weak' ? 'badge-warn' : 'badge-fail';
            cHtml += `<tr>
                <td style="font-family:monospace;font-size:0.8rem">${escapeHtml(c.name)}</td>
                <td>${escapeHtml(c.protocol)}</td>
                <td>${escapeHtml(String(c.bits))}</td>
                <td><span class="badge ${strengthCls}">${escapeHtml(c.strength)}</span></td>
                <td>${c.forward_secrecy ? '<span class="status status-pass"></span>' : '<span class="status status-fail"></span>'}</td>
            </tr>`;
        }
        cHtml += '</tbody></table>';
        cipherEl.innerHTML = cHtml;
    } else {
        cipherEl.innerHTML = '<p class="status status-fail">No cipher suites detected</p>';
    }

    let fHtml = '<table class="data-table">';
    fHtml += `<tr><th>OCSP Stapling</th><td><span class="status ${data.ocsp_stapling ? 'status-pass' : 'status-fail'}">${data.ocsp_stapling ? 'Enabled' : 'Not enabled'}</span></td></tr>`;
    fHtml += `<tr><th>TLS Compression</th><td><span class="status ${!data.tls_compression ? 'status-pass' : 'status-fail'}">${data.tls_compression ? 'Enabled (CRIME vulnerable!)' : 'Disabled (safe)'}</span></td></tr>`;
    if (data.hsts) {
        fHtml += `<tr><th>HSTS</th><td><span class="status ${data.hsts.enabled ? 'status-pass' : 'status-fail'}">${data.hsts.enabled ? 'Enabled' : 'Not set'}</span></td></tr>`;
        if (data.hsts.enabled) {
            fHtml += `<tr><th>HSTS Value</th><td class="record-box" style="margin:0">${escapeHtml(data.hsts.value)}</td></tr>`;
            fHtml += `<tr><th>HSTS Preload</th><td><span class="status ${data.hsts.preload ? 'status-pass' : 'status-warn'}">${data.hsts.preload ? 'Yes' : 'No'}</span></td></tr>`;
        }
    }
    if (data.certificate?.success) {
        const cert = data.certificate;
        fHtml += `<tr><th>Certificate</th><td><span class="status ${cert.expired ? 'status-fail' : 'status-pass'}">${cert.expired ? 'EXPIRED' : escapeHtml(String(cert.days_until_expiry)) + ' days remaining'}</span></td></tr>`;
        fHtml += `<tr><th>Wildcard</th><td>${cert.wildcard ? 'Yes' : 'No'}</td></tr>`;
        fHtml += `<tr><th>Self-signed</th><td><span class="status ${cert.self_signed ? 'status-fail' : 'status-pass'}">${cert.self_signed ? 'Yes' : 'No'}</span></td></tr>`;
        fHtml += `<tr><th>SAN Count</th><td>${escapeHtml(String(cert.san_count))}</td></tr>`;
    }
    fHtml += '</table>';
    featEl.innerHTML = fHtml;
}

// ===== HTTPS Redirect =====
function renderHttpsRedirect(data) {
    const el = $('httpsContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (data.error) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.error)}</p>`;
        return;
    }
    const cls = data.pass ? 'status-pass' : 'status-fail';
    let html = `<p class="status ${cls}">${data.redirects ? 'HTTP redirects to HTTPS' : 'No HTTPS redirect'}</p>`;
    if (data.redirects) {
        html += `<table class="data-table">
            <tr><th>Status</th><td>${escapeHtml(String(data.status_code))} (${data.permanent ? 'Permanent' : 'Temporary'})</td></tr>
            <tr><th>Location</th><td>${escapeHtml(data.location)}</td></tr>
        </table>`;
    }
    el.innerHTML = html;
}

// ===== HTTP Headers =====
function renderHeaders(data) {
    const el = $('headersContent');
    if (!data || !data.success) {
        el.innerHTML = `<p class="status status-fail">${escapeHtml(data?.error || 'Headers check failed')}</p>`;
        return;
    }

    const score = data.score;
    const barColor = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--orange)' : 'var(--red)';

    let html = `<div class="header-bar">
        <span style="font-weight:600">${escapeHtml(String(score))}%</span>
        <div class="progress-bar"><div class="progress-fill" style="width:${score}%;background:${barColor}"></div></div>
    </div>`;

    if (data.server) {
        html += `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem">Server: ${escapeHtml(data.server)}</p>`;
    }

    html += '<table class="data-table">';
    for (const [hdr, val] of Object.entries(data.headers_found || {})) {
        html += `<tr><th><span class="status status-pass"></span> ${escapeHtml(hdr)}</th><td style="font-size:0.8rem">${escapeHtml(val)}</td></tr>`;
    }
    for (const hdr of (data.headers_missing || [])) {
        html += `<tr><th><span class="status status-fail"></span> ${escapeHtml(hdr)}</th><td style="color:var(--text-muted)">Not set</td></tr>`;
    }
    html += '</table>';
    el.innerHTML = html;
}

// ===== IPv6 =====
function renderIpv6(data) {
    const el = $('ipv6Content');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }

    let html = '<table class="data-table">';
    const aaaaText = (data.aaaa_records || []).map(escapeHtml).join(', ') || 'None';
    html += `<tr><th>Web (AAAA)</th><td><span class="status ${data.web_pass ? 'status-pass' : 'status-fail'}">${aaaaText}</span></td></tr>`;

    if (data.mx_ipv6 && Object.keys(data.mx_ipv6).length > 0) {
        const mxText = Object.entries(data.mx_ipv6)
            .map(([h, ips]) => `${escapeHtml(h)}: ${ips.map(escapeHtml).join(', ')}`)
            .join('<br>');
        html += `<tr><th>Mail IPv6</th><td><span class="status status-pass">${mxText}</span></td></tr>`;
    } else {
        html += `<tr><th>Mail IPv6</th><td><span class="status status-fail">No mail server IPv6</span></td></tr>`;
    }

    if (data.ns_ipv6 && Object.keys(data.ns_ipv6).length > 0) {
        const nsText = Object.entries(data.ns_ipv6)
            .map(([h, ips]) => `${escapeHtml(h)}: ${ips.map(escapeHtml).join(', ')}`)
            .join('<br>');
        html += `<tr><th>NS IPv6</th><td><span class="status status-pass">${nsText}</span></td></tr>`;
    } else {
        html += `<tr><th>NS IPv6</th><td><span class="status status-fail">No nameserver IPv6</span></td></tr>`;
    }
    html += '</table>';
    el.innerHTML = html;
}

// ===== Blacklist =====
function renderBlacklist(data) {
    const el = $('blacklistContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (data.error) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.error)}</p>`;
        return;
    }

    let html = '';
    if (data.ip) html += `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem">IP: ${escapeHtml(data.ip)}</p>`;

    const cls = data.is_listed ? 'status-fail' : 'status-pass';
    const msg = data.is_listed ? `Listed on ${data.listed.length} blacklist(s)!` : 'Clean - not listed on any blacklist';
    html += `<p class="status ${cls}" style="margin-bottom:0.75rem">${escapeHtml(msg)}</p>`;

    html += '<div class="bl-list">';
    for (const bl of (data.listed || [])) {
        html += `<div class="bl-item"><span class="status status-fail"></span> ${escapeHtml(bl)}</div>`;
    }
    for (const bl of (data.clean || [])) {
        html += `<div class="bl-item"><span class="status status-pass"></span> ${escapeHtml(bl)}</div>`;
    }
    html += '</div>';
    el.innerHTML = html;
}

// ===== Recommendations =====
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function generateRecommendations(data) {
    const recs = [];
    const add = (severity, category, title, problem, fix, reference) => {
        const r = { severity, category, title, problem, fix };
        if (reference) r.reference = reference;
        recs.push(r);
    };

    if (data.dnssec && !data.dnssec.signed) {
        add('medium', 'DNS', 'DNSSEC not configured',
            'DNSSEC is not fully set up. Responses cannot be cryptographically verified.',
            'Enable DNSSEC at your DNS provider. Publish a DS record at the registrar.');
    }

    if (data.spf && !data.spf.found) {
        add('high', 'Email', 'SPF record missing',
            'Anyone can spoof mail from this domain.',
            'Publish a TXT record: v=spf1 include:_spf.yourprovider.com -all');
    } else if (data.spf && data.spf.found && !data.spf.strict) {
        add('medium', 'Email', 'SPF is not strict',
            'SPF ends with ~all or ?all, so spoofed mail may still be accepted.',
            'After verifying sending sources, tighten to -all.');
    }

    if (data.dmarc && !data.dmarc.found) {
        add('high', 'Email', 'DMARC missing',
            'No DMARC policy is published.',
            'Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain; then move to quarantine/reject.');
    } else if (data.dmarc && data.dmarc.policy === 'none') {
        add('medium', 'Email', 'DMARC policy is p=none',
            'DMARC is only in monitor mode; spoofed mail is not blocked.',
            'After reviewing aggregate reports, change to p=quarantine or p=reject.');
    }

    if (data.dkim && !data.dkim.found) {
        add('medium', 'Email', 'No DKIM selectors detected',
            'Mail from this domain may not be DKIM-signed.',
            'Enable DKIM at your mail provider and publish the public key as <selector>._domainkey.');
    }

    if (data.mta_sts && !data.mta_sts.found) {
        add('low', 'Email', 'MTA-STS not configured',
            'Inbound mail may be delivered over insecure TLS.',
            'Publish _mta-sts TXT and host the policy at https://mta-sts.yourdomain/.well-known/mta-sts.txt.');
    }

    if (data.tlsrpt && !data.tlsrpt.found) {
        add('low', 'Email', 'TLS-RPT not configured',
            'No reporting of TLS failures on inbound mail.',
            'Publish _smtp._tls TXT: v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.');
    }

    if (data.tls_deep && data.tls_deep.success) {
        const tls = data.tls_deep;
        if (['D','F','T'].includes(tls.grade)) {
            add('critical', 'TLS', 'Poor TLS grade (' + tls.grade + ')',
                'Connections are exposed to known attacks.',
                'Disable obsolete protocols, remove weak ciphers, install a trusted certificate, enable HSTS.',
                'https://ssl-config.mozilla.org/');
        }
        const protos = {};
        (tls.protocols || []).forEach(p => { protos[p.name] = p.supported; });
        if (protos['TLS 1.0']) add('high', 'TLS', 'TLS 1.0 enabled', 'TLS 1.0 is deprecated and vulnerable to BEAST.', 'Disable TLS 1.0 in the web server config.');
        if (protos['TLS 1.1']) add('high', 'TLS', 'TLS 1.1 enabled', 'TLS 1.1 is deprecated (RFC 8996).', 'Require TLS 1.2 as a minimum.');
        if (!protos['TLS 1.3']) add('low', 'TLS', 'TLS 1.3 not available', 'Missing performance and security benefits of TLS 1.3.', 'Upgrade OpenSSL and enable TLS 1.3.');

        const cs = tls.cipher_summary || {};
        if ((cs.weak||0) + (cs.insecure||0) > 0) {
            add('high', 'TLS', 'Weak ciphers accepted',
                (cs.weak||0) + ' weak and ' + (cs.insecure||0) + ' insecure cipher suites are accepted.',
                'Restrict to modern AEAD suites (ECDHE-*-GCM, CHACHA20).',
                'https://ssl-config.mozilla.org/');
        }
        if (cs.total > 0 && cs.forward_secrecy < cs.total) {
            add('medium', 'TLS', 'Forward secrecy not universal',
                'Some cipher suites lack forward secrecy.',
                'Only allow ECDHE/DHE cipher suites.');
        }
        if (tls.tls_compression) {
            add('high', 'TLS', 'TLS compression enabled (CRIME)',
                'Server vulnerable to the CRIME attack.',
                'Disable TLS compression.');
        }
        if (!tls.ocsp_stapling) {
            add('low', 'TLS', 'OCSP stapling disabled',
                'Clients may query the CA directly (slower, privacy leak).',
                'Enable OCSP stapling in your web server.');
        }
        const hsts = tls.hsts || {};
        if (!hsts.enabled) {
            add('medium', 'TLS', 'HSTS missing',
                'First-visit downgrade attacks are possible.',
                'Return Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
                'https://hstspreload.org/');
        }
        const cert = tls.certificate || {};
        if (cert.expired) {
            add('critical', 'Certificate', 'Certificate expired',
                'Browsers block access.',
                'Renew immediately and automate with ACME.');
        } else if (cert.days_until_expiry !== undefined && cert.days_until_expiry < 30) {
            add('high', 'Certificate', 'Certificate expires soon',
                'Certificate expires in ' + cert.days_until_expiry + ' days.',
                'Renew now and automate renewals.');
        }
        if (cert.self_signed) {
            add('high', 'Certificate', 'Self-signed certificate',
                'Browsers show warnings.',
                'Use a trusted CA (e.g. Let\'s Encrypt).');
        }
    }

    if (data.https_redirect && !data.https_redirect.pass) {
        add('high', 'Web', 'HTTP does not redirect to HTTPS',
            'Plain HTTP exposes users to MITM.',
            'Force a 301 redirect from HTTP to HTTPS.');
    }

    if (data.http_headers && data.http_headers.success) {
        const missing = data.http_headers.headers_missing || [];
        if (missing.length > 0) {
            const sev = missing.length >= 4 ? 'medium' : 'low';
            add(sev, 'Web', missing.length + ' security header(s) missing',
                'Recommended HTTP security headers are not set.',
                'Add: ' + missing.join(', '),
                'https://owasp.org/www-project-secure-headers/');
        }
    }

    if (data.ipv6 && !data.ipv6.has_ipv6) {
        add('low', 'Network', 'No IPv6 (AAAA) record',
            'IPv6-only clients cannot reach the domain.',
            'Publish AAAA records for your web server.');
    }

    if (data.blacklist && data.blacklist.is_listed) {
        add('critical', 'Network', 'IP listed on DNSBL',
            'Listed on: ' + (data.blacklist.listed || []).join(', '),
            'Investigate the cause and request delisting after remediation.');
    }

    const risky = {21:'FTP unencrypted', 23:'Telnet unencrypted', 3306:'MySQL public', 3389:'RDP exposed', 5432:'PostgreSQL public'};
    if (data.ports && data.ports.open) {
        data.ports.open.forEach(p => {
            if (risky[p.port]) {
                add('high', 'Network', 'Risky port ' + p.port + '/' + p.service + ' open',
                    risky[p.port],
                    'Close the port on the public interface or restrict via firewall/VPN.');
            }
        });
    }

    recs.sort((a,b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
    return recs;
}

function renderRecommendations(data) {
    const el = $('recommendationsContent');
    const recs = generateRecommendations(data);
    const badge = $('recBadge');

    const counts = {critical:0,high:0,medium:0,low:0,info:0};
    recs.forEach(r => { counts[r.severity]++; });

    const total = recs.length;
    if (total === 0) {
        badge.textContent = '0';
        badge.className = 'tab-badge ok';
    } else {
        badge.textContent = String(total);
        badge.className = 'tab-badge';
    }

    if (recs.length === 0) {
        el.innerHTML = '<div class="rec-empty">No issues detected. Keep monitoring regularly.</div>';
        return;
    }

    let summary = '<div class="rec-summary">';
    SEVERITIES.forEach(s => {
        if (counts[s] > 0) {
            summary += `<span class="chip sev-${s}"><span class="chip-count">${counts[s]}</span> ${escapeHtml(s)}</span>`;
        }
    });
    summary += '</div>';

    let html = summary;
    recs.forEach(r => {
        html += `<article class="rec sev-${escapeHtml(r.severity)}">
            <div class="rec-head">
                <span class="rec-badge sev-${escapeHtml(r.severity)}">${escapeHtml(r.severity.toUpperCase())}</span>
                <span class="rec-category">${escapeHtml(r.category)}</span>
                <h4>${escapeHtml(r.title)}</h4>
            </div>
            <div class="rec-body">
                <p><strong>Problem:</strong> ${escapeHtml(r.problem)}</p>
                <p><strong>Fix:</strong> ${escapeHtml(r.fix)}</p>
                ${r.reference ? `<p><strong>Reference:</strong> <a href="${escapeHtml(r.reference)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.reference)}</a></p>` : ''}
            </div>
        </article>`;
    });

    el.innerHTML = html;
}

// ===== Report =====
function openReport() {
    if (!currentScanId) {
        showError('No saved scan yet. Run a scan first.');
        return;
    }
    window.open('/report/' + currentScanId, '_blank', 'noopener');
}

// ===== History Drawer =====
async function openHistory() {
    $('historyDrawer').classList.remove('hidden');
    $('drawerOverlay').classList.remove('hidden');
    await loadHistory();
}

function closeHistory() {
    $('historyDrawer').classList.add('hidden');
    $('drawerOverlay').classList.add('hidden');
}

async function loadHistory() {
    const list = $('historyList');
    const statsEl = $('historyStats');
    list.innerHTML = '<p class="history-empty">Loading…</p>';
    try {
        const resp = await fetch('/api/history?limit=100');
        const data = await resp.json();
        const stats = data.stats || {};
        statsEl.innerHTML = `<span><strong>${escapeHtml(String(stats.total_scans || 0))}</strong>scans</span>
            <span><strong>${escapeHtml(String(stats.unique_domains || 0))}</strong>domains</span>`;
        renderHistoryList(data.scans || []);
    } catch (err) {
        list.innerHTML = '<p class="history-empty">Failed to load history</p>';
    }
}

function renderHistoryList(scans) {
    const list = $('historyList');
    if (scans.length === 0) {
        list.innerHTML = '<p class="history-empty">No scans saved yet</p>';
        return;
    }
    list.innerHTML = '';
    scans.forEach(s => {
        const grade = s.grade || 'N/A';
        const gradeClass = 'g-' + grade.toLowerCase().replace('+', 'plus').replace('/', '');
        const when = s.created_at ? new Date(s.created_at).toLocaleString() : '';
        const item = document.createElement('div');
        item.className = 'history-item';

        const gradeDiv = document.createElement('div');
        gradeDiv.className = 'history-grade ' + (grade === 'N/A' ? 'g-na' : gradeClass);
        gradeDiv.textContent = grade;
        item.appendChild(gradeDiv);

        const main = document.createElement('div');
        main.className = 'history-main';
        const domainDiv = document.createElement('div');
        domainDiv.className = 'history-domain';
        domainDiv.textContent = s.domain;
        const metaDiv = document.createElement('div');
        metaDiv.className = 'history-meta';
        metaDiv.textContent = when + ' \u00b7 ' + (s.issues_count || 0) + ' finding(s)';
        main.appendChild(domainDiv);
        main.appendChild(metaDiv);
        item.appendChild(main);

        const actions = document.createElement('div');
        actions.className = 'history-item-actions';

        const loadBtn = document.createElement('button');
        loadBtn.textContent = 'Load';
        loadBtn.addEventListener('click', e => { e.stopPropagation(); loadScan(s.id); });
        actions.appendChild(loadBtn);

        const reportBtn = document.createElement('button');
        reportBtn.textContent = 'Report';
        reportBtn.addEventListener('click', e => { e.stopPropagation(); window.open('/report/' + s.id, '_blank', 'noopener'); });
        actions.appendChild(reportBtn);

        const delBtn = document.createElement('button');
        delBtn.className = 'danger';
        delBtn.textContent = '\u2715';
        delBtn.title = 'Delete';
        delBtn.addEventListener('click', e => { e.stopPropagation(); deleteScan(s.id); });
        actions.appendChild(delBtn);

        item.appendChild(actions);
        item.addEventListener('click', () => loadScan(s.id));
        list.appendChild(item);
    });
}

async function loadScan(scanId) {
    try {
        const resp = await fetch('/api/history/' + scanId);
        if (!resp.ok) { showError('Failed to load scan'); return; }
        const record = await resp.json();
        scanData = record.data;
        currentScanId = record.id;
        $('domainInput').value = record.domain;
        renderResults(record.data);
        closeHistory();
    } catch (err) {
        showError('Network error while loading scan');
    }
}

async function deleteScan(scanId) {
    if (!confirm('Delete this scan from history?')) return;
    try {
        const resp = await fetch('/api/history/' + scanId, { method: 'DELETE' });
        if (resp.ok) await loadHistory();
    } catch (err) {
        showError('Failed to delete scan');
    }
}

async function clearHistory() {
    if (!confirm('Delete ALL saved scans? This cannot be undone.')) return;
    try {
        const resp = await fetch('/api/history', { method: 'DELETE' });
        if (resp.ok) await loadHistory();
    } catch (err) {
        showError('Failed to clear history');
    }
}

// ===== Ports =====
function renderPorts(data) {
    const el = $('portsContent');
    if (!data) { el.innerHTML = '<p>-</p>'; return; }
    if (data.error) {
        el.innerHTML = `<p class="status status-warn">${escapeHtml(data.error)}</p>`;
        return;
    }

    let html = '';
    if (data.ip) html += `<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem">IP: ${escapeHtml(data.ip)}</p>`;
    html += `<p style="margin-bottom:0.75rem">${escapeHtml(String(data.open?.length || 0))} open port(s) found</p>`;

    html += '<div class="port-grid">';
    for (const p of (data.open || [])) {
        html += `<div class="port-item port-open"><span class="port-dot"></span> ${escapeHtml(String(p.port))} <span style="color:var(--text-muted)">${escapeHtml(p.service)}</span></div>`;
    }
    for (const p of (data.closed || [])) {
        html += `<div class="port-item port-closed"><span class="port-dot"></span> ${escapeHtml(String(p.port))} <span style="color:var(--text-muted)">${escapeHtml(p.service)}</span></div>`;
    }
    html += '</div>';
    el.innerHTML = html;
}
