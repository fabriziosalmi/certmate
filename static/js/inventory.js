/**
 * Certificate inventory dashboard (#471).
 * Lists issued + discovered certificates with an expiry forecast, client-side
 * filtering, an admin config panel and a "scan now" trigger.
 *
 * static/js/inventory.js
 */
(function () {
    'use strict';

    var API_HEADERS = { 'Content-Type': 'application/json' };
    var escapeHtml = (window.CertMate && CertMate.escapeHtml) || function (s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    };

    var ROLE_LEVELS = { viewer: 0, operator: 1, admin: 2 };
    var records = [];
    var currentRole = 'viewer';

    function el(id) { return document.getElementById(id); }

    function roleAtLeast(name) {
        return (ROLE_LEVELS[currentRole] || 0) >= (ROLE_LEVELS[name] || 0);
    }

    function statusBadge(status, days) {
        var map = {
            expired: ['bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300', 'Expired'],
            critical: ['bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300', days + 'd'],
            warning: ['bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300', days + 'd'],
            ok: ['bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300', days + 'd'],
            unknown: ['bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300', '—']
        };
        var m = map[status] || map.unknown;
        return '<span class="inline-block px-2 py-0.5 rounded-full text-xs font-medium ' + m[0] + '">' + escapeHtml(m[1]) + '</span>';
    }

    function sourceBadge(source, managed) {
        var cls = managed
            ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300'
            : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300';
        return '<span class="inline-block px-2 py-0.5 rounded text-xs ' + cls + '">' + escapeHtml(source || '?') + '</span>';
    }

    function keyLabel(key) {
        if (!key || !key.type) { return '—'; }
        if (key.curve) { return escapeHtml(key.type + ' ' + key.curve); }
        if (key.size) { return escapeHtml(key.type + ' ' + key.size); }
        return escapeHtml(key.type);
    }

    function subjectCell(r) {
        var sans = (r.san_dns || []).slice(0, 3).join(', ');
        var extra = (r.san_dns || []).length > 3 ? ' +' + ((r.san_dns.length) - 3) : '';
        var cn = r.subject_cn || '(no CN)';
        var s = '<div class="font-medium text-foreground">' + escapeHtml(cn) + '</div>';
        if (sans) { s += '<div class="text-xs text-muted truncate max-w-xs">' + escapeHtml(sans) + escapeHtml(extra) + '</div>'; }
        return s;
    }

    function endpointsCell(r) {
        var eps = r.endpoints || [];
        if (!eps.length) { return '<span class="text-xs text-muted">—</span>'; }
        var first = eps[0].host + ':' + eps[0].port;
        var more = eps.length > 1 ? ' <span class="text-muted">+' + (eps.length - 1) + '</span>' : '';
        return '<span class="text-xs font-mono">' + escapeHtml(first) + '</span>' + more;
    }

    function actionsCell(r) {
        // Only unmanaged (discovered) certificates can be adopted, and only by
        // an operator+. Managed certs and viewers get no button.
        if (r.managed || !roleAtLeast('operator')) { return ''; }
        return '<button type="button" onclick="InventoryPage.adopt(\'' + escapeHtml(r.fingerprint) + '\')" '
            + 'class="px-2 py-1 text-xs bg-surface-2 text-primary rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition" '
            + 'title="Take over issuance/renewal of this certificate">'
            + '<i class="fas fa-hand-holding-medical mr-1"></i>Adopt</button>';
    }

    function passesFilters(r) {
        var group = el('invGroup').value;
        var source = el('invSource').value;
        var expiry = el('invExpiry').value;
        var q = el('invSearch').value.trim().toLowerCase();
        if (group && r.group !== group) { return false; }
        if (source && r.source !== source) { return false; }
        if (expiry && r.expiry_status !== expiry) { return false; }
        if (q) {
            var hay = [r.subject_cn, r.issuer_cn, r.issuer, (r.san_dns || []).join(' ')]
                .join(' ').toLowerCase();
            if (hay.indexOf(q) === -1) { return false; }
        }
        return true;
    }

    function render() {
        var body = el('inventoryBody');
        var rows = records.filter(passesFilters);
        el('invCount').textContent = rows.length + ' of ' + records.length;
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-muted">'
                + (records.length ? 'No certificates match the filters.' : 'Inventory is empty. Configure discovery or CT-log monitoring, then Scan now.')
                + '</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (r) {
            return '<tr class="hover:bg-hover">'
                + '<td class="px-4 py-2">' + subjectCell(r) + '</td>'
                + '<td class="px-4 py-2 text-xs text-muted">' + escapeHtml(r.issuer_cn || r.issuer || '—') + '</td>'
                + '<td class="px-4 py-2">' + statusBadge(r.expiry_status, r.days_until_expiry) + '</td>'
                + '<td class="px-4 py-2 text-xs">' + keyLabel(r.key) + '</td>'
                + '<td class="px-4 py-2">' + sourceBadge(r.source, r.managed) + '</td>'
                + '<td class="px-4 py-2">' + endpointsCell(r) + '</td>'
                + '<td class="px-4 py-2 text-right">' + actionsCell(r) + '</td>'
                + '</tr>';
        }).join('');
    }

    function adopt(fingerprint) {
        // Fetch the adoption plan (pre-filled from the observed cert), confirm
        // the values with the operator, then issue.
        fetch('/api/inventory/' + encodeURIComponent(fingerprint) + '/adopt',
            { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (plan) {
                if (!plan.available) {
                    window.alert('Cannot adopt this certificate:\n\n' + (plan.reason || 'Not available.'));
                    return;
                }
                var sans = (plan.san_domains || []).join(', ') || '(none)';
                var key = plan.key_type
                    ? (plan.key_type + (plan.elliptic_curve ? ' ' + plan.elliptic_curve : (plan.key_size ? ' ' + plan.key_size : '')))
                    : 'default';
                var summary = 'Adopt and manage this certificate?\n\n'
                    + 'Domain: ' + plan.domain + '\n'
                    + 'SANs: ' + sans + '\n'
                    + 'Key: ' + key + '\n'
                    + 'DNS provider: ' + (plan.dns_provider || 'default') + '\n\n'
                    + 'CertMate will issue the certificate and take over its renewal.';
                if (!window.confirm(summary)) { return; }
                return fetch('/api/inventory/' + encodeURIComponent(fingerprint) + '/adopt',
                    { method: 'POST', headers: API_HEADERS, credentials: 'same-origin' })
                    .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
                    .then(function (res) {
                        if (res.ok) { load(); }
                        else { window.alert('Adoption failed: ' + (res.j.error || 'unknown error')); }
                    });
            })
            .catch(function (err) { window.alert('Could not load adoption plan (' + err + ').'); });
    }

    function setSummary(s) {
        s = s || {};
        var ex = s.expiry || {};
        el('sumTotal').textContent = s.total || 0;
        el('sumIssued').textContent = s.issued || 0;
        el('sumDiscovered').textContent = s.discovered || 0;
        el('sumExpired').textContent = ex.expired || 0;
        el('sum7').textContent = ex['7'] || 0;
        el('sum30').textContent = ex['30'] || 0;
        el('sum90').textContent = ex['90'] || 0;
    }

    function load() {
        fetch('/api/inventory', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (data) {
                records = data.certificates || [];
                setSummary(data.summary);
                render();
            })
            .catch(function (err) {
                el('inventoryBody').innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-red-500">Failed to load inventory (' + escapeHtml(err) + ').</td></tr>';
            });
    }

    function loadConfig() {
        fetch('/api/inventory/config', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (cfg) {
                var d = cfg.discovery || {};
                var c = cfg.ct_monitoring || {};
                el('cfgDiscEnabled').checked = !!d.enabled;
                el('cfgIncludeManaged').checked = d.include_managed !== false;
                el('cfgAllowPrivate').checked = !!d.allow_private;
                el('cfgEndpoints').value = (d.endpoints || []).join('\n');
                el('cfgCtEnabled').checked = !!c.enabled;
                el('cfgCtIncludeManaged').checked = c.include_managed !== false;
                el('cfgCtDomains').value = (c.domains || []).join('\n');
            })
            .catch(function () { /* viewer without config access — panel stays hidden */ });
    }

    function lines(id) {
        return el(id).value.split('\n').map(function (s) { return s.trim(); })
            .filter(function (s) { return s.length; });
    }

    function saveConfig() {
        var msg = el('cfgMsg');
        msg.textContent = 'Saving…';
        var body = {
            discovery: {
                enabled: el('cfgDiscEnabled').checked,
                include_managed: el('cfgIncludeManaged').checked,
                allow_private: el('cfgAllowPrivate').checked,
                endpoints: lines('cfgEndpoints')
            },
            ct_monitoring: {
                enabled: el('cfgCtEnabled').checked,
                include_managed: el('cfgCtIncludeManaged').checked,
                domains: lines('cfgCtDomains')
            }
        };
        fetch('/api/inventory/config', {
            method: 'POST', headers: API_HEADERS, credentials: 'same-origin',
            body: JSON.stringify(body)
        })
            .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
            .then(function (res) {
                msg.textContent = res.ok ? 'Saved.' : ('Error: ' + (res.j.error || 'failed'));
                msg.className = 'text-xs mr-auto ' + (res.ok ? 'text-green-600' : 'text-red-500');
            })
            .catch(function () { msg.textContent = 'Save failed.'; msg.className = 'text-xs mr-auto text-red-500'; });
    }

    function runScan() {
        var btn = el('scanNowBtn');
        var original = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Scanning…';
        fetch('/api/inventory/scan', { method: 'POST', headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function () { load(); })
            .catch(function () { /* keep current view */ })
            .then(function () { btn.disabled = false; btn.innerHTML = original; });
    }

    function gateAdminControls() {
        fetch('/api/auth/me', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (me) {
                currentRole = (me && (me.role || (me.user && me.user.role))) || 'viewer';
                if (roleAtLeast('admin')) {
                    el('configPanel').classList.remove('hidden');
                    el('scanNowBtn').classList.remove('hidden');
                    loadConfig();
                }
                // Re-render so operator+ get the Adopt buttons now the role is known.
                if (records.length) { render(); }
            })
            .catch(function () { /* stay read-only */ });
    }

    window.InventoryPage = {
        load: load, render: render, saveConfig: saveConfig,
        runScan: runScan, adopt: adopt
    };

    document.addEventListener('DOMContentLoaded', function () {
        load();
        gateAdminControls();
    });
}());
