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

    // Only a verified answer is shown as good or revoked; everything else is
    // grey with the reason on hover, so "could not check" never reads as fine.
    function revocationBadge(rev) {
        if (!rev || !rev.status) { return ''; }
        var map = {
            revoked: ['bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300', 'Revoked',
                'Revoked' + (rev.revoked_at ? ' on ' + rev.revoked_at : '') + (rev.reason ? ' (' + rev.reason + ')' : '')
                + (rev.method ? ' — ' + rev.method.toUpperCase() : '')],
            good: ['bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300', 'Not revoked',
                'Not revoked — verified ' + (rev.method || '').toUpperCase() + ' answer, ' + (rev.checked_at || '')],
            unknown: ['bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300', 'Revocation unknown',
                rev.error || 'The responder does not know this certificate'],
            // "not checked" was wrong: `unavailable` is what the checker
            // returns when it DID ask and got nothing it could trust — an
            // unreachable responder, a signature that did not verify, a
            // stale response. Saying it was not checked hides a failure
            // behind a shrug. The reason is in the tooltip either way.
            unavailable: ['bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300', 'Revocation unverified',
                rev.error || 'No verified answer could be obtained'],
            // revocation.py returns five statuses. This map had four, so a
            // self-signed certificate fell through `map[rev.status]` and the
            // cell rendered empty — indistinguishable from "never checked".
            not_applicable: ['bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300', 'Self-signed',
                'Self-signed, so there is no issuer that could revoke it']
        };
        var m = map[rev.status];
        if (!m) { return ''; }
        return '<span class="inline-block mt-1 px-2 py-0.5 rounded-full text-xs whitespace-nowrap ' + m[0] + '" title="'
            + escapeHtml(m[2]) + '">' + escapeHtml(m[1]) + '</span>';
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
        // Viewers get no buttons at all.
        if (!roleAtLeast('operator')) { return ''; }
        // Pass the fingerprint via a data attribute (read in adoptFromEl /
        // forgetFromEl) rather than interpolating it into an inline onclick
        // JS-string.
        var fp = escapeHtml(r.fingerprint);
        var html = '';
        // Only unmanaged (discovered) certificates can be adopted.
        if (!r.managed) {
            html += '<button type="button" data-fp="' + fp + '" '
                + 'onclick="InventoryPage.adoptFromEl(this)" '
                + 'class="px-2 py-1 text-xs bg-surface-2 text-primary rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition" '
                + 'title="Take over issuance/renewal of this certificate">'
                + '<i class="fas fa-hand-holding-medical mr-1"></i>Adopt</button>';
        }
        // Forget removes the inventory row (#634). Offered for managed records
        // too: the certificate itself is untouched, so the only consequence is
        // that CertMate stops listing this observation.
        html += '<button type="button" data-fp="' + fp + '" '
            + 'onclick="InventoryPage.forgetFromEl(this)" '
            + 'class="ml-1 px-2 py-1 text-xs bg-surface-2 text-muted rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition" '
            + 'title="Remove this certificate from the inventory">'
            + '<i class="fas fa-eraser mr-1"></i>Forget</button>';
        return html;
    }

    function passesFilters(r) {
        var group = el('invGroup').value;
        var source = el('invSource').value;
        var expiry = el('invExpiry').value;
        var q = el('invSearch').value.trim().toLowerCase();
        if (group && r.group !== group) { return false; }
        if (source && r.source !== source) { return false; }
        if (expiry === 'revoked') {
            if (!r.revocation || r.revocation.status !== 'revoked') { return false; }
        } else if (expiry && r.expiry_status !== expiry) { return false; }
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
                + '<td class="px-4 py-2">' + statusBadge(r.expiry_status, r.days_until_expiry)
                    + '<div>' + revocationBadge(r.revocation) + '</div></td>'
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

    function forget(fingerprint, label) {
        // Removing an inventory row is not the same as stopping discovery, and
        // the difference is the whole of #634: say it in the confirmation so an
        // operator does not delete the same row after every scan.
        var name = label || fingerprint;
        if (!window.confirm(
            'Remove "' + name + '" from the inventory?\n\n'
            + 'The certificate itself is not touched — CertMate only forgets '
            + 'that it observed it.\n\n'
            + 'If this domain is still in the discovery configuration it will '
            + 'be recorded again on the next scan. Remove it there first to '
            + 'stop looking at it.')) { return; }

        fetch('/api/inventory/' + encodeURIComponent(fingerprint),
            { method: 'DELETE', headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
            .then(function (res) {
                if (res.ok) { load(); }
                else { window.alert('Could not remove it: ' + (res.j.error || 'unknown error')); }
            })
            .catch(function (err) { window.alert('Could not remove it (' + err + ').'); });
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
        el('sumRevoked').textContent = (s.revocation || {}).revoked || 0;
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
                el('inventoryBody').innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-red-500">Failed to load inventory (' + escapeHtml(err) + ').</td></tr>';
            });
    }

    // Domain registrations. Only a registry-published date gets a day count;
    // "not published" (.de, .eu) and a failed lookup say so in words instead
    // of showing a number nobody stated.
    function registrationExpiryCell(r) {
        if (r.status === 'ok') {
            return statusBadge(r.expiry_status, r.days_until_expiry)
                + ' <span class="text-xs text-muted">' + escapeHtml((r.expires_at || '').slice(0, 10)) + '</span>';
        }
        var words = {
            not_published: ['Not published by the registry', 'This registry does not publish when a registration expires.'],
            not_registered: ['Not registered', 'The registry says this name does not exist.'],
            unavailable: ['Could not check', r.error || 'No answer from the registry.']
        }[r.status] || ['Unknown', ''];
        return '<span class="inline-block px-2 py-0.5 rounded-full text-xs whitespace-nowrap '
            + (r.status === 'not_registered'
                ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
                : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300')
            + '" title="' + escapeHtml(words[1]) + '">' + escapeHtml(words[0]) + '</span>';
    }

    function loadRegistrations() {
        fetch('/api/inventory/domains', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (data) {
                var rows = data.domains || [];
                var s = data.summary || {};
                var ex = s.expiry || {};
                el('regExpired').textContent = ex.expired || 0;
                el('reg30').textContent = ex['30'] || 0;
                el('reg90').textContent = ex['90'] || 0;
                el('regNotPublished').textContent = (s.by_status || {}).not_published || 0;
                el('regCount').textContent = rows.length ? rows.length + ' domains' : '';
                if (!rows.length) {
                    el('registrationsBody').innerHTML = '<tr><td colspan="4" class="px-4 py-6 text-center text-muted">'
                        + 'No domain registrations checked yet. Enable the check in Discovery configuration, then Scan now.</td></tr>';
                    return;
                }
                el('registrationsBody').innerHTML = rows.map(function (r) {
                    return '<tr class="hover:bg-hover">'
                        + '<td class="px-4 py-2 font-medium text-foreground">' + escapeHtml(r.domain) + '</td>'
                        + '<td class="px-4 py-2">' + registrationExpiryCell(r) + '</td>'
                        + '<td class="px-4 py-2 text-xs text-muted">' + escapeHtml(r.registrar || '—') + '</td>'
                        + '<td class="px-4 py-2 text-xs text-muted" title="Checked ' + escapeHtml(r.checked_at || '') + '">'
                        + escapeHtml((r.source || '—').toUpperCase()) + '</td>'
                        + '</tr>';
                }).join('');
            })
            .catch(function (err) {
                el('registrationsBody').innerHTML = '<tr><td colspan="4" class="px-4 py-6 text-center text-red-500">Failed to load domain registrations (' + escapeHtml(err) + ').</td></tr>';
            });
    }

    // A check's status as a chip. `unknown` is deliberately not green and not
    // red: it means nobody answered, which is neither a pass nor a finding.
    function healthChip(check) {
        if (!check) { return '<span class="text-xs text-muted">—</span>'; }
        var styles = {
            ok: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
            warning: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
            failing: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
            unknown: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300'
        };
        var labels = { ok: 'OK', warning: 'Warning', failing: 'Failing', unknown: 'Not verifiable' };
        var status = check.status || 'unknown';
        return '<span class="inline-block px-2 py-0.5 rounded-full text-xs whitespace-nowrap '
            + (styles[status] || styles.unknown) + '" title="' + escapeHtml(check.detail || '')
            + '">' + escapeHtml(labels[status] || status) + '</span>';
    }

    function loadDomainHealth() {
        fetch('/api/inventory/health', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (data) {
                var rows = data.names || [];
                var by = (data.summary || {}).by_status || {};
                el('healthFailing').textContent = by.failing || 0;
                el('healthWarning').textContent = by.warning || 0;
                el('healthUnknown').textContent = by.unknown || 0;
                el('healthOk').textContent = by.ok || 0;
                el('healthCount').textContent = rows.length ? rows.length + ' names' : '';
                if (!rows.length) {
                    el('domainHealthBody').innerHTML = '<tr><td colspan="9" class="px-4 py-6 text-center text-muted">'
                        + 'No names checked yet. Enable Domain health in Discovery configuration, then Scan now.</td></tr>';
                    return;
                }
                el('domainHealthBody').innerHTML = rows.map(function (r) {
                    var c = r.checks || {};
                    return '<tr class="hover:bg-hover">'
                        + '<td class="px-4 py-2 font-medium text-foreground" title="Checked '
                        + escapeHtml(r.checked_at || '') + '">' + escapeHtml(r.name) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.spf) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.dmarc) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.mx) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.blocklists) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.hsts) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.security_headers) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.disclosure) + '</td>'
                        + '<td class="px-4 py-2">' + healthChip(c.weak_tls) + '</td>'
                        + '</tr>';
                }).join('');
            })
            .catch(function (err) {
                el('domainHealthBody').innerHTML = '<tr><td colspan="9" class="px-4 py-6 text-center text-red-500">Failed to load domain health (' + escapeHtml(err) + ').</td></tr>';
            });
    }

    function loadCryptoSummary() {
        fetch('/api/inventory/crypto-report', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (rep) {
                var c = rep.by_classification || {};
                el('cryptoWeak').textContent = c.weak || 0;
                el('cryptoAcceptable').textContent = c.acceptable || 0;
                el('cryptoModern').textContent = c.modern || 0;
                el('cryptoQuantum').textContent = rep.quantum_vulnerable || 0;
            })
            .catch(function () { /* leave placeholders */ });
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
                el('cfgCheckRevocation').checked = d.check_revocation !== false;
                el('cfgEndpoints').value = (d.endpoints || []).join('\n');
                el('cfgCtEnabled').checked = !!c.enabled;
                el('cfgCtIncludeManaged').checked = c.include_managed !== false;
                el('cfgCtDomains').value = (c.domains || []).join('\n');
                var g = cfg.domain_registration || {};
                el('cfgRegEnabled').checked = !!g.enabled;
                el('cfgRegIncludeInventory').checked = g.include_inventory !== false;
                el('cfgRegExtra').value = (g.extra_domains || []).join('\n');
                var h = cfg.domain_health || {};
                el('cfgHealthEnabled').checked = !!h.enabled;
                el('cfgHealthIncludeInventory').checked = h.include_inventory !== false;
                el('cfgHealthMail').checked = h.check_mail !== false;
                el('cfgHealthBlocklists').checked = h.check_blocklists !== false;
                el('cfgHealthHeaders').checked = h.check_headers !== false;
                el('cfgHealthWeakTls').checked = !!h.check_weak_tls;
                el('cfgHealthExtra').value = (h.extra_domains || []).join('\n');
                el('cfgDnsResolvers').value = ((cfg.dns_resolver || {}).nameservers || []).join('\n');
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
                check_revocation: el('cfgCheckRevocation').checked,
                endpoints: lines('cfgEndpoints')
            },
            ct_monitoring: {
                enabled: el('cfgCtEnabled').checked,
                include_managed: el('cfgCtIncludeManaged').checked,
                domains: lines('cfgCtDomains')
            },
            domain_registration: {
                enabled: el('cfgRegEnabled').checked,
                include_inventory: el('cfgRegIncludeInventory').checked,
                extra_domains: lines('cfgRegExtra')
            },
            domain_health: {
                enabled: el('cfgHealthEnabled').checked,
                include_inventory: el('cfgHealthIncludeInventory').checked,
                check_mail: el('cfgHealthMail').checked,
                check_blocklists: el('cfgHealthBlocklists').checked,
                check_headers: el('cfgHealthHeaders').checked,
                check_weak_tls: el('cfgHealthWeakTls').checked,
                extra_domains: lines('cfgHealthExtra')
            },
            dns_resolver: { nameservers: lines('cfgDnsResolvers') }
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
            .then(function () { load(); loadRegistrations(); loadDomainHealth(); })
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

    function adoptFromEl(elm) {
        var fp = elm && elm.getAttribute('data-fp');
        if (fp) { adopt(fp); }
    }

    function forgetFromEl(elm) {
        var fp = elm && elm.getAttribute('data-fp');
        if (!fp) { return; }
        // Name the certificate in the prompt by its subject, not its
        // fingerprint: the operator recognises the hostname.
        var match = null;
        for (var i = 0; i < records.length; i++) {
            if (records[i].fingerprint === fp) { match = records[i]; break; }
        }
        forget(fp, match && match.subject_cn);
    }

    window.InventoryPage = {
        load: load, render: render, saveConfig: saveConfig,
        runScan: runScan, adopt: adopt, adoptFromEl: adoptFromEl,
        forget: forget, forgetFromEl: forgetFromEl
    };

    document.addEventListener('DOMContentLoaded', function () {
        load();
        loadCryptoSummary();
        loadRegistrations();
        loadDomainHealth();
        gateAdminControls();
    });
}());
