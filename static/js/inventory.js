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
    // The session's role as the page was served (inventory.html), so the first
    // list already has the buttons it will keep: drawn without them and again
    // with them once /api/auth/me answered, the columns moved under the eye.
    var currentRole = ((document.getElementById('inventoryApp') || {}).dataset || {}).role || 'viewer';

    function el(id) { return document.getElementById(id); }

    // A count and the colour it earns, together.
    //
    // The nine alarm tiles on this page wrote the colour into their class
    // attribute, so it belonged to the LABEL rather than to the value: "0
    // expired", "0 revoked" and "0 weak" — the best states this page can
    // report — were painted in the colour it uses for "act now", and a healthy
    // instance opened on a wall of red (#939). The dashboard already got this
    // right, and said so in a comment; the two surfaces disagreed about what a
    // colour meant.
    //
    // It runs both ways. "Modern 0" was painted GREEN by the same habit, and
    // zero modern certificates is not good news either — it is the same lie
    // with the other palette.
    //
    // Zero is NEUTRAL, never green: on an instance that has scanned nothing,
    // "0 weak" is an absence of evidence and not an achievement. The "nothing
    // checked yet" copy under each table is where that distinction belongs.
    //
    // `data-nonzero` on the tile is the class the value earns when it is not
    // zero — an alarm colour for a bad category, a positive one for a good
    // one — so adding a tile is a template change and nothing here has to be
    // remembered.
    function setCount(id, value) {
        var node = el(id);
        if (!node) return;
        var count = value || 0;
        node.textContent = count;
        var earned = node.getAttribute('data-nonzero');
        if (!earned) return;
        // The neutral class comes OFF when the earned one goes on. Both are
        // `color` utilities of equal specificity, so the winner is whichever
        // Tailwind emits later in the bundle and not whichever was added last
        // to the element: leaving both in place left "Expired 4" white while
        // "<= 7 days 1" went orange, because those two colours happen to sit
        // on opposite sides of `text-foreground` in the generated stylesheet.
        // Visible only in a browser — `classList.contains` was satisfied.
        node.classList.toggle('text-foreground', count === 0);
        earned.split(/\s+/).forEach(function (cls) {
            if (cls) node.classList.toggle(cls, count > 0);
        });
    }

    function roleAtLeast(name) {
        return (ROLE_LEVELS[currentRole] || 0) >= (ROLE_LEVELS[name] || 0);
    }

    // The pill's colour is the renewal state, in the dashboard's words on
    // hover (P25): Overdue red, Due amber, Valid green.
    function statusBadge(status, days) {
        var map = {
            expired: ['bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300', 'Expired', 'Expired'],
            critical: ['bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300', days + 'd', 'Renewal overdue'],
            warning: ['bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300', days + 'd', 'Renewal due'],
            ok: ['bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300', days + 'd', 'Valid: renewal not due yet'],
            unknown: ['bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300', '—', '']
        };
        var m = map[status] || map.unknown;
        return '<span class="inline-block px-2 py-0.5 rounded-full text-xs font-medium ' + m[0] + '"'
            + (m[2] ? ' title="' + escapeHtml(m[2]) + '"' : '') + '>' + escapeHtml(m[1]) + '</span>';
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

    // The key as text, '' when there is none. Shared by the cell and the sort, so
    // the column is ordered by exactly what it shows.
    function keyText(key) {
        if (!key || !key.type) { return ''; }
        if (key.curve) { return key.type + ' ' + key.curve; }
        if (key.size) { return key.type + ' ' + key.size; }
        return String(key.type);
    }

    function keyLabel(key) {
        var text = keyText(key);
        return text ? escapeHtml(text) : '—';
    }

    function subjectCell(r) {
        var sans = (r.san_dns || []).slice(0, 3).join(', ');
        var extra = (r.san_dns || []).length > 3 ? ' +' + ((r.san_dns.length) - 3) : '';
        var cn = r.subject_cn || '(no CN)';
        var s = '<div class="font-medium text-foreground">' + escapeHtml(cn);
        // Replaced on every endpoint it was seen on (#1044): kept in the history, and said so.
        if (r.superseded) {
            s += ' <span class="inline-block px-1.5 py-0.5 rounded text-xs bg-surface-2 text-muted" '
                + 'title="A newer certificate replaced it: every endpoint it was seen on now serves another, or CertMate renewed it">superseded</span>';
        }
        s += '</div>';
        // Below md the subject is the only column: the names fill the cell
        // and take no width of their own (w-0 min-w-full), so a long list of
        // them is cut with an ellipsis instead of widening the table past a
        // 360 px screen.
        if (sans) { s += '<div class="text-xs text-muted truncate max-w-xs max-md:w-0 max-md:min-w-full">' + escapeHtml(sans) + escapeHtml(extra) + '</div>'; }
        return s;
    }

    // The first endpoint, and "+N" for the rest. The rest used to be only a
    // number: a certificate served on five hosts said "+4" with no way to see
    // which four short of the API. Hovering the cell now lists every one, one per
    // line (the native tooltip: no script, nothing the CSP has to allow), and the
    // same list is in the cell as screen-reader text, which a title alone is not
    // reliably announced as.
    function endpointsCell(r) {
        var eps = r.endpoints || [];
        if (!eps.length) { return '<span class="text-xs text-muted">—</span>'; }
        var all = eps.map(function (e) { return e.host + ':' + e.port; });
        var first = '<span class="text-xs font-mono">' + escapeHtml(all[0]) + '</span>';
        if (all.length === 1) { return first; }
        return '<span class="cursor-help whitespace-nowrap" title="' + escapeHtml(all.join('\n')) + '">'
            + first + ' <span class="text-muted" aria-hidden="true">+' + (all.length - 1) + '</span>'
            + '<span class="sr-only">, ' + escapeHtml(all.slice(1).join(', ')) + '</span>'
            + '</span>';
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
                + 'data-click="InventoryPage.adoptFromEl" data-pass="el" '
                + 'class="px-2 py-1 text-xs bg-surface-2 text-primary rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition" '
                + 'title="Take over issuance/renewal of this certificate">'
                + '<i class="fas fa-hand-holding-medical mr-1"></i>Adopt</button>';
        }
        // Forget removes the inventory row (#634). A managed row whose domain
        // CertMate still holds a certificate for has none: that record comes
        // back only at startup or on the next issuance or renewal, so a
        // forgotten one left Managed short of the certificates (P48). A
        // managed row whose certificate was deleted keeps Forget, or nothing
        // in the page could remove it: 'managed' never goes back to false.
        // Until the certificate list is known, managed rows show none.
        if (r.managed && (heldDomains === null || !r.managed_domain || heldDomains[r.managed_domain])) {
            return html;
        }
        html += '<button type="button" data-fp="' + fp + '" '
            + 'data-click="InventoryPage.forgetFromEl" data-pass="el" '
            + 'class="ml-1 px-2 py-1 text-xs bg-surface-2 text-muted rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition" '
            + 'title="Remove this certificate from the inventory">'
            + '<i class="fas fa-eraser mr-1"></i>Forget</button>';
        return html;
    }

    function issuerText(r) {
        return r.issuer_cn || r.issuer || '—';
    }

    // Below md the row is the subject cell alone, and this is what the other
    // columns say, under the subject: the expiry with its date, the issuer,
    // the source and the actions. The seven columns were 911 px wide on a
    // 390 px phone, so all a person saw was the names (P11).
    function phoneSummary(r) {
        var date = (r.not_after || '').slice(0, 10);
        var actions = actionsCell(r);
        return '<div class="md:hidden mt-1 space-y-1">'
            + '<div class="flex flex-wrap items-center gap-x-2 gap-y-1">'
                + statusBadge(r.expiry_status, r.days_until_expiry)
                + (date ? '<span class="text-xs text-muted">' + escapeHtml(date) + '</span>' : '')
                + sourceBadge(r.source, r.managed)
                + revocationBadge(r.revocation)
            + '</div>'
            + '<div class="text-xs text-muted break-words">' + escapeHtml(issuerText(r)) + '</div>'
            + (actions ? '<div class="pt-1">' + actions + '</div>' : '')
            + '</div>';
    }

    // The filters as the controls hold them.
    function currentFilters() {
        return {
            group: el('invGroup').value,
            source: el('invSource').value,
            expiry: el('invExpiry').value,
            q: el('invSearch').value.trim().toLowerCase()
        };
    }

    // One test for the list and for the summary cards (P09): a card counts the
    // records that pass the filter it applies when clicked, so its number and
    // the rows it shows cannot disagree.
    function passesFilters(r, f) {
        f = f || currentFilters();
        var group = f.group, source = f.source, expiry = f.expiry, q = f.q;
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

    // How many superseded certificates the last load left out of the list (0 when they are shown).
    var hiddenSuperseded = 0;

    function showSuperseded() {
        var box = el('invSuperseded');
        return !!(box && box.checked);
    }

    // Column sorting: the same interaction as the dashboard and client-certificate
    // tables. A header sorts ascending, a second click descending, and aria-sort and
    // the glyph follow. Until a header is clicked the list keeps the order the API
    // returned, so the page looks exactly as it did before anyone sorts it.
    var sortState = { field: null, dir: 'asc' };

    // What a column sorts by: a number, a lower-cased string, or null when the
    // record has nothing for it. Expiry is the date, not the badge text, so
    // "3 days" comes before "12 days" and both before "Expired" in descending order.
    function sortValue(r, field) {
        if (field === 'subject') { return (r.subject_cn || '').toLowerCase() || null; }
        if (field === 'issuer') { return (r.issuer_cn || r.issuer || '').toLowerCase() || null; }
        if (field === 'expiry') {
            var when = Date.parse(r.not_after || '');
            return isNaN(when) ? null : when;
        }
        if (field === 'key') { return keyText(r.key).toLowerCase() || null; }
        if (field === 'source') { return (r.source || '').toLowerCase() || null; }
        if (field === 'endpoints') { return (r.endpoints || []).length; }
        return null;
    }

    function compareRecords(a, b) {
        var va = sortValue(a, sortState.field);
        var vb = sortValue(b, sortState.field);
        // A record with nothing to sort by goes to the bottom in either direction,
        // rather than heading the list as a block of dashes.
        if (va === null || vb === null) {
            if (va === vb) { return 0; }
            return va === null ? 1 : -1;
        }
        var dir = sortState.dir === 'asc' ? 1 : -1;
        if (typeof va === 'number') { return dir * (va - vb); }
        // numeric: 'RSA 2048' before 'RSA 4096', 'a2.example' before 'a10.example'.
        return dir * va.localeCompare(vb, undefined, { numeric: true });
    }

    function applySort(rows) {
        // Array.prototype.sort is stable, so equal keys keep the API's order.
        return sortState.field ? rows.slice().sort(compareRecords) : rows;
    }

    function sortBy(field) {
        if (sortState.field === field) {
            sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
        } else {
            sortState.field = field;
            sortState.dir = 'asc';
        }
        document.querySelectorAll('[id^="inv-sort-icon-"]').forEach(function (icon) {
            icon.className = 'fas fa-sort ml-1 text-gray-400';
        });
        document.querySelectorAll('[id^="inv-sort-th-"]').forEach(function (th) {
            th.setAttribute('aria-sort', 'none');
        });
        var icon = el('inv-sort-icon-' + field);
        if (icon) { icon.className = 'fas fa-sort-' + (sortState.dir === 'asc' ? 'up' : 'down') + ' ml-1 text-primary'; }
        var th = el('inv-sort-th-' + field);
        if (th) { th.setAttribute('aria-sort', sortState.dir === 'asc' ? 'ascending' : 'descending'); }
        render();
    }

    function render() {
        var body = el('inventoryBody');
        var rows = applySort(records.filter(function (r) { return passesFilters(r); }));
        el('inventoryHead').classList.remove('invisible');
        el('invCount').textContent = rows.length + ' of ' + records.length
            + (hiddenSuperseded ? ' · ' + hiddenSuperseded + ' superseded hidden' : '');
        if (!rows.length) {
            var empty = records.length
                ? 'No certificates match the filters.'
                : (hiddenSuperseded
                    ? 'Every certificate in the inventory has been superseded. Tick \u201cShow superseded\u201d to see them.'
                    : 'Inventory is empty. Configure discovery or CT-log monitoring, then Scan now.');
            body.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-muted">' + empty + '</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (r) {
            return '<tr class="hover:bg-hover">'
                + '<td class="px-4 py-2">' + subjectCell(r) + phoneSummary(r) + '</td>'
                + '<td class="px-4 py-2 text-xs text-muted hidden md:table-cell">' + escapeHtml(issuerText(r)) + '</td>'
                + '<td class="px-4 py-2 hidden md:table-cell">' + statusBadge(r.expiry_status, r.days_until_expiry)
                    + '<div>' + revocationBadge(r.revocation) + '</div></td>'
                + '<td class="px-4 py-2 text-xs hidden md:table-cell">' + keyLabel(r.key) + '</td>'
                + '<td class="px-4 py-2 hidden md:table-cell">' + sourceBadge(r.source, r.managed) + '</td>'
                + '<td class="px-4 py-2 hidden md:table-cell">' + endpointsCell(r) + '</td>'
                + '<td class="px-4 py-2 text-right hidden md:table-cell">' + actionsCell(r) + '</td>'
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
        //
        // Asked in the page's own dialog, not window.confirm (P48). Only a
        // discovered row has Forget, and what brings one back is a sweep or a
        // CT-log poll that finds it again, whatever made it look there: an
        // endpoint, a watched domain, or the managed names it includes.
        var name = label || fingerprint;
        CertMate.confirm(
            'Remove "' + name + '" from the inventory? The certificate itself is not touched: '
            + 'CertMate only forgets that it saw it. A later discovery sweep or CT-log poll that '
            + 'finds it again records it again; to stop that, first change the Discovery '
            + 'configuration so it no longer looks there.',
            'Forget certificate', { confirmText: 'Forget' }
        ).then(function (confirmed) {
            if (!confirmed) { return; }
            fetch('/api/inventory/' + encodeURIComponent(fingerprint),
                { method: 'DELETE', headers: API_HEADERS, credentials: 'same-origin' })
                .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
                .then(function (res) {
                    if (res.ok) { load(); }
                    else { CertMate.toast('Could not remove it: ' + (res.j.error || 'unknown error'), 'error'); }
                })
                .catch(function (err) { CertMate.toast('Could not remove it (' + err + ').', 'error'); });
        });
    }

    // A card's filter: its group and expiry, nothing else.
    function cardFilters(card) {
        return {
            group: card.getAttribute('data-card-group') || '',
            source: '',
            expiry: card.getAttribute('data-card-expiry') || '',
            q: ''
        };
    }

    function cardCount(card) {
        var f = cardFilters(card);
        return records.filter(function (r) { return passesFilters(r, f); }).length;
    }

    // Every card is counted from the list the page holds, with the filter its
    // click applies. They were the API summary's calendar buckets (expired,
    // within 7 / 30 / 90 days), which the pills and the filter do not use.
    function setSummary() {
        var count = {};
        document.querySelectorAll('#summaryCards [data-card-expiry]').forEach(function (card) {
            var value = card.querySelector('[id]');
            if (value) { count[value.id] = cardCount(card); }
        });
        setCount('sumTotal', count.sumTotal);
        setCount('sumIssued', count.sumIssued);
        setCount('sumDiscovered', count.sumDiscovered);
        setCount('sumExpired', count.sumExpired);
        setCount('sumOverdue', count.sumOverdue);
        setCount('sumDue', count.sumDue);
        setCount('sumValid', count.sumValid);
        setCount('sumRevoked', count.sumRevoked);
    }

    // A click on a card shows what it counts: its filter, and the others cleared.
    function showCard(card) {
        if (!card) { return; }
        var f = cardFilters(card);
        el('invGroup').value = f.group;
        el('invSource').value = f.source;
        el('invExpiry').value = f.expiry;
        el('invSearch').value = f.q;
        render();
    }

    // The domains CertMate holds a certificate for, as {domain: true}, or null
    // while unknown (not loaded, or the request failed).
    var heldDomains = null;

    function loadHeldDomains() {
        fetch('/api/certificates', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (list) {
                var held = {};
                (Array.isArray(list) ? list : []).forEach(function (c) {
                    if (c && c.exists && c.domain) held[c.domain] = true;
                });
                heldDomains = held;
                render();
            })
            .catch(function () { /* unknown: managed rows keep no Forget */ });
    }

    function load() {
        loadHeldDomains();
        // Superseded certificates are left out by the server unless asked for, so the summary cards
        // describe what the list shows; the API itself returns them, marked, by default.
        var url = '/api/inventory' + (showSuperseded() ? '' : '?include_superseded=false');
        fetch(url, { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (data) {
                records = data.certificates || [];
                hiddenSuperseded = showSuperseded() ? 0 : ((data.summary || {}).superseded || 0);
                setSummary();
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

    // A domain check (registrations, health) is drawn on or off by the
    // template (inventory_page); `data-check-when` parts follow the state, and
    // a check that is off loads nothing.
    function checkOn(panelId) {
        var panel = el(panelId);
        return !!panel && panel.getAttribute('data-check-on') === 'true';
    }

    function showCheck(panelId, on) {
        var panel = el(panelId);
        if (!panel) { return; }
        panel.setAttribute('data-check-on', on ? 'true' : 'false');
        panel.querySelectorAll('[data-check-when]').forEach(function (part) {
            part.classList.toggle('hidden', (part.getAttribute('data-check-when') === 'on') !== on);
        });
    }

    // The rows in the table, or, when there are none, a sentence in place of
    // the table: outside its scroll box, so a phone shows it whole.
    function fillCheck(name, rowsHtml, sentence, failed) {
        el(name + 'Body').innerHTML = rowsHtml || '';
        el(name + 'Table').classList.toggle('hidden', !rowsHtml);
        var note = el(name + 'Note');
        note.classList.toggle('hidden', !!rowsHtml);
        note.textContent = sentence || '';
        note.classList.toggle('text-danger-fg', !!failed);
        note.classList.toggle('text-muted', !failed);
    }

    // Where both checks take their names from, for the sentence that says
    // there is nothing to check.
    var CHECK_SOURCES = 'The check takes them from the certificates CertMate holds, '
        + 'from the inventory when it is included, and from the extra domains in the Discovery configuration.';

    // With no row: a scan that has names to check has not run yet, or there
    // is nothing for any scan to check (summary.tracked is 0).
    function emptyCheckSentence(tracked, notYet, nothing) {
        return tracked === 0 ? nothing + ' ' + CHECK_SOURCES : notYet;
    }

    function loadRegistrations() {
        if (!checkOn('registrationsPanel')) { return; }
        fetch('/api/inventory/domains', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (data) {
                var rows = data.domains || [];
                var s = data.summary || {};
                var ex = s.expiry || {};
                setCount('regExpired', ex.expired);
                setCount('reg30', ex['30']);
                setCount('reg90', ex['90']);
                setCount('regNotPublished', (s.by_status || {}).not_published);
                el('regCount').textContent = rows.length ? rows.length + ' domains' : '';
                if (!rows.length) {
                    fillCheck('registrations', '', emptyCheckSentence(s.tracked,
                        'No domain registrations checked yet: the next scan checks them.',
                        'Nothing to check: there is no domain to track.'));
                    return;
                }
                fillCheck('registrations', rows.map(function (r) {
                    return '<tr class="hover:bg-hover">'
                        + '<td class="px-4 py-2 font-medium text-foreground">' + escapeHtml(r.domain) + '</td>'
                        + '<td class="px-4 py-2">' + registrationExpiryCell(r) + '</td>'
                        + '<td class="px-4 py-2 text-xs text-muted">' + escapeHtml(r.registrar || '—') + '</td>'
                        + '<td class="px-4 py-2 text-xs text-muted" title="Checked ' + escapeHtml(r.checked_at || '') + '">'
                        + escapeHtml((r.source || '—').toUpperCase()) + '</td>'
                        + '</tr>';
                }).join(''));
            })
            .catch(function (err) {
                fillCheck('registrations', '', 'Failed to load domain registrations (' + err + ').', true);
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
        if (!checkOn('domainHealthPanel')) { return; }
        fetch('/api/inventory/health', { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (data) {
                var rows = data.names || [];
                var summary = data.summary || {};
                var by = summary.by_status || {};
                setCount('healthFailing', by.failing);
                setCount('healthWarning', by.warning);
                setCount('healthUnknown', by.unknown);
                setCount('healthOk', by.ok);
                el('healthCount').textContent = rows.length ? rows.length + ' names' : '';
                if (!rows.length) {
                    fillCheck('domainHealth', '', emptyCheckSentence(summary.tracked,
                        'No names checked yet: the next scan checks them.',
                        'Nothing to check: there is no name to track.'));
                    return;
                }
                fillCheck('domainHealth', rows.map(function (r) {
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
                }).join(''));
            })
            .catch(function (err) {
                fillCheck('domainHealth', '', 'Failed to load domain health (' + err + ').', true);
            });
    }

    function loadCryptoSummary() {
        // The readiness cards describe what the list shows: they leave out superseded certificates too.
        var url = '/api/inventory/crypto-report' + (showSuperseded() ? '' : '?include_superseded=false');
        fetch(url, { headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function (rep) {
                var c = rep.by_classification || {};
                setCount('cryptoWeak', c.weak);
                setCount('cryptoAcceptable', c.acceptable);
                setCount('cryptoModern', c.modern);
                setCount('cryptoQuantum', rep.quantum_vulnerable);
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
                if (!res.ok) { return; }
                // A check turned on or off here opens or folds its section now.
                showCheck('registrationsPanel', body.domain_registration.enabled);
                showCheck('domainHealthPanel', body.domain_health.enabled);
                loadRegistrations();
                loadDomainHealth();
            })
            .catch(function () { msg.textContent = 'Save failed.'; msg.className = 'text-xs mr-auto text-red-500'; });
    }

    function runScan() {
        var btn = el('scanNowBtn');
        var msg = el('scanMsg');
        var original = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Scanning…';
        if (msg) { msg.textContent = ''; msg.className = 'text-xs text-muted'; }
        fetch('/api/inventory/scan', { method: 'POST', headers: API_HEADERS, credentials: 'same-origin' })
            .then(function (r) {
                // 409 carries a body: a scan was already running and this one
                // did not happen. Reloading the tables would show the other
                // run's partial state as though it were the answer to THIS
                // click, so say what happened instead.
                return r.json().then(function (body) { return { ok: r.ok, status: r.status, body: body }; },
                                     function () { return { ok: r.ok, status: r.status, body: {} }; });
            })
            .then(function (res) {
                if (res.ok) { load(); loadRegistrations(); loadDomainHealth(); return; }
                if (!msg) { return; }
                msg.textContent = res.status === 409
                    ? (res.body.error || 'A scan is already running.')
                    : 'Scan failed.';
                msg.className = 'text-xs text-danger-fg';
            })
            .catch(function () {
                if (msg) { msg.textContent = 'Scan failed.'; msg.className = 'text-xs text-danger-fg'; }
            })
            .then(function () { btn.disabled = false; btn.innerHTML = original; });
    }

    function gateAdminControls() {
        fetch('/api/auth/me', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (me) {
                var served = currentRole;
                currentRole = (me && (me.role || (me.user && me.user.role))) || 'viewer';
                // The template already drew both for an admin (inventory.html);
                // this is the check, and it hides as well as shows.
                var admin = roleAtLeast('admin');
                el('configPanel').classList.toggle('hidden', !admin);
                el('scanNowBtn').classList.toggle('hidden', !admin);
                if (admin) { loadConfig(); }
                // Re-render only when the answer differs from the role the page
                // was served with: the Adopt and Forget buttons follow it.
                if (records.length && currentRole !== served) { render(); }
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

    // "Turn on in Discovery configuration" on a check that is off: the
    // configuration opened at that check's switch. Saving it is still the
    // admin's step.
    function openConfig(fieldId) {
        var details = el('configPanel') && el('configPanel').querySelector('details');
        if (details) { details.open = true; }
        var field = el(fieldId);
        if (field) {
            field.scrollIntoView({ block: 'center' });
            field.focus();
        }
    }

    // The one control that changes what both the list and the readiness cards describe.
    function toggleSuperseded() {
        load();
        loadCryptoSummary();
    }

    window.InventoryPage = {
        load: load, render: render, saveConfig: saveConfig, toggleSuperseded: toggleSuperseded,
        sortBy: sortBy, openConfig: openConfig, showCard: showCard,
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
    // What the page's controls may ask for by name (`data-click`, `data-change`,
    // `data-input`): see CertMate.actions in certmate.js.
    CertMate.globalActions([
        'InventoryPage.adoptFromEl', 'InventoryPage.forgetFromEl', 'InventoryPage.load', 'InventoryPage.openConfig',
        'InventoryPage.render', 'InventoryPage.runScan', 'InventoryPage.saveConfig', 'InventoryPage.showCard',
        'InventoryPage.sortBy', 'InventoryPage.toggleSuperseded'
    ]);
}());
