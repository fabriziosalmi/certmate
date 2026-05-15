/*
 * CertMate — one-click bug reporter
 *
 * Powers the "Report this issue" button rendered by CertMate.toast when
 * the caller supplies an errorContext. The button is admin-only (no
 * snapshot endpoint access otherwise) and fully manual — nothing leaves
 * the install without an explicit user click.
 *
 * Flow:
 *   1. fetch /api/diagnostics/snapshot                (admin-gated)
 *   2. merge with client-side context                 (browser, page, error)
 *   3. format as Markdown                             (renderable on GitHub)
 *   4. navigator.clipboard.writeText(markdown)        (fallback: modal)
 *   5. window.open(github/issues/new?...)             (fallback: link in modal)
 *
 * The user lands on github.com with the bug template open and the
 * markdown in their clipboard. They paste, read what they're sending
 * (it's right there in the textarea), edit if they want, submit.
 *
 * Issue: https://github.com/fabriziosalmi/certmate/issues/150
 */
(function () {
    'use strict';

    var CM = window.CertMate = window.CertMate || {};
    var REPO = 'fabriziosalmi/certmate';
    var GITHUB_NEW_ISSUE_URL = 'https://github.com/' + REPO + '/issues/new';
    // GitHub silently truncates ?title= over ~256 chars and the surrounding
    // querystring caps around 2KB. We trim our title aggressively below.
    var TITLE_MAX = 200;

    // ──────────────────────────────────────────────────────────────────
    // Pure helpers (no side effects — testable as a unit)
    // ──────────────────────────────────────────────────────────────────

    function _humanBytes(n) {
        if (n === null || n === undefined) return 'unknown';
        if (n < 1024) return n + ' B';
        var units = ['KB', 'MB', 'GB', 'TB'];
        var v = n / 1024, i = 0;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
        return v.toFixed(1) + ' ' + units[i];
    }

    function _browserLabel(ua) {
        // Pure best-effort family + version detection. We don't ship a
        // full UA parser for a one-line bug-report field; the raw UA
        // remains visible in the Markdown for forensic accuracy.
        if (!ua) return 'unknown';
        var m;
        if ((m = /Firefox\/([\d.]+)/.exec(ua))) return 'Firefox ' + m[1];
        if ((m = /Edg\/([\d.]+)/.exec(ua))) return 'Edge ' + m[1];
        if ((m = /Chrome\/([\d.]+)/.exec(ua))) return 'Chrome ' + m[1];
        if ((m = /Version\/([\d.]+).+Safari/.exec(ua))) return 'Safari ' + m[1];
        return ua.length > 80 ? ua.slice(0, 80) + '…' : ua;
    }

    /**
     * Build the issue title from the error envelope.
     * Shape: "[Bug] <status> <code> on <method> <endpoint>"
     * Falls back gracefully when fields are missing.
     */
    function buildTitle(errorContext) {
        var ec = errorContext || {};
        var parts = ['[Bug]'];
        if (ec.status) parts.push(String(ec.status));
        if (ec.code) parts.push(String(ec.code));
        if (ec.endpoint) parts.push('on ' + ec.endpoint);
        var t = parts.join(' ').trim();
        if (t.length > TITLE_MAX) t = t.slice(0, TITLE_MAX - 1) + '…';
        return t;
    }

    /**
     * Format the merged context as a Markdown body. Pure function — easy to
     * inspect, easy to unit-test, easy for a maintainer to extend with a
     * new field without touching the network/clipboard plumbing.
     */
    function buildMarkdown(snapshot, errorContext, clientContext) {
        var snap = snapshot || {};
        var ec = errorContext || {};
        var cc = clientContext || {};

        function line(label, value) {
            return '- **' + label + '**: ' + (value === undefined || value === null || value === '' ? 'unknown' : value);
        }

        var out = [];

        out.push('### Environment');
        out.push(line('CertMate', snap.certmate_version ? 'v' + snap.certmate_version : null));
        out.push(line('Python', snap.python_version));
        out.push(line('OS', snap.os_platform + (snap.container ? ' (Docker)' : '')));
        out.push(line('Browser', _browserLabel(cc.userAgent) + (cc.viewport ? ' — ' + cc.viewport : '')));
        out.push(line('Page', cc.path));
        out.push('');

        out.push('### Error');
        out.push(line('Endpoint', ec.endpoint));
        out.push(line('Status', ec.status));
        if (ec.code) out.push(line('Code', '`' + ec.code + '`'));
        if (ec.message) out.push(line('Message', ec.message));
        if (ec.hint) out.push(line('Hint', ec.hint));
        out.push('');

        out.push('### Diagnostics');
        out.push(line('Scheduler', snap.scheduler_running ? 'running' : 'not running'));
        out.push(line('Certificates', snap.certificate_count));
        out.push(line('DNS Provider', snap.dns_provider));
        out.push(line('CA', snap.default_ca));
        out.push(line('Challenge', snap.challenge_type));
        out.push(line('Storage', snap.storage_backend));
        out.push(line('Disk free', _humanBytes(snap.disk_free_bytes) +
            (snap.disk_total_bytes ? ' / ' + _humanBytes(snap.disk_total_bytes) : '')));
        out.push('');

        out.push('### Recent activity (sanitized — identifiers stripped)');
        var entries = Array.isArray(snap.recent_audit) ? snap.recent_audit : [];
        if (entries.length === 0) {
            out.push('_(no recent audit entries)_');
        } else {
            entries.forEach(function (e, i) {
                var ts = (e && e.timestamp) ? e.timestamp.replace('T', ' ').replace('Z', '') : '?';
                out.push((i + 1) + '. ' + ts + ' — ' + (e.operation || '?') + ' / ' + (e.resource_type || '?') + ' / ' + (e.status || '?'));
            });
        }

        if (snap.errors && Object.keys(snap.errors).length) {
            out.push('');
            out.push('### Snapshot partial failures');
            Object.keys(snap.errors).forEach(function (k) {
                out.push('- `' + k + '`: ' + snap.errors[k]);
            });
        }

        out.push('');
        out.push('---');
        out.push('_Generated by CertMate\'s in-app bug reporter. The author opened this issue from a one-click button in an error toast; the snapshot above was retrieved from `GET /api/diagnostics/snapshot` and sanitized server-side. The author saw and chose to share these fields before submitting._');

        return out.join('\n');
    }

    // ──────────────────────────────────────────────────────────────────
    // Clipboard + URL plumbing (with fallbacks)
    // ──────────────────────────────────────────────────────────────────

    function _writeClipboard(text) {
        // Modern path. Fails outside HTTPS in some browsers — we
        // surface the fallback modal in that case.
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        return Promise.reject(new Error('clipboard API unavailable'));
    }

    function _openFallbackModal(markdown, issueUrl) {
        // Used when clipboard fails OR window.open is blocked. The user
        // can copy the markdown manually and click the link to open
        // GitHub themselves.
        var overlay = document.createElement('div');
        overlay.className = 'fixed inset-0 z-[10001] flex items-center justify-center p-4';
        overlay.innerHTML = '<div class="absolute inset-0 bg-black/50 backdrop-blur-sm"></div>';

        var box = document.createElement('div');
        box.className = 'relative bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-2xl border border-gray-200 dark:border-gray-700';
        var title = 'Report this issue — manual paste';
        box.innerHTML =
            '<div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">' +
                '<h3 class="text-lg font-semibold text-gray-900 dark:text-white">' + CM.escapeHtml(title) + '</h3>' +
                '<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Your browser blocked the clipboard or new-tab automation. Copy the markdown below and open the issue manually.</p>' +
            '</div>' +
            '<div class="px-6 py-4">' +
                '<textarea readonly class="w-full h-64 p-3 text-xs font-mono bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-800 dark:text-gray-200"></textarea>' +
                '<div class="flex justify-between items-center mt-4">' +
                    '<a target="_blank" rel="noopener" href="' + CM.escapeHtml(issueUrl) + '" class="text-blue-600 dark:text-blue-400 hover:underline text-sm">Open GitHub issue form &nearr;</a>' +
                    '<div class="flex gap-2">' +
                        '<button data-action="copy" class="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700">Copy markdown</button>' +
                        '<button data-action="close" class="px-4 py-2 rounded-lg text-sm font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">Close</button>' +
                    '</div>' +
                '</div>' +
            '</div>';
        overlay.appendChild(box);
        document.body.appendChild(overlay);

        var ta = box.querySelector('textarea');
        ta.value = markdown;
        ta.focus();
        ta.select();

        box.querySelector('[data-action="copy"]').addEventListener('click', function () {
            ta.select();
            try {
                document.execCommand('copy');
                if (CM.toast) CM.toast('Copied to clipboard', 'success', 2000);
            } catch (e) {
                if (CM.toast) CM.toast('Copy failed — please select and Cmd/Ctrl+C', 'warning', 4000);
            }
        });
        box.querySelector('[data-action="close"]').addEventListener('click', function () {
            overlay.remove();
        });
    }

    // ──────────────────────────────────────────────────────────────────
    // Public entry point — wired up by toast button click handler
    // ──────────────────────────────────────────────────────────────────

    /**
     * `errorContext` shape (all optional except endpoint+status if you
     * want the title to be useful):
     *   {
     *     endpoint: 'POST /api/certificates/create',
     *     status: 422,
     *     code: 'CERTBOT_FAILED',
     *     message: 'Certificate creation failed: DNS verification timed out',
     *     hint: 'Check DNS provider credentials and ensure DNS records can be created.'
     *   }
     */
    var _inFlight = false;
    CM.reportIssue = function (errorContext) {
        if (_inFlight) return Promise.resolve();   // idempotency: ignore rapid double-clicks
        _inFlight = true;

        var clientContext = {
            userAgent: navigator.userAgent,
            path: window.location.pathname + window.location.search,
            viewport: window.innerWidth + '×' + window.innerHeight,
            timestamp: new Date().toISOString()
        };

        function _finalize() { _inFlight = false; }

        return fetch('/api/diagnostics/snapshot', {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        })
            .then(function (r) {
                if (!r.ok) {
                    // 403 (role changed mid-session) or 5xx — degrade
                    // gracefully: ship a client-only report so the
                    // user is never stranded with no recovery.
                    return r.json().catch(function () { return {}; }).then(function (body) {
                        return { _snapshot_unavailable: true, _snapshot_status: r.status, _snapshot_body: body };
                    });
                }
                return r.json();
            })
            .catch(function () {
                return { _snapshot_unavailable: true };
            })
            .then(function (snapshot) {
                var markdown = buildMarkdown(snapshot, errorContext, clientContext);
                if (snapshot && snapshot._snapshot_unavailable) {
                    markdown = '> ⚠️ Server snapshot was unavailable (status ' +
                        (snapshot._snapshot_status || 'network error') +
                        '). The report below is client-side only.\n\n' + markdown;
                }
                var url = GITHUB_NEW_ISSUE_URL + '?template=bug_report.md&title=' +
                    encodeURIComponent(buildTitle(errorContext));

                return _writeClipboard(markdown).then(function () {
                    var tab = window.open(url, '_blank', 'noopener');
                    if (!tab) {
                        // popup blocker — fall back to the manual modal
                        // (which has a clickable link inside it).
                        _openFallbackModal(markdown, url);
                    } else if (CM.toast) {
                        CM.toast('Bug report copied. GitHub opened in a new tab — paste and review before submitting.', 'success', 8000);
                    }
                }).catch(function () {
                    // Clipboard write rejected (HTTP, permission, browser policy)
                    _openFallbackModal(markdown, url);
                });
            })
            .then(_finalize, _finalize);
    };

    // Expose pure helpers so they can be unit-tested or reused.
    CM.reportIssueInternals = {
        buildTitle: buildTitle,
        buildMarkdown: buildMarkdown,
        _humanBytes: _humanBytes,
        _browserLabel: _browserLabel
    };
})();
