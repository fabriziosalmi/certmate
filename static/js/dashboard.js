/**
 * Dashboard — Server certificate management module.
 * Handles certificate CRUD, deployment status checking, filtering,
 * sorting, detail panel, and debug console.
 *
 * static/js/dashboard.js
 */
(function () {
    'use strict';

    // API Configuration - session cookies are sent automatically
    var API_HEADERS = {
        'Content-Type': 'application/json'
    };

    var escapeHtml = CertMate.escapeHtml;
    var browserDeploymentReportQueue = {};
    var browserDeploymentReportTimer = null;

    // --- Role-aware UI gating (audit punch-list M2) -----------------------
    // Default to viewer until /api/auth/me responds. The server is the
    // source of truth — these checks only suppress controls the user
    // would get a 403 from anyway, so a brief mis-render at startup is
    // safe. We refresh on every loadCertificates() so a session role
    // change between requests doesn't leave the UI stuck.
    var ROLE_LEVELS = { viewer: 0, operator: 1, admin: 2 };
    var currentRole = 'viewer';

    function roleAtLeast(name) {
        return (ROLE_LEVELS[currentRole] || 0) >= (ROLE_LEVELS[name] || 0);
    }

    function refreshCurrentRole() {
        return fetch('/api/auth/me', { credentials: 'same-origin' })
            .then(function (r) {
                if (!r.ok) return null;
                return r.json();
            })
            .then(function (data) {
                if (data && data.user && data.user.role) {
                    currentRole = data.user.role;
                }
            })
            .catch(function () { /* keep last-known role */ });
    }

    // Show enhanced loading modal with progress
    function showLoadingModal(title, message) {
        title = title || 'Processing Certificate...';
        message = message || 'This may take a few minutes';
        var modal = document.getElementById('loadingModal');
        document.getElementById('loadingTitle').textContent = title;
        document.getElementById('loadingMessage').textContent = message;
        // Indeterminate progress: we have no real percentage to report, so we
        // show a steady partial bar instead of faking a random climb to 90%.
        // Activity is conveyed by the modal's spinner; hideLoadingModal()
        // completes the bar to 100% on real completion.
        document.getElementById('progressBar').style.width = '40%';
        // Toggle `hidden` and the flex centering utilities together — the
        // static markup keeps only `hidden` so we never ship `hidden flex`
        // at the same time (display utilities conflicting; works today
        // only because of Tailwind's class ordering).
        modal.classList.remove('hidden');
        modal.classList.add('flex', 'items-center', 'justify-center');

        // No fake progress interval — return null. hideLoadingModal() tolerates
        // a null arg (it already guards `if (progressInterval)`).
        return null;
    }

    // Hide loading modal and complete progress
    function hideLoadingModal(progressInterval) {
        document.getElementById('progressBar').style.width = '100%';
        setTimeout(function () {
            var modal = document.getElementById('loadingModal');
            modal.classList.add('hidden');
            modal.classList.remove('flex', 'items-center', 'justify-center');
            if (progressInterval) clearInterval(progressInterval);
        }, 500);
    }

    // Show message function with improved styling
    function showMessage(message, type, options) {
        // options.errorContext (when supplied) triggers the "Report
        // this issue" button in the resulting toast — see report-issue.js.
        CertMate.toast(message, type, undefined, options);
    }

    // Clear filters function
    function clearFilters() {
        document.getElementById('statusFilter').value = 'all';
        filterCertificates();
    }

    function queueBrowserDeploymentReport(domain, result) {
        if (!domain || !result || !result.reachable) {
            return;
        }

        browserDeploymentReportQueue[domain] = {
            domain: domain,
            reachable: true,
            checked_at: result.timestamp || new Date().toISOString(),
            method: result.method || 'browser-fallback',
            source: 'browser'
        };

        if (!browserDeploymentReportTimer) {
            browserDeploymentReportTimer = setTimeout(flushBrowserDeploymentReports, 250);
        }
    }

    function flushBrowserDeploymentReports() {
        browserDeploymentReportTimer = null;
        var reports = Object.keys(browserDeploymentReportQueue).map(function (domain) {
            return browserDeploymentReportQueue[domain];
        });
        browserDeploymentReportQueue = {};

        if (!reports.length) {
            return Promise.resolve();
        }

        return fetch('/api/certificates/deployment-status/browser', {
            method: 'POST',
            headers: API_HEADERS,
            credentials: 'same-origin',
            body: JSON.stringify({ reports: reports })
        }).catch(function (error) {
            console.warn('Failed to send browser deployment reports:', error);
        });
    }

    // Update statistics cards with deployment info
    // Number of stat cards `updateStats` emits below (Total, Valid,
    // Expiring, Deployed). Drives the initial skeleton render so the
    // placeholder count always matches the real count — when the metric
    // list changes, bump this constant in lockstep with the statCard()
    // calls in `updateStats`.
    var STAT_METRICS_COUNT = 4;

    function statsSkeletonHtml(count) {
        var rows = [];
        for (var i = 0; i < count; i++) {
            rows.push(
                '<div class="bg-surface rounded-xl px-3 py-2" aria-hidden="true">' +
                    '<div class="skeleton h-3 w-16 mb-1"></div>' +
                    '<div class="skeleton h-6 w-8"></div>' +
                '</div>'
            );
        }
        return rows.join('');
    }

    function updateStats(certificates) {
        // Ensure certificates is an array
        if (!Array.isArray(certificates)) {
            certificates = []; // Fallback to empty array
        }

        var total = certificates.length;
        var valid = certificates.filter(function (cert) { return cert.exists && cert.days_until_expiry > 30; }).length;
        var expiring = certificates.filter(function (cert) { return cert.exists && cert.days_until_expiry > 0 && cert.days_until_expiry <= 30; }).length;
        var expired = certificates.filter(function (cert) { return cert.exists && cert.days_until_expiry !== null && cert.days_until_expiry !== undefined && cert.days_until_expiry <= 0; }).length;

        var statsContainer = document.getElementById('statsCards');

        // Reactive KPI tile: a hero number with the label above it and a
        // discreet icon accent, plus a left accent bar + surface tint that
        // light up only when the metric needs action — so the most urgent
        // number draws the eye the moment the dashboard loads. The old layout
        // pushed the label and icon to opposite corners (justify-between) with
        // no link between the three elements; this groups them and adds meaning.
        function statCard(label, value, state, iconClass, valueId, subtitle) {
            var S = ({
                headline: { bar: 'bg-blue-500', val: 'text-foreground', bg: 'bg-surface' },
                neutral:  { bar: 'bg-gray-200 dark:bg-gray-700', val: 'text-muted', bg: 'bg-surface' },
                good:     { bar: 'bg-green-500', val: 'text-success-fg', bg: 'bg-surface' },
                warn:     { bar: 'bg-yellow-500', val: 'text-warning-fg', bg: 'bg-warning-surface' },
                danger:   { bar: 'bg-red-500', val: 'text-danger-fg', bg: 'bg-danger-surface' },
                info:     { bar: 'bg-indigo-500', val: 'text-indigo-600 dark:text-indigo-400', bg: 'bg-surface' }
            })[state] || {};
            return '<div class="relative overflow-hidden rounded-xl shadow-card hover:shadow-elevated transition-shadow duration-200 ' + S.bg + '">' +
                '<span class="absolute inset-y-0 left-0 w-1 ' + S.bar + '" aria-hidden="true"></span>' +
                '<div class="pl-4 pr-3 py-3">' +
                '<div class="flex items-start justify-between gap-2">' +
                '<p class="text-[11px] font-semibold text-muted uppercase tracking-wider mt-0.5">' + CertMate.escapeHtml(label) + '</p>' +
                '<i class="fas ' + iconClass + ' text-sm flex-shrink-0"></i>' +
                '</div>' +
                '<p class="text-3xl font-bold ' + S.val + ' tabular-nums leading-none mt-1.5"' + (valueId ? ' id="' + valueId + '"' : '') + '>' + value + '</p>' +
                (subtitle ? '<p class="text-xs text-muted mt-1.5">' + CertMate.escapeHtml(subtitle) + '</p>' : '') +
                '</div></div>';
        }

        // The third tile surfaces the MOST urgent lifecycle state. It becomes a
        // red "Expired" tile when any cert has lapsed (expired was computed but
        // never shown — those certs were invisible on the dashboard), an amber
        // "Expiring" tile within 30 days, else a calm neutral one.
        var attn;
        if (expired > 0) {
            attn = ['Expired', expired, 'danger', 'fa-circle-xmark text-danger-fg',
                    expiring > 0 ? ('renew now · ' + expiring + ' expiring') : 'renew now'];
        } else if (expiring > 0) {
            attn = ['Expiring', expiring, 'warn', 'fa-triangle-exclamation text-warning-fg', 'within 30 days'];
        } else {
            attn = ['Expiring', 0, 'neutral', 'fa-triangle-exclamation text-muted', 'none expiring'];
        }

        statsContainer.innerHTML = [
            statCard('Total', total, 'headline', 'fa-certificate text-blue-500 dark:text-blue-400', null, total === 1 ? 'certificate' : 'certificates'),
            statCard('Valid', valid, valid > 0 ? 'good' : 'neutral', 'fa-circle-check ' + (valid > 0 ? 'text-success-fg' : 'text-muted'), null, valid + ' of ' + total + ' healthy'),
            statCard(attn[0], attn[1], attn[2], attn[3], null, attn[4]),
            (total === 0
                ? statCard('Deployed', '0', 'neutral', 'fa-globe text-muted', null, 'none deployed')
                : statCard('Deployed', '<span class="text-gray-300 dark:text-gray-600 animate-pulse" aria-label="checking deployments">—</span>', 'info', 'fa-globe text-indigo-500 dark:text-indigo-400', 'deploymentCount', 'reachable'))
        ].join('');
    }

    // Deployment Status Cache System
    function DeploymentCache() {
        this.cache = new Map();
        this.defaultTTL = 300000; // 5 minutes default
        this.loadSettings();
    }

    DeploymentCache.prototype.loadSettings = function () {
        try {
            var savedSettings = localStorage.getItem('deployment-cache-settings');
            if (savedSettings) {
                var settings = JSON.parse(savedSettings);
                this.defaultTTL = settings.ttl || this.defaultTTL;
            }
        } catch (error) {
            // Ignore settings load failures, defaults will be used
        }
    };

    DeploymentCache.prototype.saveSettings = function (ttl) {
        try {
            this.defaultTTL = ttl;
            localStorage.setItem('deployment-cache-settings', JSON.stringify({ ttl: ttl }));
        } catch (error) {
            // Ignore settings save failures
        }
    };

    DeploymentCache.prototype.set = function (domain, result) {
        var timestamp = Date.now();
        this.cache.set(domain, {
            result: result,
            timestamp: timestamp,
            ttl: this.defaultTTL
        });
    };

    DeploymentCache.prototype.get = function (domain) {
        var cached = this.cache.get(domain);
        if (!cached) return null;

        var now = Date.now();
        var isExpired = (now - cached.timestamp) > cached.ttl;

        if (isExpired) {
            this.cache.delete(domain);
            return null;
        }

        return cached.result;
    };

    DeploymentCache.prototype.invalidate = function (domain) {
        this.cache.delete(domain);
    };

    DeploymentCache.prototype.clear = function () {
        this.cache.clear();
    };

    DeploymentCache.prototype.getStatus = function () {
        var now = Date.now();
        var entries = [];
        this.cache.forEach(function (data, domain) {
            entries.push({
                domain: domain,
                age: Math.round((now - data.timestamp) / 1000),
                remaining: Math.round((data.ttl - (now - data.timestamp)) / 1000),
                status: data.result.deployed ? 'deployed' : 'not-deployed'
            });
        });
        return {
            totalEntries: this.cache.size,
            ttl: Math.round(this.defaultTTL / 1000),
            entries: entries
        };
    };

    // Initialize cache
    var deploymentCache = new DeploymentCache();

    // Global variable to store all certificates
    var allCertificates = [];

    // Async issuance lifecycle (redesign phase 3). A create submitted with
    // async:true returns 202 + a job id; we track each in-flight job here so the
    // table can show an optimistic "Issuing" row and poll the job to resolution.
    var pendingJobs = {};        // job_id -> { domain, provider, sanCount, state, error, errorCode, payload, domainsDisplay }
    var pendingPollTimers = {};  // job_id -> setTimeout handle

    // Filter and search certificates
    function filterCertificates() {
        var statusFilter = document.getElementById('statusFilter').value;

        // Ensure allCertificates is an array
        if (!Array.isArray(allCertificates)) {
            allCertificates = [];
        }

        var filteredCerts = allCertificates.filter(function (cert) {
            // Status filter (free-text search now lives in the ⌘K palette)
            var matchesStatus = true;
            if (statusFilter !== 'all') {
                var isExpired = cert.exists && cert.days_until_expiry !== null && cert.days_until_expiry !== undefined && cert.days_until_expiry <= 0;
                var isExpiringSoon = cert.exists && cert.days_until_expiry !== null && cert.days_until_expiry !== undefined && cert.days_until_expiry > 0 && cert.days_until_expiry <= 30;
                var isValid = cert.exists && cert.days_until_expiry !== null && cert.days_until_expiry !== undefined && cert.days_until_expiry > 30;

                switch (statusFilter) {
                    case 'valid':
                        matchesStatus = isValid;
                        break;
                    case 'expiring':
                        matchesStatus = isExpiringSoon;
                        break;
                    case 'expired':
                        matchesStatus = isExpired;
                        break;
                }
            }

            return matchesStatus;
        });

        displayCertificates(filteredCerts);
    }

    // Sorting state
    var currentSort = { field: 'domain', dir: 'asc' };

    function sortCertificates(field) {
        if (currentSort.field === field) {
            currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
        } else {
            currentSort.field = field;
            currentSort.dir = 'asc';
        }
        // Reset every sortable column's icon + aria-sort to neutral,
        // then mark the active column with both the right glyph and the
        // matching aria-sort value (B2). Browsers / screen readers use
        // aria-sort to announce "ascending" / "descending" — the visual
        // icon alone was inaccessible to non-sighted users.
        document.querySelectorAll('[id^="sort-icon-"]').forEach(function (icon) {
            icon.className = 'fas fa-sort ml-1 text-gray-400';
        });
        document.querySelectorAll('[id^="sort-th-"]').forEach(function (th) {
            th.setAttribute('aria-sort', 'none');
        });
        var activeIcon = document.getElementById('sort-icon-' + field);
        if (activeIcon) {
            activeIcon.className = 'fas fa-sort-' + (currentSort.dir === 'asc' ? 'up' : 'down') + ' ml-1 text-primary';
        }
        var activeTh = document.getElementById('sort-th-' + field);
        if (activeTh) {
            activeTh.setAttribute('aria-sort', currentSort.dir === 'asc' ? 'ascending' : 'descending');
        }
        filterCertificates();
    }

    function applySorting(certs) {
        var field = currentSort.field;
        var dir = currentSort.dir === 'asc' ? 1 : -1;
        return certs.slice().sort(function (a, b) {
            if (field === 'domain') return dir * a.domain.localeCompare(b.domain);
            if (field === 'status') return dir * ((a.days_until_expiry || 0) - (b.days_until_expiry || 0));
            if (field === 'expiry') return dir * ((a.days_until_expiry || 0) - (b.days_until_expiry || 0));
            if (field === 'provider') {
                var pa = (a.dns_provider || '').toLowerCase();
                var pb = (b.dns_provider || '').toLowerCase();
                if (pa !== pb) {
                    // Certs with no provider sort to the bottom regardless of direction.
                    if (!pa) return 1;
                    if (!pb) return -1;
                    return dir * pa.localeCompare(pb);
                }
                // Tiebreaker: within a provider group, order by expiry (most
                // overdue / soonest first), independent of the chosen direction.
                return (a.days_until_expiry || 0) - (b.days_until_expiry || 0);
            }
            return 0;
        });
    }

    // Per-cert auto-renew toggle button (issue #111).
    function autoRenewButtonHtml(safeDomain, autoRenewEnabled) {
        var icon = autoRenewEnabled ? 'fa-toggle-on' : 'fa-toggle-off';
        var color = autoRenewEnabled
            ? 'text-gray-400 hover:text-purple-600 dark:hover:text-purple-400'
            : 'text-amber-500 hover:text-amber-700 dark:text-amber-400 dark:hover:text-amber-300';
        var title = autoRenewEnabled ? 'Disable auto-renew' : 'Enable auto-renew';
        // safeDomain is already escapeHtml-ed by the caller (dashboard.js
        // L581). aria-label combines the action verb with the domain so
        // screen readers announce "Enable auto-renew foo.example.com"
        // instead of just "Enable auto-renew" repeated per row (B1 fix).
        return '<button type="button" data-action="toggle-auto-renew" data-domain="' + safeDomain +
            '" data-auto-renew="' + (autoRenewEnabled ? 'true' : 'false') + '" onclick="event.stopPropagation()" ' +
            'class="p-1.5 ' + color + ' rounded hover:bg-hover" ' +
            'title="' + title + '" aria-label="' + title + ' ' + safeDomain + '">' +
            '<i class="fas ' + icon + '" aria-hidden="true"></i></button>';
    }

    function deploymentStatusDisplay(role, result) {
        var isBrowser = role === 'browser';
        // "Server" (the probe ran from CertMate's server) vs "Browser" (from
        // your browser). Avoids reading "Backend: Unreachable" as "the CertMate
        // app is down" when it only means the target endpoint failed a probe.
        var roleLabel = isBrowser ? 'Browser' : 'Server';
        var roleIcon = isBrowser ? 'fa-globe' : 'fa-server';
        // chipClass: subtle surface + status-coloured foreground (the role icon
        // and the status glyph both inherit it). statusIcon: a small glyph that
        // encodes the state so it is not conveyed by colour alone (WCAG 1.4.1).
        var chipClass, statusIcon, statusText;

        if (isBrowser) {
            if (result && result.reachable) {
                chipClass = 'bg-success-surface text-success-fg'; statusIcon = 'fa-check'; statusText = 'Reachable';
            } else if (result && result.reachable === false) {
                chipClass = 'bg-danger-surface text-danger-fg'; statusIcon = 'fa-xmark'; statusText = 'Unreachable';
            } else {
                chipClass = 'bg-surface-2 text-muted'; statusIcon = 'fa-minus'; statusText = 'Not Checked';
            }
        } else {
            if (result && result.error === 'backend-unavailable') {
                chipClass = 'bg-surface-2 text-muted'; statusIcon = 'fa-exclamation'; statusText = 'Unavailable';
            } else if (result && result.deployed && result.certificate_match === true) {
                chipClass = 'bg-success-surface text-success-fg'; statusIcon = 'fa-check'; statusText = 'Deployed';
            } else if (result && result.reachable && result.certificate_match === false) {
                chipClass = 'bg-warning-surface text-warning-fg'; statusIcon = 'fa-triangle-exclamation'; statusText = 'Wrong Cert';
            } else if (result && result.reachable === false) {
                chipClass = 'bg-danger-surface text-danger-fg'; statusIcon = 'fa-xmark'; statusText = 'Unreachable';
            } else {
                chipClass = 'bg-surface-2 text-muted'; statusIcon = 'fa-minus'; statusText = 'Unknown';
            }
        }

        return {
            roleIcon: roleIcon,
            statusIcon: statusIcon,
            chipClass: chipClass,
            text: roleLabel + ': ' + statusText
        };
    }

    // Shared chip presentation so the initial render (deploymentBadgeHtml) and
    // the post-probe update (updateDeploymentUI) always produce identical
    // markup — otherwise the cell flips from icon chip to stale text after a
    // deployment check.
    function deploymentChipClass(display) {
        return 'inline-flex items-center gap-1 px-1.5 py-1 rounded-md ' + display.chipClass;
    }
    function deploymentChipInner(display) {
        return '<i class="fas ' + display.roleIcon + '" aria-hidden="true"></i>' +
            '<i class="fas ' + display.statusIcon + ' text-[0.65rem]" aria-hidden="true"></i>';
    }

    function deploymentBadgeHtml(role, result, safeDomain, domainId) {
        var display = deploymentStatusDisplay(role, result);
        var title = display.text;
        if (result && result.method) {
            title += ' via ' + result.method;
        }
        if (result && result.port) {
            title += ' :' + result.port;
        }
        if (result && result.protocol && result.protocol !== result.method) {
            title += ' (' + result.protocol + ')';
        }
        if (result && result.timestamp) {
            title += ' at ' + result.timestamp;
        }
        // Compact icon chip: role glyph + status glyph side by side. The full
        // "Role: Status …" string lives in title (tooltip) and aria-label, and
        // role="img" makes screen readers announce it as a single labelled unit.
        // No `id` here on purpose: this badge renders in up to three places per
        // domain (desktop cell, mobile meta, detail panel), so an id would be
        // duplicated (invalid HTML). The data-deployment-* attributes identify
        // it for updates; the deployed-count reads deploymentCache directly.
        return '<span data-deployment-domain="' + safeDomain + '" data-deployment-role="' + role + '" role="img"' +
            ' title="' + escapeHtml(title) + '" aria-label="' + escapeHtml(title) + '"' +
            ' class="' + deploymentChipClass(display) + '">' +
            deploymentChipInner(display) +
            '</span>';
    }

    // Build deployment status badges HTML — two compact icon chips (server,
    // browser) on a single horizontal row.
    function deploymentBadgesHtml(cert) {
        var safeDomain = escapeHtml(cert.domain);
        var domainId = safeDomain.replace(/\./g, '-');
        var cachedStatus = deploymentCache.get(cert.domain) || {};
        var browserStatus = cachedStatus.browser || null;
        return '<div class="flex items-center gap-1.5">' +
            deploymentBadgeHtml('backend', cachedStatus, safeDomain, domainId) +
            deploymentBadgeHtml('browser', browserStatus, safeDomain, domainId) +
            '</div>';
    }

    function providerDisplayName(provider) {
        var safeProvider = escapeHtml(provider || '');
        return safeProvider ? safeProvider.charAt(0).toUpperCase() + safeProvider.slice(1) : '';
    }

    // Provider label with its brand logo (or monogram) inline, shared by the
    // table Provider column and the detail modal. `label` must already be
    // escaped (providerDisplayName output). Returns '' when there's no label;
    // falls back to the bare label when no icon exists for the provider.
    function providerCellHtml(provider, label, wrapClass) {
        if (!label) return '';
        var icon = window.providerIconHtml
            ? window.providerIconHtml(provider, label, { sizeCls: 'h-4 w-4', textCls: 'text-[8px]' })
            : null;
        return '<span class="inline-flex items-center gap-1.5 ' + (wrapClass || '') + '">' +
            (icon || '') + '<span>' + label + '</span></span>';
    }

    function displayCertificates(certificates) {
        var container = document.getElementById('certificatesList');
        var thead = document.querySelector('#certificatesTable thead');

        if (!Array.isArray(certificates)) {
            certificates = [];
        }

        if (certificates.length === 0) {
            var isFiltered = document.getElementById('statusFilter').value !== 'all';
            thead.style.display = 'none';

            if (isFiltered) {
                container.innerHTML = '<tr data-empty-state><td colspan="6">' +
                    '<div class="px-6 py-12 text-center">' +
                    '<div class="mx-auto max-w-sm border-2 border-dashed border-border rounded-xl p-8">' +
                    '<div class="mx-auto h-16 w-16 flex items-center justify-center bg-surface-2 rounded-full mb-4">' +
                    '<i class="fas fa-search text-gray-400 text-2xl"></i>' +
                    '</div>' +
                    '<h3 class="text-lg font-medium text-foreground mb-2">No matching certificates</h3>' +
                    '<p class="text-muted mb-6">Try adjusting your search criteria or filters.</p>' +
                    '<button onclick="clearFilters()" class="inline-flex items-center px-4 py-2 border border-border shadow-sm text-sm font-medium rounded-md text-label bg-input hover:bg-gray-50 dark:hover:bg-gray-600">' +
                    '<i class="fas fa-times mr-2"></i>Clear Filters</button>' +
                    '</div>' +
                    '</div>' +
                    '</td></tr>';
            } else {
                container.innerHTML = '<tr data-empty-state><td colspan="6">' +
                    '<div class="px-6 py-8"><div class="mx-auto max-w-lg">' +
                    '<div class="text-center mb-6">' +
                    '<div class="mx-auto h-16 w-16 flex items-center justify-center bg-info-surface rounded-full mb-4"><i class="fas fa-rocket text-blue-500 text-2xl"></i></div>' +
                    '<h3 class="text-lg font-medium text-foreground mb-2">Welcome to CertMate</h3>' +
                    '<p class="text-muted">Follow these steps to get started:</p>' +
                    '</div>' +
                    '<ol class="space-y-3 mb-6 text-sm">' +
                    '<li class="flex items-start"><span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-500 text-white rounded-full text-xs font-bold mr-3 mt-0.5">1</span>' +
                    '<span class="text-label"><a href="/settings" class="text-info-fg font-medium hover:underline">Go to Settings</a> and configure your DNS provider</span></li>' +
                    '<li class="flex items-start"><span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-500 text-white rounded-full text-xs font-bold mr-3 mt-0.5">2</span>' +
                    '<span class="text-label">Add a domain above and create your first SSL certificate</span></li>' +
                    '<li class="flex items-start"><span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-500 text-white rounded-full text-xs font-bold mr-3 mt-0.5">3</span>' +
                    '<span class="text-label">Enable <a href="/settings#users" class="text-info-fg font-medium hover:underline">Local Authentication</a> in Settings to secure your instance</span></li>' +
                    '</ol>' +
                    '<div class="bg-warning-surface border border-warning-line rounded-lg p-3 mb-6">' +
                    '<p class="text-xs text-warning-strong"><i class="fas fa-shield-alt mr-1"></i><strong>Security:</strong> Authentication is disabled by default. Enable it before exposing CertMate to the internet.</p>' +
                    '</div>' +
                    '<div class="text-center"><button type="button" onclick="openCreateCertForm()" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary hover:bg-secondary"><i class="fas fa-plus mr-2"></i>Create Certificate</button></div>' +
                    '</div></div>' +
                    '</td></tr>';
            }
            renderPendingRows();
            return;
        }

        thead.style.display = '';
        var sorted = applySorting(certificates);

        var rowHtml = CertMate.html;
        var rowRaw = CertMate.raw;

        // Action button shorthand. cert.domain flows in raw \u2014 the helper
        // escapes it for both the data-domain attribute and the onclick
        // arg, so we no longer pre-compute a `safeDomain`.
        // The aria-label is `${title} ${domain}` so screen readers
        // announce both the action and which row it targets \u2014 without
        // it, the actions column reads as "Renew, Force renew, Download,
        // API, Auto-renew, Delete" with no domain context, repeated for
        // every row in the table (B1 fix).
        function actionBtn(action, domain, hoverColor, title, icon) {
            return rowRaw(rowHtml`<button type="button" data-action="${action}" data-domain="${domain}" onclick="event.stopPropagation()" class="inline-flex items-center justify-center p-2 text-gray-500 dark:text-gray-300 hover:text-${rowRaw(hoverColor)}-600 dark:hover:text-${rowRaw(hoverColor)}-400 rounded hover:bg-hover" title="${title}" aria-label="${title} ${domain}"><i class="fas ${rowRaw(icon)}" aria-hidden="true"></i></button>`);
        }

        container.innerHTML = sorted.map(function (cert, i) {
            // providerDisplayName(...) already calls escapeHtml internally —
            // when interpolating into the rowHtml template we wrap it with
            // rowRaw() to opt out of re-escaping. cert.domain and
            // cert.domain_alias flow in unescaped; the helper escapes them.
            var providerLabel = providerDisplayName(cert.dns_provider);
            var domainAlias = cert.domain_alias || '';

            if (!cert.exists) {
                return rowHtml`<tr data-row-domain="${cert.domain}" class="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer" tabindex="0" role="button" aria-label="View details for ${cert.domain}" onclick="openCertDetail('${cert.domain}')" onkeydown="certRowKey(event, '${cert.domain}')">
                    <td class="px-6 py-4 md:max-w-0"><div class="text-sm font-medium text-foreground break-words md:truncate">${cert.domain}</div></td>
                    <td class="px-4 py-4 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-danger-fg ring-1 ring-inset ring-red-500/20"><i class="fas fa-times-circle mr-1"></i>Not Found</span></td>
                    <td class="px-4 py-4 whitespace-nowrap hidden md:table-cell text-sm text-muted">\u2014</td>
                    <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-muted">${providerLabel ? rowRaw(providerCellHtml(cert.dns_provider, providerLabel)) : '\u2014'}</td>
                    <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell">\u2014</td>
                    <td class="px-4 py-4 whitespace-nowrap text-right">
                        <div class="flex items-center justify-end gap-1">
                            ${roleAtLeast('admin') ? actionBtn('delete', cert.domain, 'red', 'Remove from list', 'fa-trash-alt') : false}
                        </div>
                    </td>
                </tr>`;
            }

            var daysKnown = cert.days_until_expiry !== null && cert.days_until_expiry !== undefined;
            var isExpired = daysKnown && cert.days_until_expiry <= 0;
            var isExpiringSoon = daysKnown && cert.days_until_expiry > 0 && cert.days_until_expiry <= 30;
            var statusClass, statusIcon, statusText, healthClass;
            if (isExpired) {
                statusClass = 'bg-red-500/10 text-danger-fg ring-1 ring-inset ring-red-500/20'; statusIcon = 'fa-times-circle'; statusText = 'Expired'; healthClass = 'health-expired';
            } else if (isExpiringSoon) {
                statusClass = 'bg-yellow-500/10 text-warning-fg ring-1 ring-inset ring-yellow-500/20'; statusIcon = 'fa-exclamation-triangle'; statusText = 'Expiring'; healthClass = 'health-warning';
            } else {
                statusClass = 'bg-green-500/10 text-success-fg ring-1 ring-inset ring-green-500/20'; statusIcon = 'fa-check-circle'; statusText = 'Valid'; healthClass = 'health-valid';
            }

            var expiryDate = new Date(cert.expiry_date);
            var expiryStr = expiryDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            // The day counter is the focal value (large, status-coloured); the
            // absolute date drops to a smaller secondary line. Status colour is
            // carried onto the counter itself — green for healthy so the colour
            // encodes the state, not just the expired/expiring alarm cases.
            var daysClass = isExpired ? 'text-danger-fg' : isExpiringSoon ? 'text-warning-fg' : 'text-success-fg';
            var absDays = Math.abs(cert.days_until_expiry);
            var daysText = isExpired
                ? absDays + (absDays === 1 ? ' day ago' : ' days ago')
                : cert.days_until_expiry + (cert.days_until_expiry === 1 ? ' day left' : ' days left');

            // Inline subtle glyph instead of a rounded blue panel — the
            // rounded panel read like an interactive control to users
            // (issue #100) but it had no handler. The whole row is the
            // affordance for opening the detail panel.
            //
            // Role-aware controls: hide buttons the user would just 403 on.
            // Server still enforces; this is UX-only.
            //
            // deploymentBadgeHtml + autoRenewButtonHtml return pre-built HTML
            // strings whose inputs are already escaped, so we wrap with raw().
            //
            // Domain alias indicator (#122): when cert.domain_alias is set,
            // render a small "Alias: …" hint under the domain name so users
            // can spot rows that go through the CNAME-delegation flow.
            var aliasHint = domainAlias
                ? rowRaw(rowHtml`<div class="mt-1 flex items-center text-xs text-info-fg min-w-0"><i class="fas fa-link mr-1 text-blue-500 shrink-0" aria-hidden="true"></i><span class="truncate" title="${domainAlias}">DNS-01 Alias: ${domainAlias}</span></div>`)
                : false;
            // R-5 mobile card layout: surface the three desktop-only columns
            // (Expires / Provider / Deployment) as stacked rows inside the
            // Domain cell when below md (768 px). The table semantics are
            // preserved — the dedicated columns still render at md+ via
            // their `hidden md:table-cell` / `hidden lg:table-cell` rules,
            // so we never double-render on tablet+. The border-top on the
            // wrapper gives a visual seam between the domain identity and
            // the meta block, reading as a card on phones without breaking
            // the table on bigger screens.
            var mobileExpiryLine = (daysKnown && cert.expiry_date)
                ? rowRaw(rowHtml`<div class="md:hidden flex items-center text-xs"><i class="fas fa-clock mr-1.5 w-3 shrink-0 text-muted" aria-hidden="true"></i><span><span class="font-semibold ${rowRaw(daysClass)}">${daysText}</span><span class="text-muted"> · ${expiryStr}</span></span></div>`)
                : false;
            var mobileProviderLine = providerLabel
                ? rowRaw(rowHtml`<div class="flex items-center text-xs text-muted">${rowRaw(providerCellHtml(cert.dns_provider, providerLabel))}</div>`)
                : false;
            var mobileDeploymentLine = rowRaw(rowHtml`<div class="flex items-start text-xs text-muted"><i class="fas fa-rocket mr-1.5 mt-0.5 w-3 shrink-0" aria-hidden="true"></i><div class="flex-1 min-w-0">${rowRaw(deploymentBadgesHtml(cert))}</div></div>`);
            var mobileMeta = rowRaw(rowHtml`<div class="lg:hidden mt-2 pt-2 border-t border-gray-100 dark:border-gray-700/50 space-y-1">${mobileExpiryLine}${mobileProviderLine}${mobileDeploymentLine}</div>`);
            var lockColor = isExpired ? 'text-red-400' : isExpiringSoon ? 'text-yellow-400' : 'text-green-500';
            // An expired cert is no longer trusted; a closed padlock (the
            // "secure connection" glyph) is a visual paradox there. Show an
            // open padlock for expired so the icon matches the state.
            var lockIcon = isExpired ? 'fa-lock-open' : 'fa-lock';
            return rowHtml`<tr data-row-domain="${cert.domain}" class="${rowRaw(healthClass)} row-enter hover:bg-blue-50/40 dark:hover:bg-blue-900/10 transition-colors duration-150 cursor-pointer" style="animation-delay:${rowRaw(String(i * 30))}ms" tabindex="0" role="button" aria-label="View details for ${cert.domain}" onclick="openCertDetail('${cert.domain}')" onkeydown="certRowKey(event, '${cert.domain}')">
                <td class="px-6 py-4 md:max-w-0">
                    <div class="flex items-center min-w-0">
                        <i class="fas ${rowRaw(lockIcon)} ${rowRaw(lockColor)} mr-2 text-sm shrink-0" aria-hidden="true"></i>
                        <div class="min-w-0">
                            <div class="text-sm font-medium text-foreground break-words md:truncate">${cert.domain}</div>
                            ${aliasHint}
                            ${mobileMeta}
                        </div>
                    </div>
                </td>
                <td class="px-4 py-4 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${rowRaw(statusClass)}"><i class="fas ${rowRaw(statusIcon)} mr-1"></i>${statusText}</span></td>
                <td class="px-4 py-4 whitespace-nowrap hidden md:table-cell"><div class="text-sm font-semibold ${rowRaw(daysClass)}">${daysText}</div><div class="text-xs text-muted mt-0.5">${expiryStr}</div></td>
                <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-muted">${providerLabel ? rowRaw(providerCellHtml(cert.dns_provider, providerLabel)) : '—'}</td>
                <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell">${rowRaw(deploymentBadgesHtml(cert))}</td>
                <td class="px-4 py-4 whitespace-nowrap text-right">
                    <div class="flex items-center justify-end gap-1">
                        ${roleAtLeast('operator') ? actionBtn('renew', cert.domain, 'green', 'Renew', 'fa-sync-alt') : false}
                        ${actionBtn('download', cert.domain, 'blue', 'Download', 'fa-download')}
                        ${rowRaw('<button type="button" data-more-domain="' + escapeHtml(cert.domain) + '" data-autorenew="' + (cert.auto_renew !== false ? 'true' : 'false') + '" data-op="' + (roleAtLeast('operator') ? '1' : '0') + '" data-admin="' + (roleAtLeast('admin') ? '1' : '0') + '" onclick="event.stopPropagation()" class="inline-flex items-center justify-center p-2 text-gray-500 dark:text-gray-300 hover:text-gray-700 dark:hover:text-gray-100 rounded hover:bg-hover" title="More actions" aria-label="More actions for ' + escapeHtml(cert.domain) + '" aria-haspopup="menu"><i class="fas fa-ellipsis-vertical" aria-hidden="true"></i></button>')}
                    </div>
                </td>
            </tr>`;
        }).join('');

        // Attach event listeners for cert action buttons
        container.querySelectorAll('button[data-action]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var domain = btn.dataset.domain;
                switch (btn.dataset.action) {
                    case 'renew': renewCertificate(domain); break;
                    case 'force-renew': renewCertificate(domain, true); break;
                    case 'download': downloadCertificate(domain); break;
                    case 'curl': copyCurlCommand(domain); break;
                    case 'toggle-auto-renew':
                        toggleAutoRenew(domain, btn.dataset.autoRenew === 'true');
                        break;
                    case 'delete': deleteCertificate(domain); break;
                }
            });
        });

        // "More actions" overflow menu (force-renew, API, auto-renew, delete).
        container.querySelectorAll('button[data-more-domain]').forEach(function (btn) {
            btn.addEventListener('click', function (e) { e.stopPropagation(); openRowMenu(btn); });
        });

        // Automatic deployment checks are triggered once, from loadCertificates(),
        // via runDeploymentChecks() — batched and deduped. We intentionally do NOT
        // fire a second (unbatched) pass here.

        // Re-attach any optimistic Issuing/Failed rows on top: a full rebuild
        // here (loadCertificates or a filter pass) would otherwise drop them.
        renderPendingRows();
    }

    // Row "More actions" overflow menu. Secondary cert actions live here so the
    // row shows only the daily-use Renew + Download inline. Appended to <body>
    // (position:fixed) so the table's overflow-hidden / overflow-x-auto wrappers
    // don't clip it.
    var _rowMenu = null;
    function closeRowMenu() {
        if (!_rowMenu) return;
        _rowMenu.remove();
        _rowMenu = null;
        document.removeEventListener('click', _rowMenuAway, true);
        document.removeEventListener('keydown', _rowMenuKey, true);
    }
    function _rowMenuAway(e) {
        if (_rowMenu && !_rowMenu.contains(e.target) && !e.target.closest('[data-more-domain]')) closeRowMenu();
    }
    function _rowMenuKey(e) { if (e.key === 'Escape') closeRowMenu(); }
    function _menuItem(icon, label, danger) {
        return '<button type="button" role="menuitem" class="w-full flex items-center gap-2 px-3 py-2 text-left ' +
            (danger ? 'text-danger-fg hover:bg-red-50 dark:hover:bg-red-900/20' : 'text-foreground hover:bg-hover') +
            '"><i class="fas ' + icon + ' w-4 ' + (danger ? '' : 'text-muted') + '" aria-hidden="true"></i>' + label + '</button>';
    }
    function openRowMenu(btn) {
        closeRowMenu();
        var domain = btn.getAttribute('data-more-domain');
        var autoOn = btn.getAttribute('data-autorenew') === 'true';
        var isOp = btn.getAttribute('data-op') === '1';
        var isAdmin = btn.getAttribute('data-admin') === '1';
        var actions = [];
        if (isOp) actions.push({ html: _menuItem('fa-bolt', 'Force renew'), fn: function () { renewCertificate(domain, true); } });
        actions.push({ html: _menuItem('fa-code', 'Copy API command'), fn: function () { copyCurlCommand(domain); } });
        if (isOp) actions.push({ html: _menuItem(autoOn ? 'fa-toggle-on' : 'fa-toggle-off', autoOn ? 'Disable auto-renew' : 'Enable auto-renew'), fn: function () { toggleAutoRenew(domain, autoOn); } });
        if (isAdmin) actions.push({ html: '<div class="my-1 border-t border-border"></div>' + _menuItem('fa-trash-can', 'Delete certificate', true), fn: function () { deleteCertificate(domain); } });
        if (!actions.length) return;
        var menu = document.createElement('div');
        menu.className = 'fixed w-52 py-1 bg-surface border border-border rounded-lg shadow-xl text-sm';
        menu.style.zIndex = '60';
        menu.setAttribute('role', 'menu');
        menu.innerHTML = actions.map(function (a) { return a.html; }).join('');
        document.body.appendChild(menu);
        var r = btn.getBoundingClientRect();
        var top = r.bottom + 4;
        var left = r.right - menu.offsetWidth;
        if (top + menu.offsetHeight > window.innerHeight - 8) top = Math.max(8, r.top - menu.offsetHeight - 4);
        if (left < 8) left = 8;
        menu.style.top = top + 'px';
        menu.style.left = left + 'px';
        var items = menu.querySelectorAll('button[role="menuitem"]');
        items.forEach(function (b, i) {
            b.addEventListener('click', function () { closeRowMenu(); actions[i].fn(); });
        });
        _rowMenu = menu;
        setTimeout(function () {
            document.addEventListener('click', _rowMenuAway, true);
            document.addEventListener('keydown', _rowMenuKey, true);
        }, 0);
        if (items[0]) items[0].focus();
    }

    // Certificate detail slide-out panel
    // B3: skeleton mirror of the detail panel layout. Shown briefly while
    // the panel slides in, so the user never sees an empty card or the
    // previous cert's contents while the new HTML is rendering. Mirrors
    // the populated structure (status block, expiry box, action list).
    function certDetailSkeletonHtml() {
        return '<div class="space-y-6 animate-pulse" aria-hidden="true">' +
            // Status block
            '<div class="space-y-2">' +
                '<div class="skeleton h-3 w-16"></div>' +
                '<div class="skeleton h-6 w-32"></div>' +
            '</div>' +
            // Definition list (Issuer, SANs, Provider, …)
            '<div class="space-y-3">' +
                '<div class="flex justify-between"><div class="skeleton h-3 w-20"></div><div class="skeleton h-3 w-36"></div></div>' +
                '<div class="flex justify-between"><div class="skeleton h-3 w-16"></div><div class="skeleton h-3 w-40"></div></div>' +
                '<div class="flex justify-between"><div class="skeleton h-3 w-24"></div><div class="skeleton h-3 w-32"></div></div>' +
                '<div class="flex justify-between"><div class="skeleton h-3 w-20"></div><div class="skeleton h-3 w-28"></div></div>' +
            '</div>' +
            // Action buttons stack
            '<div class="space-y-2 pt-4">' +
                '<div class="skeleton h-9 w-full rounded-md"></div>' +
                '<div class="skeleton h-9 w-full rounded-md"></div>' +
                '<div class="skeleton h-9 w-full rounded-md"></div>' +
            '</div>' +
        '</div>';
    }

    // Keyboard activation for the clickable certificate rows: Enter or Space
    // opens the detail panel, matching the row's onclick. Space is prevented
    // from scrolling the page.
    function certRowKey(event, domain) {
        if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
            event.preventDefault();
            openCertDetail(domain);
        }
    }

    // Element focused before the detail modal opened, so focus can be
    // restored to the triggering row when it closes.
    var _lastDetailFocus = null;

    // Inline auto-renew toggle for the detail modal (replaces the old text row +
    // separate "Disable Auto-Renew" button). role="switch" for a11y; the click
    // routes through toggleAutoRenew, which confirms, persists, and reloads.
    function autoRenewSwitchHtml(domain, on) {
        return '<button type="button" role="switch" aria-checked="' + (on ? 'true' : 'false') + '" ' +
            'aria-label="Auto-renew" title="' + (on ? 'Auto-renew on — click to disable' : 'Auto-renew off — click to enable') + '" ' +
            'onclick="toggleAutoRenew(\'' + domain + '\', ' + (on ? 'true' : 'false') + ')" ' +
            'class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 ' + (on ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600') + '">' +
            '<span class="inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ' + (on ? 'translate-x-5' : 'translate-x-1') + '"></span>' +
            '</button>';
    }

    // Copy the detail modal's domain (the header value) to the clipboard.
    window.copyDetailDomain = function () {
        var el = document.getElementById('detailDomain');
        if (!el || !navigator.clipboard) return;
        navigator.clipboard.writeText(el.textContent.trim()).then(function () {
            if (CertMate.toast) CertMate.toast('Domain copied to clipboard', 'info');
        });
    };

    function openCertDetail(domain) {
        var cert = allCertificates.find(function (c) { return c.domain === domain; });
        if (!cert) return;

        var panel = document.getElementById('certDetailPanel');
        var overlay = document.getElementById('certDetailOverlay');
        var content = document.getElementById('certDetailContent');
        document.getElementById('detailDomain').textContent = cert.domain;
        // Paint skeleton placeholders before the real content lands. Without
        // this, opening cert B right after closing cert A briefly showed A's
        // stale HTML, and on slow devices the panel could slide in over an
        // empty white card. The skeleton matches the populated layout so the
        // transition reads as "loading detail" rather than "broken".
        content.innerHTML = certDetailSkeletonHtml();

        var safeDomain = escapeHtml(cert.domain);
        var providerLabel = providerDisplayName(cert.dns_provider);
        var safeDomainAlias = escapeHtml(cert.domain_alias || '');
        var aliasProviderLabel = providerDisplayName(cert.alias_dns_provider);
        var sanDomains = Array.isArray(cert.san_domains) ? cert.san_domains : [];
        var sanDomainsHtml = sanDomains.map(function (san) {
            return '<div class="break-all">' + escapeHtml(san) + '</div>';
        }).join('');

        // Provider cells render the brand logo (or monogram) inline next to the
        // name (right-aligned in the detail grid), matching the table column
        // and DNS selector for consistency.
        var providerCell = providerCellHtml(cert.dns_provider, providerLabel, 'justify-end');
        var aliasProviderCell = providerCellHtml(cert.alias_dns_provider, aliasProviderLabel, 'justify-end');

        if (!cert.exists) {
            content.innerHTML = '<div class="text-center py-8"><i class="fas fa-exclamation-triangle text-red-400 text-3xl mb-3"></i>' +
                '<p class="text-muted mb-6">Certificate not found on disk.</p>' +
                (roleAtLeast('admin')
                    ? '<button type="button" onclick="deleteCertificate(\'' + safeDomain + '\')" class="inline-flex items-center px-4 py-2 border border-danger-line shadow-sm text-sm font-medium rounded-md text-danger-fg bg-danger-surface hover:bg-red-100 dark:hover:bg-red-900/40"><i class="fas fa-trash-alt mr-2"></i>Remove from List</button>'
                    : '<p class="text-xs text-gray-400">Ask an admin to remove this entry.</p>') +
                '</div>';
        } else {
            var daysKnown2 = cert.days_until_expiry !== null && cert.days_until_expiry !== undefined;
            var isExpired = daysKnown2 && cert.days_until_expiry <= 0;
            var isExpiringSoon = daysKnown2 && cert.days_until_expiry > 0 && cert.days_until_expiry <= 30;
            var expiryDate = new Date(cert.expiry_date);
            var statusClass, statusText;
            if (isExpired) { statusClass = 'text-danger-fg'; statusText = 'Expired'; }
            else if (isExpiringSoon) { statusClass = 'text-warning-fg'; statusText = 'Expiring Soon'; }
            else { statusClass = 'text-success-fg'; statusText = 'Valid'; }

            var absDays = Math.abs(cert.days_until_expiry);
            var daysText = isExpired
                ? absDays + (absDays === 1 ? ' day ago' : ' days ago')
                : cert.days_until_expiry + (cert.days_until_expiry === 1 ? ' day left' : ' days left');
            var expiryStr = expiryDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            var bannerBg = isExpired ? 'bg-danger-surface' : isExpiringSoon ? 'bg-warning-surface' : 'bg-success-surface';
            var bannerIcon = isExpired ? 'fa-circle-xmark' : isExpiringSoon ? 'fa-triangle-exclamation' : 'fa-circle-check';
            var autoOn = cert.auto_renew !== false;

            // Quick-action icon button — same glyphs as the dashboard table row
            // actions so the action vocabulary reads identically everywhere; the
            // label lives in the tooltip + aria-label.
            function actIcon(onclick, icon, hover, title) {
                return '<button type="button" onclick="' + onclick + '" title="' + title + '" aria-label="' + title + '" ' +
                    'class="inline-flex items-center justify-center w-10 h-10 rounded-lg border border-border bg-input text-muted hover:text-' + hover + '-600 dark:hover:text-' + hover + '-400 hover:bg-hover hover:border-border-strong transition">' +
                    '<i class="fas ' + icon + '"></i></button>';
            }
            function detailRow(label, valueHtml) {
                return '<div class="flex items-center justify-between gap-4 py-2.5"><dt class="text-sm text-muted flex-shrink-0">' + label + '</dt>' +
                    '<dd class="text-sm font-medium text-right text-foreground min-w-0">' + valueHtml + '</dd></div>';
            }

            content.innerHTML =
                '<div class="space-y-5">' +
                // Status banner: status word + days + date, integrated and at one
                // weight (the day count and the calendar date are the same datum).
                '<div class="flex items-center gap-3 p-4 rounded-lg ' + bannerBg + '">' +
                '<i class="fas ' + bannerIcon + ' text-2xl ' + statusClass + ' flex-shrink-0"></i>' +
                '<div class="min-w-0">' +
                '<div class="text-lg font-semibold ' + statusClass + '">' + statusText + (daysKnown2 ? ' · ' + daysText : '') + '</div>' +
                (cert.expiry_date ? '<div class="text-sm ' + statusClass + ' opacity-80">' + (isExpired ? 'Expired ' : 'Expires ') + expiryStr + '</div>' : '') +
                '</div>' +
                '</div>' +
                // Details
                '<dl class="divide-y divide-border">' +
                (providerLabel ? detailRow('DNS Provider', providerCell) : '') +
                (sanDomains.length ? detailRow('SANs', '<div class="text-right">' + sanDomainsHtml + '</div>') : '') +
                (safeDomainAlias ? detailRow('DNS-01 Alias', '<span class="break-all text-info-fg">' + safeDomainAlias + '</span>') : '') +
                (safeDomainAlias && aliasProviderLabel ? detailRow('Alias Provider', aliasProviderCell) : '') +
                detailRow('Auto-Renew', roleAtLeast('operator')
                    ? autoRenewSwitchHtml(safeDomain, autoOn)
                    : '<span class="' + (autoOn ? 'text-success-fg' : 'text-warning-fg') + '">' + (autoOn ? 'Enabled' : 'Disabled') + '</span>') +
                '</dl>' +
                // Deployment — its own section, separated by a rule.
                '<div class="pt-4 border-t border-border">' +
                '<div class="flex items-center justify-between mb-3">' +
                '<h4 class="text-xs font-semibold text-muted uppercase tracking-wider">Deployment</h4>' +
                '<button type="button" onclick="checkDeploymentStatus(\'' + safeDomain + '\', this, true)" title="Check deployment now" aria-label="Check deployment now" class="inline-flex items-center justify-center w-8 h-8 rounded-lg text-muted hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-hover transition"><i class="fas fa-arrows-rotate text-sm"></i></button>' +
                '</div>' +
                '<div class="flex items-center gap-2 mb-3">' + deploymentBadgesHtml(cert) + '</div>' +
                '<div class="flex items-center justify-between gap-2 rounded-lg bg-surface-2 px-3 py-2">' +
                '<span class="text-sm text-muted min-w-0 truncate"><i class="fas fa-rocket mr-1.5 text-green-500"></i>Deploy hooks</span>' +
                '<div class="flex items-center gap-1 flex-shrink-0">' +
                '<a href="/settings#deploy" title="View / edit deploy hooks in Settings" aria-label="View or edit deploy hooks" class="inline-flex items-center justify-center w-8 h-8 rounded-lg text-muted hover:text-blue-600 dark:hover:text-blue-400 hover:bg-hover transition"><i class="fas fa-pen-to-square text-sm"></i></a>' +
                (roleAtLeast('admin') ? '<button type="button" onclick="runDeployHooks(\'' + safeDomain + '\')" title="Run deploy hooks now" aria-label="Run deploy hooks now" class="inline-flex items-center justify-center w-8 h-8 rounded-lg text-muted hover:text-green-600 dark:hover:text-green-400 hover:bg-hover transition"><i class="fas fa-play text-sm"></i></button>' : '') +
                '</div>' +
                '</div>' +
                (safeDomainAlias ? '<button type="button" onclick="checkDnsAliasForCertificate(\'' + safeDomain + '\')" class="mt-2 w-full inline-flex items-center justify-center px-3 py-1.5 text-xs border border-info-line rounded-lg text-info-fg bg-info-surface hover:bg-blue-100 dark:hover:bg-blue-900/50"><i class="fas fa-search mr-1.5"></i>Check DNS-01 Alias</button>' : '') +
                '<div id="cert_dns_alias_check_result" class="hidden mt-2"></div>' +
                '</div>' +
                // Quick actions — consistent icons (label on hover), separated.
                '<div class="pt-4 border-t border-border">' +
                '<h4 class="text-xs font-semibold text-muted uppercase tracking-wider mb-3">Actions</h4>' +
                '<div class="flex flex-wrap items-center gap-2">' +
                (roleAtLeast('operator')
                    ? actIcon("renewCertificate('" + safeDomain + "')", 'fa-sync-alt', 'green', 'Renew certificate') +
                      actIcon("renewCertificate('" + safeDomain + "', true)", 'fa-bolt', 'amber', 'Force renew') +
                      actIcon("startEditReissue('" + safeDomain + "')", 'fa-pen', 'blue', 'Edit & reissue')
                    : '') +
                actIcon("downloadCertificate('" + safeDomain + "')", 'fa-download', 'blue', 'Download certificate') +
                actIcon("copyCurlCommand('" + safeDomain + "')", 'fa-code', 'indigo', 'Show API command') +
                (roleAtLeast('admin')
                    ? '<span class="flex-grow"></span>' + actIcon("deleteCertificate('" + safeDomain + "')", 'fa-trash-alt', 'red', 'Delete certificate')
                    : '') +
                '</div>' +
                '</div>' +
                '</div>';
        }

        // Reveal the backdrop and modal, then animate the card in (scale +
        // fade) on the next frame so the transition actually plays. Focus moves
        // to the close button and is restored to the triggering row on close.
        _lastDetailFocus = document.activeElement;
        overlay.classList.remove('hidden');
        panel.classList.remove('hidden');
        panel.classList.add('flex');
        CertMate.lockScroll();
        var card = document.getElementById('certDetailCard');
        requestAnimationFrame(function () {
            if (card) card.classList.remove('opacity-0', 'scale-95');
        });
        var closeBtn = panel.querySelector('[data-detail-close]');
        if (closeBtn) closeBtn.focus();
    }

    function closeCertDetail() {
        var panel = document.getElementById('certDetailPanel');
        if (!panel || panel.classList.contains('hidden')) return;
        CertMate.unlockScroll();
        var overlay = document.getElementById('certDetailOverlay');
        var content = document.getElementById('certDetailContent');
        var card = document.getElementById('certDetailCard');
        if (card) card.classList.add('opacity-0', 'scale-95');
        setTimeout(function () {
            overlay.classList.add('hidden');
            panel.classList.add('hidden');
            panel.classList.remove('flex');
            // Clear after the close transition so the next open starts from a
            // blank surface — prevents the previous cert's details from
            // flashing visible for a frame when opening cert B right after
            // closing cert A.
            if (content) content.innerHTML = '';
        }, 200);
        if (_lastDetailFocus && _lastDetailFocus.focus) _lastDetailFocus.focus();
    }

    // Close detail modal on Escape key
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeCertDetail();
    });

    // Debug console functions
    function toggleDebugConsole() {
        var el = document.getElementById('debugConsole');
        el.classList.toggle('hidden');
    }

    function clearDebugConsole() {
        document.getElementById('debugOutput').innerHTML = '<div class="text-gray-500">Debug console cleared. Click "Check All" to see deployment check logs...</div>';
    }

    function addDebugLog(message, type) {
        type = type || 'info';
        var output = document.getElementById('debugOutput');
        var timestamp = new Date().toLocaleTimeString();
        var colors = {
            info: 'text-green-400',
            warn: 'text-yellow-400',
            error: 'text-red-400',
            success: 'text-blue-400'
        };

        var logEntry = document.createElement('div');
        logEntry.className = (colors[type] || colors.info) + ' mb-1';
        var timeSpan = document.createElement('span');
        timeSpan.className = 'text-gray-500';
        timeSpan.textContent = '[' + timestamp + ']';
        logEntry.appendChild(timeSpan);
        logEntry.appendChild(document.createTextNode(' ' + message));

        output.appendChild(logEntry);
        output.scrollTop = output.scrollHeight;

        // Keep only last 100 entries
        while (output.children.length > 100) {
            output.removeChild(output.firstChild);
        }
    }

    // Cache management functions
    function showCacheStats() {
        var stats = deploymentCache.getStatus();
        var ttlMinutes = Math.round(stats.ttl / 60);
        var ttlHours = Math.round(stats.ttl / 3600);

        var ttlDisplay = stats.ttl + 's';
        if (ttlHours >= 1) {
            ttlDisplay = ttlHours + 'h';
        } else if (ttlMinutes >= 1) {
            ttlDisplay = ttlMinutes + 'm';
        }

        addDebugLog('=== CACHE STATISTICS ===', 'info');
        addDebugLog('Total entries: ' + stats.totalEntries, 'info');
        addDebugLog('TTL: ' + ttlDisplay + ' (' + stats.ttl + ' seconds)', 'info');

        if (stats.entries.length > 0) {
            addDebugLog('Recent entries:', 'info');
            stats.entries.slice(0, 5).forEach(function (entry) {
                addDebugLog('  ' + entry.domain + ': ' + entry.status + ' (' + entry.remaining + 's remaining)', 'info');
            });
            if (stats.entries.length > 5) {
                addDebugLog('  ... and ' + (stats.entries.length - 5) + ' more entries', 'info');
            }
        } else {
            addDebugLog('No cached entries', 'warn');
        }
        addDebugLog('========================', 'info');
    }

    function invalidateAllCache() {
        CertMate.confirm('Clear all cached deployment status data? This will force a fresh check for all certificates.', 'Clear Cache', { danger: false }).then(function (confirmed) {
            if (!confirmed) return;
            deploymentCache.clear();
            addDebugLog('All cache entries cleared by user request', 'warn');
            updateCacheInfo();

            // Ensure allCertificates is an array before checking
            if (Array.isArray(allCertificates) && allCertificates.length > 0) {
                addDebugLog('Re-checking all certificates after cache clear...', 'info');
                setTimeout(function () {
                    var existingCerts = allCertificates.filter(function (cert) { return cert.exists; });
                    existingCerts.forEach(function (cert) { checkDeploymentStatus(cert.domain); });
                }, 1000);
            }
        });
    }

    function updateCacheInfo() {
        var stats = deploymentCache.getStatus();
        var ttlMinutes = Math.round(stats.ttl / 60);
        var infoElement = document.getElementById('debug-cache-info');

        if (infoElement) {
            var ttlDisplay = stats.ttl + 's';
            if (ttlMinutes >= 1) {
                ttlDisplay = ttlMinutes + 'm';
            }
            infoElement.textContent = stats.totalEntries + ' entries, TTL ' + ttlDisplay;
        }
    }

    // Update cache info periodically
    setInterval(updateCacheInfo, 10000);

    // Update deployment statistics with better counting
    function updateDeploymentStats() {
        // Ensure allCertificates is an array
        if (!Array.isArray(allCertificates)) {
            allCertificates = [];
        }

        var deployedCount = allCertificates.filter(function (cert) {
            if (!cert.exists) return false;
            // Read the authoritative backend verdict straight from the cache the
            // badges themselves render from, rather than scraping badge text from
            // the DOM (#324). This mirrors deploymentStatusDisplay's "Deployed"
            // condition for the backend role and avoids depending on a DOM id
            // (the badge renders in up to three places, so an id can't be unique).
            var cached = deploymentCache.get(cert.domain);
            return !!(cached && cached.deployed && cached.certificate_match === true);
        }).length;

        var deploymentCountElement = document.getElementById('deploymentCount');
        if (deploymentCountElement) {
            deploymentCountElement.textContent = deployedCount;
        }

        addDebugLog('Statistics updated: ' + deployedCount + ' certificates actively deployed', 'success');
    }

    // Run deployment-status checks for a list of certs in small batches (3 at a
    // time) so we never open more than that many parallel requests at once
    // (browsers cap ~6 connections/host on HTTP/1.1). Pauses 500ms between
    // batches and calls updateDeploymentStats() once everything settles. Cached
    // certs are still skipped inside checkDeploymentStatus(). Returns a Promise
    // that resolves when all batches are done.
    //
    // options.onProgress(completed, total) — optional, called after each cert
    // settles (resolve OR reject), used by the manual "Check all" button to
    // render live progress.
    function runDeploymentChecks(certs, options) {
        options = options || {};
        var onProgress = options.onProgress;

        if (!Array.isArray(certs) || certs.length === 0) {
            return Promise.resolve();
        }

        var completed = 0;
        var total = certs.length;

        function reportProgress() {
            completed++;
            if (onProgress) {
                onProgress(completed, total);
            }
        }

        // Check certificates in batches to avoid overwhelming the server.
        var batchSize = 3;
        var batches = [];
        for (var i = 0; i < certs.length; i += batchSize) {
            batches.push(certs.slice(i, i + batchSize));
        }

        var batchIndex = 0;
        return new Promise(function (resolve) {
            function processBatch() {
                if (batchIndex >= batches.length) {
                    updateDeploymentStats();
                    resolve();
                    return;
                }

                var batch = batches[batchIndex];
                var batchPromises = batch.map(function (cert) {
                    return checkDeploymentStatus(cert.domain).then(reportProgress, reportProgress);
                });

                Promise.all(batchPromises).then(function () {
                    batchIndex++;
                    if (batchIndex < batches.length) {
                        setTimeout(processBatch, 500);
                    } else {
                        // last batch settled; recurse once to hit the terminal (stats + resolve) branch
                        processBatch();
                    }
                });
            }

            processBatch();
        });
    }

    // Check deployment status for all certificates (manual "Check all" button)
    function checkAllDeploymentStatuses(evt) {
        // Resolve the trigger from the passed event (currentTarget = the button
        // the inline onclick is bound to). Avoid implicit window.event, which is
        // unreliable in Firefox/Safari under the strict-mode module.
        var button = (evt && evt.currentTarget) ? evt.currentTarget : null;
        var originalText = button ? button.innerHTML : '';
        if (button) {
            button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Checking...';
            button.disabled = true;
        }

        var restoreButton = function () {
            if (button) {
                button.innerHTML = originalText;
                button.disabled = false;
            }
        };

        // Ensure allCertificates is an array
        if (!Array.isArray(allCertificates)) {
            allCertificates = [];
        }

        var certificatesToCheck = allCertificates.filter(function (cert) { return cert.exists; });

        if (certificatesToCheck.length === 0) {
            showMessage('No certificates found to check', 'info');
            restoreButton();
            return;
        }

        runDeploymentChecks(certificatesToCheck, {
            onProgress: function (completed, totalCount) {
                if (!button) return;
                var percentage = Math.round((completed / totalCount) * 100);
                button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Checking... ' + completed + '/' + totalCount + ' (' + percentage + '%)';
            }
        }).then(function () {
            showMessage('Deployment status updated for ' + certificatesToCheck.length + ' certificates', 'success');
            restoreButton();
        });
    }

    // Check deployment status for a specific domain
    function checkDeploymentStatus(domain, triggerButton, forceRefresh) {
        var restoreButton = function () {
            if (!triggerButton) {
                return;
            }
            triggerButton.disabled = false;
            if (triggerButton.dataset.originalHtml) {
                triggerButton.innerHTML = triggerButton.dataset.originalHtml;
                delete triggerButton.dataset.originalHtml;
            }
        };

        if (triggerButton) {
            triggerButton.dataset.originalHtml = triggerButton.innerHTML;
            triggerButton.disabled = true;
            triggerButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Checking...';
        }

        var statusElements = Array.prototype.filter.call(
            document.querySelectorAll('[data-deployment-domain]'),
            function (el) {
                return el.getAttribute('data-deployment-domain') === domain;
            }
        );

        if (!statusElements.length) {
            restoreButton();
            return Promise.resolve();
        }

        // Check cache first
        var cachedResult = forceRefresh ? null : deploymentCache.get(domain);
        if (cachedResult) {
            updateDeploymentUI(domain, cachedResult);
            restoreButton();
            return Promise.resolve();
        }

        // Update UI to show checking state
        statusElements.forEach(function (statusElement) {
            statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-600';
            statusElement.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Checking...';
        });

        var deploymentUrl = '/api/certificates/' + encodeURIComponent(domain) + '/deployment-status';
        if (forceRefresh) {
            deploymentUrl += '?refresh=1';
        }

        return fetch(deploymentUrl, {
            method: 'GET',
            headers: API_HEADERS
        }).then(function (response) {
            if (response.ok) {
                return response.json().then(function (result) {
                    if (result && result.reachable === false) {
                        if (!result.protocol || result.protocol === 'https-tls') {
                            return checkDeploymentViaBrowser(domain, result.port).then(function (browserResult) {
                                if (browserResult) {
                                    queueBrowserDeploymentReport(domain, browserResult);
                                    result.browser = browserResult;
                                }
                                deploymentCache.set(domain, result);
                                updateDeploymentUI(domain, result);
                            });
                        }
                        result.browser = null;
                    }

                    deploymentCache.set(domain, result);
                    updateDeploymentUI(domain, result);
                });
            }
            throw new Error('API failed');
        }).catch(function (apiError) {
            // Fallback to browser-based certificate check
            return checkDeploymentViaBrowser(domain, null).then(function (result) {
                if (!result) {
                    result = {
                        deployed: false,
                        reachable: false,
                        certificate_match: false,
                        method: 'unavailable',
                        error: 'all_methods_failed',
                        timestamp: new Date().toISOString()
                    };
                }
                if (result.reachable) {
                    queueBrowserDeploymentReport(domain, result);
                }
                // Keep the server-side result as the primary status. The browser
                // probe is supplemental and may be useful for diagnostics, but it
                // should not replace the backend's deployed/reachable verdict.
                deploymentCache.set(domain, {
                    deployed: false,
                    reachable: false,
                    certificate_match: false,
                    method: 'browser-fallback',
                    error: 'backend-unavailable',
                    timestamp: result.timestamp || new Date().toISOString(),
                    browser: result
                });
                updateDeploymentUI(domain, deploymentCache.get(domain));
            });
        }).catch(function () {
            statusElements.forEach(function (statusElement) {
                statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-surface-2 text-muted';
                statusElement.innerHTML = '<i class="fas fa-question-circle mr-1"></i>Error';
            });
        }).finally(function () {
            restoreButton();
        });
    }

    // Browser-based certificate check fallback
    function checkDeploymentViaBrowser(domain, port) {
        var controller = new AbortController();
        var timeoutId = setTimeout(function () { controller.abort(); }, 10000);

        var url = port ? 'https://' + domain + ':' + port : 'https://' + domain;

        return fetch(url, {
            method: 'HEAD',
            mode: 'no-cors',
            signal: controller.signal
        }).then(function () {
            clearTimeout(timeoutId);
            return {
                deployed: true,
                reachable: true,
                certificate_match: null,
                method: 'browser-fallback',
                timestamp: new Date().toISOString()
            };
        }).catch(function (browserError) {
            clearTimeout(timeoutId);
            if (browserError.name === 'AbortError') {
                return {
                    deployed: false,
                    reachable: false,
                    certificate_match: false,
                    method: 'browser-fallback',
                    error: 'timeout',
                    timestamp: new Date().toISOString()
                };
            }
            return null;
        });
    }


    // Update deployment UI based on check result
    function updateDeploymentUI(domain, result) {
        var backendResult = result || null;
        var browserResult = result && result.browser ? result.browser : null;

        ['backend', 'browser'].forEach(function (role) {
            var roleResult = role === 'browser' ? browserResult : backendResult;
            var display = deploymentStatusDisplay(role, roleResult);
            Array.prototype.filter.call(
                document.querySelectorAll('[data-deployment-domain][data-deployment-role="' + role + '"]'),
                function (el) {
                    return el.getAttribute('data-deployment-domain') === domain;
                }
            ).forEach(function (statusElement) {
                // Re-render through the SAME chip helpers the initial paint uses
                // so a completed probe updates the icon + colour in place instead
                // of replacing the chip with stale "Role: Status" text.
                statusElement.className = deploymentChipClass(display);
                statusElement.innerHTML = deploymentChipInner(display);
                var title = display.text;
                if (roleResult && roleResult.method) {
                    title += ' via ' + roleResult.method;
                    if (roleResult.timestamp) {
                        title += ' at ' + roleResult.timestamp;
                    }
                }
                statusElement.title = title;
                statusElement.setAttribute('aria-label', title);
            });
        });
    }

    // Load certificates with deployment status
    function loadCertificates() {
        addDebugLog('Loading certificates from API...', 'info');

        return fetch('/api/certificates', {
            headers: API_HEADERS
        }).then(function (response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }
            return response.json();
        }).then(function (certificates) {
            // Check if the response is an error object
            if (certificates && certificates.error) {
                throw new Error('API Error: ' + certificates.error + ' (' + (certificates.code || 'unknown') + ')');
            }

            // Ensure certificates is an array
            if (!Array.isArray(certificates)) {
                addDebugLog('API returned invalid response: ' + JSON.stringify(certificates), 'error');
                throw new Error('Invalid API response: expected array of certificates');
            }

            addDebugLog('Loaded ' + certificates.length + ' certificates successfully', 'success');

            allCertificates = certificates;
            updateStats(certificates);
            displayCertificates(certificates);

            // Check deployment status for all certificates after a short delay.
            // Single source of automatic checks — batched/deduped via
            // runDeploymentChecks() (no progress callback here).
            addDebugLog('Scheduling automatic deployment status checks...', 'info');

            setTimeout(function () {
                var existingCerts = certificates.filter(function (cert) { return cert.exists; });
                if (existingCerts.length > 0) {
                    addDebugLog('Starting automatic deployment status checks for all certificates', 'info');
                    runDeploymentChecks(existingCerts).then(function () {
                        addDebugLog('Automatic deployment check completed for ' + existingCerts.length + ' certificates', 'success');
                    });
                } else {
                    addDebugLog('No certificates with valid status found to check', 'warn');
                }
            }, 1500);

        }).catch(function (error) {
            addDebugLog('Failed to load certificates: ' + error.message, 'error');

            // Initialize with empty array to prevent further errors
            allCertificates = [];
            updateStats([]);
            displayCertificates([]);

            // Show appropriate error message
            if (error.message.indexOf('401') !== -1 || error.message.indexOf('Unauthorized') !== -1) {
                showMessage('Authentication failed. Please check your API token.', 'error');
            } else if (error.message.indexOf('403') !== -1 || error.message.indexOf('Forbidden') !== -1) {
                showMessage('Access denied. Please check your permissions.', 'error');
            } else {
                showMessage('Failed to load certificates. Please try again.', 'error');
            }
        });
    }

    // Listen for cache settings updates from the settings page. The settings
    // page writes to localStorage; the browser `storage` event fires in OTHER
    // tabs than the writer, which is exactly the cross-tab signalling intent
    // here (no polling needed).
    function setupCacheSettingsListener() {
        // Track the last-seen values so we only react to genuine changes.
        var lastUpdate = localStorage.getItem('cache-settings-updated');
        var lastClearSignal = localStorage.getItem('clear-deployment-cache');

        function handleSettingsUpdate(value) {
            if (value && value !== lastUpdate) {
                deploymentCache.loadSettings();
                addDebugLog('Cache settings updated from settings page', 'info');
                lastUpdate = value;
            }
        }

        function handleClearSignal(value) {
            if (value && value !== lastClearSignal) {
                deploymentCache.clear();
                addDebugLog('Deployment cache cleared by admin request', 'warn');
                // Re-check all certificates (batched via runDeploymentChecks).
                setTimeout(function () {
                    if (Array.isArray(allCertificates) && allCertificates.length > 0) {
                        var existingCerts = allCertificates.filter(function (cert) { return cert.exists; });
                        if (existingCerts.length > 0) {
                            addDebugLog('Re-checking all certificates after cache clear...', 'info');
                            runDeploymentChecks(existingCerts);
                        }
                    }
                }, 1000);
                lastClearSignal = value;
            }
        }

        // React to writes from other tabs (the settings page).
        window.addEventListener('storage', function (e) {
            if (e.key === 'cache-settings-updated') {
                handleSettingsUpdate(e.newValue);
            } else if (e.key === 'clear-deployment-cache') {
                handleClearSignal(e.newValue);
            }
        });
    }

    // Multi-account support functions
    var providerAccounts = {};

    function loadProviderAccounts() {
        var providers = ['cloudflare', 'route53', 'digitalocean', 'azure', 'google', 'powerdns', 'rfc2136'];

        providers.forEach(function (provider) {
            fetch('/api/dns/' + provider + '/accounts', {
                headers: API_HEADERS
            }).then(function (response) {
                if (response.ok) {
                    return response.json().then(function (data) {
                        var accounts = data.accounts || {};
                        var accountsArray = Object.keys(accounts).map(function (accountId) {
                            var account = accounts[accountId];
                            account.account_id = accountId;
                            return account;
                        });
                        providerAccounts[provider] = accountsArray;
                    });
                }
            }).catch(function () {
                providerAccounts[provider] = [];
            });
        });
    }

    function updateAccountSelection() {
        var providerSelect = document.getElementById('dns_provider_select');
        var accountContainer = document.getElementById('account-selection-container');
        var accountSelect = document.getElementById('account_select');

        var selectedProvider = providerSelect.value;

        if (selectedProvider && providerAccounts[selectedProvider] && providerAccounts[selectedProvider].length > 0) {
            accountContainer.style.display = 'block';
            accountSelect.innerHTML = '<option value="">Use default account</option>';

            providerAccounts[selectedProvider].forEach(function (account) {
                var option = document.createElement('option');
                option.value = account.account_id;
                option.textContent = account.name || account.account_id;
                accountSelect.appendChild(option);
            });
        } else {
            accountContainer.style.display = 'none';
            accountSelect.innerHTML = '<option value="">Use default account</option>';
        }
    }

    function updateCAProviderInfo() {
        var caSelect = document.getElementById('ca_provider_select');
        var infoDiv = document.getElementById('ca-provider-info');
        var selectedCA = caSelect.value;

        if (selectedCA) {
            var infoText = '';
            switch (selectedCA) {
                case 'letsencrypt':
                    infoText = '<i class="fas fa-leaf mr-1 text-green-500"></i> Free certificates with 90-day validity and automatic renewal';
                    break;
                case 'letsencrypt_staging':
                    infoText = '<i class="fas fa-flask mr-1 text-yellow-500"></i> Staging environment for testing - certificates are NOT trusted by browsers, but rate limits are generous';
                    break;
                case 'zerossl':
                    infoText = '<i class="fas fa-certificate mr-1 text-yellow-500"></i> Free certificates with 90-day validity via ZeroSSL (requires EAB)';
                    break;
                case 'google':
                    infoText = '<i class="fab fa-google mr-1 text-blue-500"></i> Free certificates from Google Trust Services (requires EAB)';
                    break;
                case 'actalis':
                    infoText = '<i class="fas fa-certificate mr-1 text-blue-500"></i> Free 90-day DV certificates from Actalis, European CA (requires EAB, single domain only)';
                    break;
                case 'digicert':
                    infoText = '<i class="fas fa-shield-alt mr-1 text-blue-500"></i> Enterprise certificates (requires EAB credentials configured in Settings)';
                    break;
                case 'sslcom':
                    infoText = '<i class="fas fa-shield-alt mr-1 text-indigo-500"></i> Enterprise certificates from SSL.com (requires EAB)';
                    break;
                case 'private_ca':
                    infoText = '<i class="fas fa-building mr-1 text-purple-500"></i> Internal CA certificates (requires ACME URL configured in Settings)';
                    break;
                default:
                    // A certificate may still carry a removed/unknown CA in its
                    // metadata (e.g. the discontinued BuyPass). Show a clear note
                    // instead of a blank line.
                    infoText = '<i class="fas fa-exclamation-triangle mr-1 text-yellow-500"></i> This certificate authority is no longer available; reissue with a supported CA';
                    break;
            }
            infoDiv.innerHTML = infoText;
            infoDiv.classList.remove('hidden');
        } else {
            infoDiv.classList.add('hidden');
        }
    }

    function toggleDnsProviderVisibility() {
        var select = document.getElementById('challenge_type_select');
        var container = document.getElementById('dns-provider-container');
        if (!container) return;
        if (select && select.value === 'http-01') {
            container.style.display = 'none';
        } else {
            container.style.display = '';
        }
    }

    function toggleAdvancedOptions() {
        var optionsDiv = document.getElementById('advanced-options');
        var chevron = document.getElementById('advanced-chevron');
        var toggleBtn = document.getElementById('advancedOptionsToggle');

        if (optionsDiv.classList.contains('hidden')) {
            optionsDiv.classList.remove('hidden');
            chevron.classList.add('rotate-180');
            if (toggleBtn) { toggleBtn.setAttribute('aria-expanded', 'true'); }
        } else {
            optionsDiv.classList.add('hidden');
            chevron.classList.remove('rotate-180');
            if (toggleBtn) { toggleBtn.setAttribute('aria-expanded', 'false'); }
        }
    }

    function normalizeDnsName(value) {
        return (value || '').trim().replace(/^\*\./, '').replace(/\.+$/, '');
    }

    function normalizeDnsAliasName(value) {
        return normalizeDnsName(value).replace(/^_acme-challenge\./i, '');
    }

    // Normalize a hostname the way the cert-create form needs it: lowercase,
    // strip protocol / port / path / fragment / trailing dot, but keep the
    // optional `*.` wildcard prefix intact (both the primary and the SAN
    // fields legitimately accept wildcards). This catches the common QW-15
    // paste patterns:
    //   "https://example.com/"       → "example.com"
    //   "Example.COM"                → "example.com"
    //   "example.com:443"            → "example.com"
    //   "example.com."               → "example.com"
    //   "example.com/path?x=1"       → "example.com"
    function normalizeHostname(value) {
        if (!value) return '';
        var v = String(value).trim().toLowerCase();
        v = v.replace(/^[a-z][a-z0-9+.\-]*:\/\//, ''); // strip scheme://
        v = v.replace(/[\/?#].*$/, '');                 // strip path/query/fragment
        v = v.replace(/:\d+$/, '');                     // strip :port
        v = v.replace(/\.+$/, '');                      // strip trailing dots
        return v;
    }

    function parseSanDomainsInput(value) {
        // Accept comma, semicolon, newline, or tab as separators — users
        // routinely paste from spreadsheets, CLI output, or notepads where
        // the delimiter isn't always a comma. Each token is normalized via
        // normalizeHostname; duplicates after normalization are dropped.
        if (!value) return [];
        var seen = Object.create(null);
        var out = [];
        String(value).split(/[,;\n\t]+/).forEach(function (raw) {
            var d = normalizeHostname(raw);
            if (!d || seen[d]) return;
            seen[d] = true;
            out.push(d);
        });
        return out;
    }

    function addUniqueDomain(domains, domain) {
        if (domain && domains.indexOf(domain) === -1) {
            domains.push(domain);
        }
    }

    function buildRequestedDomains(primaryDomain, sanDomains, wildcardEnabled) {
        var domains = [];
        var primary = normalizeDnsName(primaryDomain);
        addUniqueDomain(domains, primary);

        if (wildcardEnabled && primary) {
            addUniqueDomain(domains, '*.' + primary);
        }

        sanDomains.forEach(function (san) {
            var normalizedSan = normalizeDnsName(san);
            addUniqueDomain(domains, normalizedSan);
        });

        return domains;
    }

    function dnsChallengeName(domain) {
        return '_acme-challenge.' + normalizeDnsName(domain);
    }

    function currentRequestedDomains() {
        var domainField = document.getElementById('domain');
        var sanField = document.getElementById('san_domains');
        var wildcardField = document.getElementById('wildcard-cert');
        return buildRequestedDomains(
            domainField ? domainField.value : '',
            sanField ? parseSanDomainsInput(sanField.value) : [],
            wildcardField ? wildcardField.checked : false
        );
    }

    function updateDnsAliasHelp() {
        var domainField = document.getElementById('domain');
        var aliasField = document.getElementById('dns_alias_domain');
        var help = document.getElementById('dns_alias_help');
        if (!domainField || !aliasField || !help) return;

        var aliasDomain = normalizeDnsAliasName(aliasField.value);
        var requestedDomains = currentRequestedDomains();

        if (requestedDomains.length > 0 && aliasDomain) {
            var target = '_acme-challenge.' + aliasDomain;
            var challengeNames = [];
            requestedDomains.forEach(function (requestedDomain) {
                addUniqueDomain(challengeNames, dnsChallengeName(requestedDomain));
            });

            var rows = challengeNames.map(function (source) {
                return '<div class="mt-1"><code class="font-mono bg-gray-100 dark:bg-gray-600 px-1 rounded">'
                    + escapeHtml(source)
                    + '</code> &rarr; <code class="font-mono bg-gray-100 dark:bg-gray-600 px-1 rounded">'
                    + escapeHtml(target)
                    + '</code></div>';
            }).join('');
            help.innerHTML = 'Create these CNAMEs:' + rows;
        } else {
            help.innerHTML = 'Use DNS-01 Alias Mode when <code class="font-mono bg-gray-100 dark:bg-gray-600 px-1 rounded">_acme-challenge.yourdomain.com</code> '
                + 'is CNAMEd to a validation zone you control. Enter the target FQDN (without the <code class="font-mono bg-gray-100 dark:bg-gray-600 px-1 rounded">_acme-challenge.</code> prefix).';
        }
    }

    function renderDnsAliasCheckResult(result, targetId) {
        var target = document.getElementById(targetId);
        if (!target) return;

        var checks = result && Array.isArray(result.checks) ? result.checks : [];
        var ok = result && result.ok;
        var headerClass = ok
            ? 'text-success-fg bg-success-surface border-success-line'
            : 'text-danger-fg bg-danger-surface border-danger-line';
        var icon = ok ? 'fa-check-circle' : 'fa-times-circle';
        var title = ok ? 'All DNS-01 alias CNAMEs are present' : 'DNS-01 alias CNAMEs need attention';

        var rows = checks.map(function (check) {
            var rowClass = check.ok ? 'text-success-fg' : 'text-danger-fg';
            var found = check.found_targets && check.found_targets.length
                ? check.found_targets.join(', ')
                : 'No CNAME found';
            if (check.error) {
                found = check.error;
            }
            return '<div class="mt-2 text-xs ' + rowClass + '">' +
                '<div><i class="fas ' + (check.ok ? 'fa-check' : 'fa-times') + ' mr-1"></i>' +
                '<code class="font-mono bg-surface-2 px-1 rounded">' + escapeHtml(check.source) + '</code>' +
                aliasCopyButtonHtml(check.source) + '</div>' +
                '<div class="mt-1 ml-5">Expected: <code class="font-mono bg-surface-2 px-1 rounded">' + escapeHtml(check.expected_target) + '</code>' +
                aliasCopyButtonHtml(check.expected_target) + '</div>' +
                '<div class="mt-1 ml-5">Found: <code class="font-mono bg-surface-2 px-1 rounded">' + escapeHtml(found) + '</code></div>' +
                '</div>';
        }).join('');

        if (!rows) {
            rows = '<div class="mt-2 text-xs text-muted">No DNS-01 alias records to check.</div>';
        }

        target.className = 'mt-2 rounded-md border p-3 ' + headerClass;
        target.innerHTML = '<div class="text-xs font-semibold"><i class="fas ' + icon + ' mr-1"></i>' + title + '</div>' + rows;
        target.classList.remove('hidden');
    }

    function checkDnsAliasFromForm() {
        var domain = normalizeDnsName(document.getElementById('domain').value);
        var aliasDomain = normalizeDnsAliasName((document.getElementById('dns_alias_domain') || {}).value);
        var requestedDomains = currentRequestedDomains();
        var sanDomains = requestedDomains.slice(1);
        var resultTarget = document.getElementById('dns_alias_check_result');

        if (!domain || !aliasDomain) {
            showMessage('Enter both primary domain and DNS-01 alias domain before checking.', 'error');
            return;
        }

        if (resultTarget) {
            resultTarget.className = 'mt-2 rounded-md border border-info-line bg-info-surface p-3 text-xs text-info-fg';
            resultTarget.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Checking DNS-01 alias CNAMEs...';
            resultTarget.classList.remove('hidden');
        }

        return fetch('/api/certificates/check-dns-alias', {
            method: 'POST',
            headers: API_HEADERS,
            body: JSON.stringify({
                domain: domain,
                domain_alias: aliasDomain,
                san_domains: sanDomains,
            })
        }).then(function (response) {
            return response.json().then(function (result) {
                if (!response.ok) {
                    throw new Error(result.error || 'DNS-01 alias check failed');
                }
                renderDnsAliasCheckResult(result, 'dns_alias_check_result');
            });
        }).catch(function (error) {
            showMessage(error.message || 'DNS-01 alias check failed', 'error');
            if (resultTarget) {
                resultTarget.classList.add('hidden');
            }
        });
    }

    function checkDnsAliasForCertificate(domain) {
        var targetId = 'cert_dns_alias_check_result';
        var resultTarget = document.getElementById(targetId);
        if (resultTarget) {
            resultTarget.className = 'mt-3 rounded-md border border-info-line bg-info-surface p-3 text-xs text-info-fg';
            resultTarget.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Checking DNS-01 alias CNAMEs...';
            resultTarget.classList.remove('hidden');
        }

        return fetch('/api/certificates/' + encodeURIComponent(domain) + '/dns-alias-check', {
            method: 'GET',
            headers: API_HEADERS
        }).then(function (response) {
            return response.json().then(function (result) {
                if (!response.ok) {
                    throw new Error(result.error || 'DNS-01 alias check failed');
                }
                renderDnsAliasCheckResult(result, targetId);
            });
        }).catch(function (error) {
            showMessage(error.message || 'DNS-01 alias check failed', 'error');
            if (resultTarget) {
                resultTarget.classList.add('hidden');
            }
        });
    }

    // Show RSA key-size picker only when the operator chose RSA, ECDSA curve
    // picker only when they chose ECDSA. Leaving "Use global default" hides
    // both — the form then sends no key fields and the backend inherits the
    // configured default.
    function toggleCertKeyOptions() {
        var keyType = document.getElementById('cert_key_type').value;
        var sizeEl = document.getElementById('cert_key_size_container');
        var curveEl = document.getElementById('cert_elliptic_curve_container');
        if (sizeEl) sizeEl.style.display = (keyType === 'rsa') ? '' : 'none';
        if (curveEl) curveEl.style.display = (keyType === 'ecdsa') ? '' : 'none';
    }

    // =============================================
    // Edit & Reissue (#267): reuse the create form in an edit mode that
    // POSTs to /api/certificates/<domain>/reissue instead of /create.
    // Omitted fields keep the issued values server-side; the form is
    // prefilled so what the user sees is what gets submitted.
    // =============================================
    var reissueEditingDomain = null;

    function startEditReissue(domain) {
        var cert = allCertificates.find(function (c) { return c.domain === domain; });
        if (!cert) {
            showMessage('Certificate data is not loaded yet. Refresh and try again.', 'error');
            return;
        }
        reissueEditingDomain = domain;
        closeCertDetail();
        openCreateCertForm();

        var domainField = document.getElementById('domain');
        domainField.value = domain;
        // The primary domain is the certificate's identity (certbot
        // --cert-name, directory, API path): changing it is a
        // delete+recreate, not an edit.
        domainField.readOnly = true;

        // Reverse-map the wildcard checkbox out of the SAN list — the
        // create submit handler encodes it client-side as '*.'+primary.
        // Compare case-insensitively: DNS names are, and API-created certs
        // can carry mixed-case SANs in metadata.
        var sans = (cert.san_domains || []).slice();
        var wildcardName = ('*.' + domain).toLowerCase();
        var wildcardIndex = -1;
        sans.forEach(function (s, i) {
            if (String(s).toLowerCase() === wildcardName) wildcardIndex = i;
        });
        document.getElementById('wildcard-cert').checked = wildcardIndex !== -1;
        if (wildcardIndex !== -1) sans.splice(wildcardIndex, 1);
        document.getElementById('san_domains').value = sans.join(', ');

        if (cert.challenge_type) document.getElementById('challenge_type_select').value = cert.challenge_type;
        if (cert.dns_provider) document.getElementById('dns_provider_select').value = cert.dns_provider;
        if (cert.ca_provider) document.getElementById('ca_provider_select').value = cert.ca_provider;
        var aliasField = document.getElementById('dns_alias_domain');
        if (aliasField) aliasField.value = cert.domain_alias || '';

        // Sync dependent widgets, then the account dropdown (its options
        // are rebuilt by updateAccountSelection).
        toggleDnsProviderVisibility();
        updateCAProviderInfo();
        updateDnsAliasHelp();
        if (typeof updateAccountSelection === 'function') updateAccountSelection();
        if (cert.account_id) {
            var accountSelect = document.getElementById('account_select');
            if (accountSelect) accountSelect.value = cert.account_id;
        }

        // The wildcard checkbox and alias field live inside the collapsed
        // Advanced Options panel: expand it whenever the prefill put a value
        // there, so what the user sees is what gets submitted.
        var advancedPanel = document.getElementById('advanced-options');
        if (advancedPanel && advancedPanel.classList.contains('hidden') &&
                (wildcardIndex !== -1 || cert.domain_alias)) {
            toggleAdvancedOptions();
        }

        setReissueFormMode(true, domain);
    }

    function setReissueFormMode(editing, domain) {
        var form = document.getElementById('createCertForm');
        if (!form) return;
        var submitBtn = form.querySelector('button[type="submit"]');
        var banner = document.getElementById('reissue-edit-banner');
        if (editing) {
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'reissue-edit-banner';
                banner.className = 'mb-4 p-3 rounded-md bg-warning-surface border border-warning-line text-sm text-warning-fg flex items-center justify-between gap-4';
                form.insertBefore(banner, form.firstChild);
            }
            banner.innerHTML = '<span><i class="fas fa-pen mr-2"></i>Editing <strong>' + escapeHtml(domain) + '</strong>: submitting reissues the certificate in place. The current certificate keeps serving until the reissue succeeds; the key shape is preserved unless explicitly changed.</span>' +
                '<button type="button" onclick="cancelEditReissue()" class="shrink-0 px-3 py-1 border border-warning-line rounded-md text-xs font-medium hover:bg-amber-100 dark:hover:bg-amber-900/40">Cancel edit</button>';
            if (submitBtn) {
                if (!submitBtn.dataset.createHtml) {
                    submitBtn.dataset.createHtml = submitBtn.innerHTML;
                }
                submitBtn.innerHTML = '<i class="fas fa-sync-alt mr-2"></i>Reissue Certificate';
            }
        } else {
            if (banner) banner.remove();
            if (submitBtn && submitBtn.dataset.createHtml) {
                submitBtn.innerHTML = submitBtn.dataset.createHtml;
            }
        }
    }

    function cancelEditReissue() {
        reissueEditingDomain = null;
        var domainField = document.getElementById('domain');
        domainField.readOnly = false;
        domainField.value = '';
        document.getElementById('san_domains').value = '';
        document.getElementById('wildcard-cert').checked = false;
        document.getElementById('challenge_type_select').value = '';
        document.getElementById('dns_provider_select').value = '';
        document.getElementById('account_select').value = '';
        document.getElementById('ca_provider_select').value = '';
        var aliasField = document.getElementById('dns_alias_domain');
        if (aliasField) { aliasField.value = ''; }
        updateDnsAliasHelp();
        toggleDnsProviderVisibility();
        setReissueFormMode(false);
    }

    // Create certificate
    var isCreatingCert = false;
    document.getElementById('createCertForm').addEventListener('submit', async function (e) {
        e.preventDefault();

        // QW-12: gate against duplicate submits. A real-cert issue path can
        // take 30s+ to come back; without this guard, every extra click on
        // the submit button (or Enter inside any of the inputs) fires another
        // POST /api/certificates/create with the same body. Validation
        // early-returns below run before we acquire the lock, so a rejected
        // submit doesn't leave the form stuck.
        if (isCreatingCert) return;

        // Primary domain: apply the same paste-normalization as SAN inputs
        // (lowercase, strip scheme/port/path/trailing-dot) so the request
        // body matches what the user sees rendered back in the cert row.
        var domain = normalizeHostname(document.getElementById('domain').value);
        var sanDomainsInput = document.getElementById('san_domains').value.trim();
        var wildcardEnabled = document.getElementById('wildcard-cert').checked;
        var challengeType = document.getElementById('challenge_type_select').value;
        var dnsProvider = document.getElementById('dns_provider_select').value;
        var accountId = document.getElementById('account_select').value;
        var caProvider = document.getElementById('ca_provider_select').value;
        var dnsAliasDomain = (document.getElementById('dns_alias_domain') || {}).value;
        dnsAliasDomain = dnsAliasDomain ? normalizeDnsAliasName(dnsAliasDomain) : '';

        // Parse SAN domains from comma-separated input
        var sanDomains = parseSanDomainsInput(sanDomainsInput);
        if (wildcardEnabled) {
            addUniqueDomain(sanDomains, '*.' + normalizeDnsName(domain));
        }

        if (!domain) {
            showMessage('Please enter a domain', 'error');
            return;
        }

        // Warn: HTTP-01 + wildcard is not supported
        if (challengeType === 'http-01') {
            var allDomains = [domain].concat(sanDomains);
            for (var i = 0; i < allDomains.length; i++) {
                if (allDomains[i].indexOf('*.') === 0) {
                    showMessage('HTTP-01 challenge does not support wildcard domains. Use DNS-01 instead.', 'error');
                    return;
                }
            }
        }

        // Build display message
        var domainsDisplay = sanDomains.length > 0
            ? domain + ' (+ ' + sanDomains.length + ' SAN' + (sanDomains.length > 1 ? 's' : '') + ')'
            : domain;

        // Edit mode (#267): dropping SANs is destructive for clients using
        // those names — enumerate them in a danger confirm before reissuing.
        var editingDomain = reissueEditingDomain;
        if (editingDomain) {
            var currentCert = allCertificates.find(function (c) { return c.domain === editingDomain; });
            var currentSans = (currentCert && currentCert.san_domains) || [];
            // Case-insensitive set difference: DNS names are, and a false
            // "will REMOVE" warning on a case-only mismatch is misleading.
            var newSanSet = sanDomains.map(function (s) { return String(s).toLowerCase(); });
            var removedSans = currentSans.filter(function (s) {
                return newSanSet.indexOf(String(s).toLowerCase()) === -1;
            });
            if (removedSans.length > 0) {
                var dropConfirmed = await CertMate.confirm(
                    'Reissuing ' + editingDomain + ' will REMOVE these names from the certificate:\n\n' +
                    removedSans.join('\n') +
                    '\n\nClients using the removed names will fail TLS validation once the new certificate is deployed. Continue?',
                    'Reissue Certificate',
                    { confirmText: 'Reissue' }
                );
                if (!dropConfirmed) return;
            }
        }

        // Lock the form for the duration of the request. Disabling every
        // field also blocks Enter-to-submit from inside the inputs, which
        // is the other path a user can re-trigger the POST. The original
        // disabled state of each field is snapshotted so any field that
        // was already disabled (e.g. account_select hidden by the DNS
        // provider toggle) stays disabled after re-enable.
        isCreatingCert = true;
        var form = e.target;
        var formFields = form.querySelectorAll('input, select, textarea, button');
        var previouslyDisabled = [];
        formFields.forEach(function (el, i) {
            previouslyDisabled[i] = el.disabled;
            el.disabled = true;
        });
        var submitBtn = form.querySelector('button[type="submit"]');
        var submitBtnOriginalHtml = submitBtn ? submitBtn.innerHTML : null;
        if (submitBtn) {
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Creating...';
        }

        var progressInterval = showLoadingModal(
            (editingDomain ? 'Reissuing Certificate for ' : 'Creating Certificate for ') + domainsDisplay,
            'Validating domain ownership and generating certificate...'
        );

        var requestBody = editingDomain ? {} : { domain: domain };
        if (editingDomain) {
            // The reissue payload is an explicit replacement set: [] drops
            // every SAN, and an empty alias field clears the alias (the
            // form was prefilled, so what the user sees is the intent).
            requestBody.san_domains = sanDomains;
            requestBody.domain_alias = dnsAliasDomain || '';
        } else {
            if (sanDomains.length > 0) {
                requestBody.san_domains = sanDomains;
            }
            if (dnsAliasDomain) {
                requestBody.domain_alias = dnsAliasDomain;
            }
        }
        if (challengeType) {
            requestBody.challenge_type = challengeType;
        }
        if (dnsProvider) {
            requestBody.dns_provider = dnsProvider;
        }
        if (accountId) {
            requestBody.account_id = accountId;
        }
        if (caProvider) {
            requestBody.ca_provider = caProvider;
        }

        // Optional key-shape override. Only sent when the operator picked a
        // non-default value, so an empty selector inherits the global default
        // configured in Settings.
        var certKeyType = (document.getElementById('cert_key_type') || {}).value;
        if (certKeyType === 'rsa') {
            requestBody.key_type = 'rsa';
            requestBody.key_size = parseInt(document.getElementById('cert_key_size').value, 10);
        } else if (certKeyType === 'ecdsa') {
            requestBody.key_type = 'ecdsa';
            requestBody.elliptic_curve = document.getElementById('cert_elliptic_curve').value;
        }

        // Phase 3: opt fresh creates into async issuance so the UI can show an
        // optimistic "Issuing" row + poll the job instead of blocking on the
        // full ACME round-trip. Reissue stays synchronous — it edits a row that
        // already exists, so an optimistic new row would be wrong. If the server
        // has no async executor it ignores the flag and replies synchronously,
        // which the 202-vs-200 branch below handles transparently.
        if (!editingDomain) {
            requestBody.async = true;
        }

        var submitEndpoint = editingDomain
            ? '/api/certificates/' + encodeURIComponent(editingDomain) + '/reissue'
            : '/api/certificates/create';

        fetch(submitEndpoint, {
            method: 'POST',
            headers: API_HEADERS,
            body: JSON.stringify(requestBody)
        }).then(function (response) {
            return response.json().then(function (result) {
                // Async accepted (202): the server queued the issuance and
                // handed back a job id. Show the optimistic row + poll instead
                // of treating this as a finished create.
                if (response.status === 202 && result && result.job_id) {
                    handleAsyncAccepted(result, requestBody, domainsDisplay);
                    return;
                }
                if (response.ok && result.success !== false) {
                    showMessage('Certificate ' + (editingDomain ? 'reissued' : 'created') + ' successfully for ' + domainsDisplay + '!', 'success');
                    if (editingDomain) {
                        cancelEditReissue();
                    } else {
                        clearCreateFormAfterSubmit();
                    }
                    updateAccountSelection();
                    loadCertificates();
                    if (typeof closeCertDrawer === 'function') closeCertDrawer();
                } else {
                    var errorMsg = result.error || result.message || 'Failed to create certificate';
                    if (result.hint) {
                        errorMsg += '\n\n\ud83d\udca1 ' + result.hint;
                    }
                    showMessage(errorMsg, 'error', {
                        errorContext: {
                            endpoint: 'POST ' + submitEndpoint,
                            status: response.status,
                            code: result.code,
                            message: result.error || result.message,
                            hint: result.hint
                        }
                    });
                }
            });
        }).catch(function (error) {
            console.error('Error creating certificate:', error);
            showMessage('Failed to ' + (editingDomain ? 'reissue' : 'create') + ' certificate. Please check your network connection and try again.', 'error', {
                errorContext: {
                    endpoint: 'POST ' + submitEndpoint,
                    status: 0,
                    code: 'NETWORK_ERROR',
                    message: (error && error.message) || 'network error'
                }
            });
        }).then(function () {
            hideLoadingModal(progressInterval);
            // Re-enable the form regardless of success / error / network outcome.
            formFields.forEach(function (el, i) {
                el.disabled = previouslyDisabled[i];
            });
            if (submitBtn && submitBtnOriginalHtml !== null) {
                submitBtn.innerHTML = submitBtnOriginalHtml;
            }
            isCreatingCert = false;
        });
    });

    // ===== Async issuance lifecycle (redesign phase 3) =======================
    // When a create is accepted asynchronously the table gets an optimistic
    // "Issuing" row at the top; we poll the job endpoint and resolve the row to
    // the real certificate (success, via loadCertificates) or to a "Failed" row
    // carrying the reason + a Retry button. There is no certificate_failed SSE
    // handler, so polling owns the failure path.

    // Reset the create form to its empty state after a submit was accepted
    // (shared by the sync-success and async-accepted paths).
    function clearCreateFormAfterSubmit() {
        document.getElementById('domain').value = '';
        document.getElementById('san_domains').value = '';
        document.getElementById('wildcard-cert').checked = false;
        document.getElementById('challenge_type_select').value = '';
        document.getElementById('dns_provider_select').value = '';
        document.getElementById('account_select').value = '';
        document.getElementById('ca_provider_select').value = '';
        var aliasField = document.getElementById('dns_alias_domain');
        if (aliasField) { aliasField.value = ''; }
        updateDnsAliasHelp();
        toggleDnsProviderVisibility();
    }

    function buildPendingRowsHtml() {
        var ids = Object.keys(pendingJobs);
        if (!ids.length) return '';
        // A job whose real certificate has already landed (SSE/reload beat our
        // poll) is obsolete — skip its optimistic row so the table never shows
        // both an "Issuing" and a "Valid" row for the same domain.
        var live = {};
        (allCertificates || []).forEach(function (c) { if (c && c.exists) { live[c.domain] = true; } });
        var parts = [];
        // Newest first: a just-submitted job should sit at the very top.
        ids.slice().reverse().forEach(function (id) {
            var job = pendingJobs[id];
            if (!job) return;
            if (job.state !== 'failed' && live[job.domain]) return;
            parts.push(job.state === 'failed' ? failedRowHtml(id, job) : issuingRowHtml(id, job));
        });
        return parts.join('');
    }

    function issuingRowHtml(jobId, job) {
        var domain = escapeHtml(job.domain || '');
        var providerLabel = job.provider ? escapeHtml(providerDisplayName(job.provider)) : '—';
        var sub = job.sanCount > 0
            ? ('+' + job.sanCount + ' SAN' + (job.sanCount > 1 ? 's' : ''))
            : 'Requesting certificate…';
        return '<tr data-pending-job="' + jobId + '" class="bg-blue-50/40 dark:bg-blue-900/10">' +
            '<td class="px-6 py-4 md:max-w-0"><div class="flex items-center min-w-0">' +
            '<i class="fas fa-spinner fa-spin text-info-fg mr-2 text-sm shrink-0" aria-hidden="true"></i>' +
            '<div class="min-w-0"><div class="text-sm font-medium text-foreground break-words md:truncate">' + domain + '</div>' +
            '<div class="mt-1 text-xs text-muted">' + sub + '</div></div></div></td>' +
            '<td class="px-4 py-4 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-500/10 text-info-fg ring-1 ring-inset ring-blue-500/20"><i class="fas fa-spinner fa-spin mr-1" aria-hidden="true"></i>Issuing</span></td>' +
            '<td class="px-4 py-4 whitespace-nowrap hidden md:table-cell text-sm text-muted">—</td>' +
            '<td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-muted">' + providerLabel + '</td>' +
            '<td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-muted">—</td>' +
            '<td class="px-4 py-4 whitespace-nowrap text-right"><span class="text-xs text-muted">Just now</span></td>' +
            '</tr>';
    }

    function failedRowHtml(jobId, job) {
        var domain = escapeHtml(job.domain || '');
        var providerLabel = job.provider ? escapeHtml(providerDisplayName(job.provider)) : '—';
        var rawErr = String(job.error || 'Certificate issuance failed');
        var errText = escapeHtml(rawErr.length > 140 ? rawErr.slice(0, 137) + '…' : rawErr);
        var errTitle = escapeHtml(rawErr);
        return '<tr data-pending-job="' + jobId + '" class="bg-red-50/40 dark:bg-red-900/10">' +
            '<td class="px-6 py-4 md:max-w-0"><div class="flex items-center min-w-0">' +
            '<i class="fas fa-times-circle text-danger-fg mr-2 text-sm shrink-0" aria-hidden="true"></i>' +
            '<div class="min-w-0"><div class="text-sm font-medium text-foreground break-words md:truncate">' + domain + '</div>' +
            '<div class="mt-1 text-xs text-danger-fg break-words" title="' + errTitle + '">' + errText + '</div></div></div></td>' +
            '<td class="px-4 py-4 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-danger-fg ring-1 ring-inset ring-red-500/20"><i class="fas fa-times-circle mr-1" aria-hidden="true"></i>Failed</span></td>' +
            '<td class="px-4 py-4 whitespace-nowrap hidden md:table-cell text-sm text-muted">—</td>' +
            '<td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-muted">' + providerLabel + '</td>' +
            '<td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-muted">—</td>' +
            '<td class="px-4 py-4 whitespace-nowrap text-right"><div class="flex items-center justify-end gap-1">' +
            '<button type="button" onclick="retryCreateJob(\'' + jobId + '\')" class="inline-flex items-center px-2.5 py-1 text-xs font-medium rounded border border-border text-label bg-input hover:bg-gray-50 dark:hover:bg-gray-600" title="Retry issuance for ' + domain + '" aria-label="Retry issuance for ' + domain + '"><i class="fas fa-sync-alt mr-1" aria-hidden="true"></i>Retry</button>' +
            '<button type="button" onclick="dismissPendingJob(\'' + jobId + '\')" class="inline-flex items-center justify-center p-2 text-gray-500 dark:text-gray-300 hover:text-gray-700 dark:hover:text-gray-100 rounded hover:bg-hover" title="Dismiss" aria-label="Dismiss failed issuance for ' + domain + '"><i class="fas fa-times" aria-hidden="true"></i></button>' +
            '</div></td></tr>';
    }

    // Replace the optimistic rows in place without disturbing the real rows or
    // any active filter view. Called after every pendingJobs mutation, and at
    // the tail of displayCertificates so a full rebuild re-attaches them.
    function renderPendingRows() {
        var container = document.getElementById('certificatesList');
        if (!container) return;
        container.querySelectorAll('tr[data-pending-job]').forEach(function (r) { r.remove(); });
        var html = buildPendingRowsHtml();
        if (!html) {
            // Removing the last optimistic row can leave the body blank on an
            // empty instance (the welcome panel was cleared to show the row).
            // Restore it. Guarded to 0 real certs so we never re-render — and
            // thus never clobber — a populated or filtered view.
            if (!container.children.length && (allCertificates || []).length === 0) {
                displayCertificates(allCertificates);
            }
            return;
        }
        var thead = document.querySelector('#certificatesTable thead');
        if (thead) thead.style.display = '';
        // If the body is showing the empty/welcome state, clear it first so the
        // pending rows don't render beneath a "Welcome to CertMate" panel.
        var emptyState = container.querySelector('[data-empty-state]');
        if (emptyState) container.innerHTML = '';
        container.insertAdjacentHTML('afterbegin', html);
    }

    function handleAsyncAccepted(job, requestBody, domainsDisplay) {
        var jobId = job.job_id;
        pendingJobs[jobId] = {
            domain: job.domain || requestBody.domain,
            provider: requestBody.dns_provider || '',
            sanCount: (requestBody.san_domains || []).length,
            state: 'issuing',
            payload: requestBody,
            domainsDisplay: domainsDisplay
        };
        clearCreateFormAfterSubmit();
        updateAccountSelection();
        if (typeof closeCertDrawer === 'function') { closeCertDrawer(); }
        showMessage('Issuing certificate for ' + domainsDisplay + '…', 'info');
        renderPendingRows();
        pollCertJob(jobId, job.status_url || ('/api/certificates/jobs/' + jobId));
    }

    function pollCertJob(jobId, statusUrl) {
        var attempts = 0;
        var MAX_ATTEMPTS = 150;   // ~5 min at 2s — well beyond a normal ACME issue
        function tick() {
            if (!pendingJobs[jobId]) return;   // dismissed/retried away
            attempts++;
            fetch(statusUrl, { headers: API_HEADERS }).then(function (resp) {
                if (resp.status === 404) return { status: '__gone__' };
                return resp.json();
            }).then(function (jobRec) {
                if (!pendingJobs[jobId]) return;   // dismissed during the request
                var status = jobRec && jobRec.status;
                if (status === 'succeeded') {
                    delete pendingJobs[jobId];
                    delete pendingPollTimers[jobId];
                    loadCertificates();   // the real row replaces the optimistic one
                } else if (status === 'failed') {
                    pendingJobs[jobId].state = 'failed';
                    pendingJobs[jobId].error = (jobRec && jobRec.error) || 'Certificate issuance failed';
                    pendingJobs[jobId].errorCode = jobRec && jobRec.error_code;
                    delete pendingPollTimers[jobId];
                    renderPendingRows();
                    showMessage('Certificate issuance failed for ' + pendingJobs[jobId].domain + ': ' + pendingJobs[jobId].error, 'error');
                } else if (status === '__gone__') {
                    // Job evicted/unknown — drop the optimistic row and resync.
                    delete pendingJobs[jobId];
                    delete pendingPollTimers[jobId];
                    loadCertificates();
                } else if (attempts >= MAX_ATTEMPTS) {
                    // Still running after the cap: stop polling and drop the row
                    // rather than fail it — SSE/reload will reconcile the result.
                    delete pendingJobs[jobId];
                    delete pendingPollTimers[jobId];
                    renderPendingRows();
                } else {
                    pendingPollTimers[jobId] = setTimeout(tick, 2000);
                }
            }).catch(function () {
                if (!pendingJobs[jobId]) return;
                if (attempts >= MAX_ATTEMPTS) { delete pendingPollTimers[jobId]; return; }
                pendingPollTimers[jobId] = setTimeout(tick, 2000);
            });
        }
        pendingPollTimers[jobId] = setTimeout(tick, 1500);
    }

    // POST a create payload again (used by Retry). Lean create-only mirror of
    // the form submit's request handling — no reissue branch, no form locking.
    function postCreate(requestBody, domainsDisplay) {
        return fetch('/api/certificates/create', {
            method: 'POST', headers: API_HEADERS, body: JSON.stringify(requestBody)
        }).then(function (response) {
            return response.json().then(function (result) {
                if (response.status === 202 && result && result.job_id) {
                    handleAsyncAccepted(result, requestBody, domainsDisplay);
                } else if (response.ok && result.success !== false) {
                    showMessage('Certificate created successfully for ' + domainsDisplay + '!', 'success');
                    loadCertificates();
                } else {
                    var errorMsg = result.error || result.message || 'Failed to create certificate';
                    if (result.hint) { errorMsg += '\n\n' + result.hint; }
                    showMessage(errorMsg, 'error');
                }
            });
        }).catch(function () {
            showMessage('Failed to create certificate. Please check your network connection and try again.', 'error');
        });
    }

    function retryCreateJob(jobId) {
        var job = pendingJobs[jobId];
        if (!job) return;
        var payload = job.payload || {};
        var domainsDisplay = job.domainsDisplay || payload.domain || 'certificate';
        delete pendingJobs[jobId];
        if (pendingPollTimers[jobId]) { clearTimeout(pendingPollTimers[jobId]); delete pendingPollTimers[jobId]; }
        renderPendingRows();
        postCreate(payload, domainsDisplay);
    }

    function dismissPendingJob(jobId) {
        if (pendingPollTimers[jobId]) { clearTimeout(pendingPollTimers[jobId]); delete pendingPollTimers[jobId]; }
        delete pendingJobs[jobId];
        renderPendingRows();
    }

    // Certificate action functions
    function downloadCertificate(domain) {
        fetch('/api/certificates/' + encodeURIComponent(domain) + '/download', {
            method: 'GET'
        }).then(function (response) {
            if (response.ok) {
                return response.blob().then(function (blob) {
                    var url = window.URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    a.href = url;
                    a.download = domain + '-certificates.zip';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    showMessage('Certificate downloaded for ' + domain, 'success');
                });
            } else {
                return response.json().then(function (errorData) {
                    showMessage(errorData.error || 'Failed to download certificate', 'error');
                });
            }
        }).catch(function (error) {
            console.error('Error downloading certificate:', error);
            showMessage('Failed to download certificate', 'error');
        });
    }

    // Manually trigger deploy hooks for a domain (issue #109).
    async function runDeployHooks(domain) {
        var confirmed = await CertMate.confirm('Run deploy hooks for ' + domain + ' now?\n\nAll enabled global and domain-specific hooks will execute with CERTMATE_EVENT=manual.', 'Run Deploy Hooks', { confirmText: 'Run Hooks', danger: false });
        if (!confirmed) return;
        var progressInterval = showLoadingModal(
            'Running Deploy Hooks for ' + domain,
            'Executing each enabled hook…'
        );
        fetch('/api/certificates/' + encodeURIComponent(domain) + '/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).then(function (response) {
            return response.text().then(function (text) {
                var body = null;
                try { body = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON */ }
                return { ok: response.ok, status: response.status, body: body };
            });
        }).then(function (data) {
            // Discriminate the failure modes so the toast tells the user
            // *what* to do next instead of a generic "deploy hook run failed".
            if (data.status === 401 || data.status === 403) {
                showMessage(
                    'Insufficient privileges to run deploy hooks. '
                    + 'Sign in as admin to use this action.',
                    'error'
                );
                return;
            }
            if (data.status === 404) {
                showMessage('Certificate not found for ' + domain, 'error');
                return;
            }
            if (!data.ok) {
                var msg = (data.body && data.body.error)
                    ? data.body.error
                    : ('Deploy hook run failed (HTTP ' + data.status + ')');
                showMessage(msg, 'error', {
                    errorContext: {
                        endpoint: 'POST /api/certificates/' + domain + '/deploy',
                        status: data.status,
                        code: data.body && data.body.code,
                        message: data.body && data.body.error,
                        hint: data.body && data.body.hint
                    }
                });
                return;
            }
            var s = data.body || {};
            if (s.total === 0) {
                // Backend returned 200 with ok:false + a helpful error
                // (deploy disabled, no hooks for this domain, etc.).
                showMessage(s.error || 'No deploy hooks ran', 'warn');
                return;
            }
            if (s.ok) {
                showMessage('Deploy hooks ran for ' + domain + ': ' + s.succeeded + '/' + s.total + ' succeeded', 'success');
            } else {
                showMessage('Deploy hooks ran with errors for ' + domain + ': '
                    + s.succeeded + '/' + s.total + ' succeeded, ' + s.failed + ' failed. '
                    + 'Check Settings → Deploy → Recent Executions for details.', 'error');
            }
        }).catch(function (error) {
            console.error('Error running deploy hooks:', error);
            showMessage('Failed to run deploy hooks. Please try again.', 'error');
        }).finally(function () {
            // finally (not a trailing .then) so the blocking overlay clears even
            // if the .catch handler itself throws.
            hideLoadingModal(progressInterval);
        });
    }

    // Toggle per-cert auto-renew (issue #111).
    async function toggleAutoRenew(domain, currentlyEnabled) {
        var nextState = !currentlyEnabled;
        var verb = nextState ? 'Enable' : 'Disable';
        var confirmed = await CertMate.confirm(verb + ' automatic renewal for ' + domain + '?', verb + ' Auto-Renew', { confirmText: verb, danger: false });
        if (!confirmed) return;
        fetch('/api/certificates/' + encodeURIComponent(domain) + '/auto-renew', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: nextState })
        }).then(function (response) {
            return response.json().then(function (result) {
                return { ok: response.ok, result: result };
            });
        }).then(function (data) {
            if (data.ok) {
                showMessage('Auto-renew ' + (nextState ? 'enabled' : 'disabled') + ' for ' + domain, 'success');
                loadCertificates();
            } else {
                showMessage(data.result.error || 'Failed to update auto-renew', 'error');
            }
        }).catch(function (error) {
            console.error('Error toggling auto-renew:', error);
            showMessage('Failed to update auto-renew. Please try again.', 'error');
        });
    }

    // Delete a certificate and its settings entry (issue #111).
    function deleteCertificate(domain) {
        // Use CertMate.confirm (in-page modal, danger-styled) for parity
        // with every other destructive action in the app (revoke client
        // cert, delete user, delete backup, delete API key). The native
        // window.confirm bypasses the app theme and is dismissible by
        // browser "block dialogs" toggles — too weak a guard for an
        // operation that erases the cert files and the settings entry.
        CertMate.confirm(
            'Delete certificate for ' + domain + '? This removes the certificate files from disk and removes the domain from settings. This action cannot be undone.',
            'Delete Certificate',
            { confirmText: 'Delete' }
        ).then(function (confirmed) {
            if (!confirmed) return;
            fetch('/api/certificates/' + encodeURIComponent(domain), {
                method: 'DELETE'
            }).then(function (response) {
                return response.json().then(function (result) {
                    return { ok: response.ok, status: response.status, result: result };
                });
            }).then(function (data) {
                if (data.ok) {
                    showMessage('Certificate deleted for ' + domain, 'success');
                    closeCertDetail();
                    loadCertificates();
                } else {
                    showMessage(data.result.error || 'Failed to delete certificate', 'error', {
                        errorContext: {
                            endpoint: 'DELETE /api/certificates/' + domain,
                            status: data.status || 0,
                            code: data.result.code,
                            message: data.result.error,
                            hint: data.result.hint
                        }
                    });
                }
            }).catch(function (error) {
                console.error('Error deleting certificate:', error);
                showMessage('Failed to delete certificate. Please try again.', 'error', {
                    errorContext: {
                        endpoint: 'DELETE /api/certificates/' + domain,
                        status: 0,
                        code: 'NETWORK_ERROR',
                        message: (error && error.message) || 'network error'
                    }
                });
            });
        });
    }

    function renewCertificate(domain, force) {
        force = force === true;
        var progressInterval = showLoadingModal(
            (force ? 'Force Renewing Certificate for ' : 'Renewing Certificate for ') + domain,
            force ? 'This bypasses the normal due check and may count against CA rate limits...' : 'This may take a few minutes...'
        );

        fetch('/api/certificates/' + encodeURIComponent(domain) + '/renew', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ force: force })
        }).then(function (response) {
            return response.json().then(function (result) {
                return { ok: response.ok, status: response.status, result: result };
            });
        }).then(function (data) {
            if (data.ok) {
                showMessage((force ? 'Forced renewal completed for ' : 'Certificate renewal completed for ') + domain + '!', 'success');
                setTimeout(function () { loadCertificates(); }, 2000);
            } else {
                showMessage(data.result.error || data.result.message || 'Failed to renew certificate', 'error', {
                    errorContext: {
                        endpoint: 'POST /api/certificates/' + domain + '/renew',
                        status: data.status,
                        code: data.result.code,
                        message: data.result.error || data.result.message,
                        hint: data.result.hint
                    }
                });
            }
        }).catch(function (error) {
            console.error('Error renewing certificate:', error);
            showMessage('Failed to renew certificate. Please try again.', 'error', {
                errorContext: {
                    endpoint: 'POST /api/certificates/' + domain + '/renew',
                    status: 0,
                    code: 'NETWORK_ERROR',
                    message: (error && error.message) || 'network error'
                }
            });
        }).then(function () {
            hideLoadingModal(progressInterval);
        });
    }

    // Copy curl command modal functions
    function copyCurlCommand(domain) {
        var curlCommand = 'curl -O -H "Authorization: Bearer YOUR_API_TOKEN" \\\n' +
            '     ' + window.location.origin + '/api/certificates/' + encodeURIComponent(domain) + '/download';

        document.getElementById('curlCommandText').textContent = curlCommand;
        document.getElementById('curlModal').classList.remove('hidden');
    }

    function closeCurlModal() {
        document.getElementById('curlModal').classList.add('hidden');
    }

    function copyFromModal() {
        var commandText = document.getElementById('curlCommandText').textContent;

        if (navigator.clipboard) {
            navigator.clipboard.writeText(commandText).then(function () {
                showMessage('Curl command copied to clipboard!', 'success');
            }).catch(function (err) {
                console.error('Failed to copy: ', err);
                fallbackCopyTextToClipboard(commandText);
            });
        } else {
            fallbackCopyTextToClipboard(commandText);
        }
    }

    function fallbackCopyTextToClipboard(text) {
        var textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.top = '0';
        textArea.style.left = '0';
        textArea.style.position = 'fixed';

        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            var successful = document.execCommand('copy');
            if (successful) {
                showMessage('Curl command copied to clipboard!', 'success');
            } else {
                showMessage('Failed to copy command', 'error');
            }
        } catch (err) {
            showMessage('Failed to copy command', 'error');
        }

        document.body.removeChild(textArea);
    }

    function aliasCopyButtonHtml(value) {
        if (!value) return '';
        return ' <button type="button" class="ml-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors align-middle"' +
            ' data-copy="' + escapeHtml(value) + '"' +
            ' onclick="copyAliasValueToClipboard(this)"' +
            ' title="Copy to clipboard" aria-label="Copy to clipboard">' +
            '<i class="fas fa-clipboard text-xs"></i></button>';
    }

    function copyAliasValueToClipboard(button) {
        // The raw value is stored in data-copy and trimmed at copy time so the
        // user can't end up pasting the leading/trailing whitespace that the
        // browser tends to grab when a CNAME string is selected by hand
        // (issue #159).
        var text = String(button.dataset.copy || '').trim();
        if (!text) return;
        var icon = button.querySelector('i');
        var originalIconClass = icon ? icon.className : 'fas fa-clipboard text-xs';
        function flashSuccess() {
            if (icon) icon.className = 'fas fa-check text-xs';
            button.classList.add('text-green-600', 'dark:text-green-400');
            setTimeout(function () {
                if (icon) icon.className = originalIconClass;
                button.classList.remove('text-green-600', 'dark:text-green-400');
            }, 1500);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(flashSuccess).catch(function () {
                aliasFallbackCopy(text, flashSuccess);
            });
        } else {
            aliasFallbackCopy(text, flashSuccess);
        }
    }

    function aliasFallbackCopy(text, onSuccess) {
        var textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.top = '0';
        textArea.style.left = '0';
        textArea.style.position = 'fixed';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            if (document.execCommand('copy')) onSuccess();
        } catch (err) {
            /* swallow: feedback simply won't flash */
        }
        document.body.removeChild(textArea);
    }

    // Initialize on page load
    // Deep-link helper: when the dashboard is loaded with `?cert=<domain>`
    // in the query string (typically because the user clicked a cert
    // entry on /activity), open the detail panel for that domain once
    // the initial cert list has rendered. Silently no-ops on
    // unparseable URLs / missing param / unknown domain — openCertDetail
    // itself handles the not-found case via showMessage.
    function maybeOpenCertFromQuery() {
        try {
            var params = new URLSearchParams(window.location.search);
            var domain = params.get('cert');
            if (domain) openCertDetail(domain);
        } catch (e) { /* old browser, skip */ }
    }

    // ⌘K jump-and-flash: scroll the named row into view and pulse it. Distinct
    // from ?cert= (which opens the detail panel) — flashing just locates the row
    // so the user can act on it. Returns false if the row is absent or hidden
    // (e.g. the client view is active), so the caller can fall back to a reload.
    function flashCertRow(domain) {
        if (!domain) return false;
        var sel = (window.CSS && CSS.escape) ? CSS.escape(domain) : domain.replace(/"/g, '\\"');
        var row = document.querySelector('#certificatesList tr[data-row-domain="' + sel + '"]');
        if (!row || row.offsetParent === null) return false;
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.classList.remove('cmd-flash');
        void row.offsetWidth;            // reflow so the animation restarts on repeat jumps
        row.classList.add('cmd-flash');
        setTimeout(function () { row.classList.remove('cmd-flash'); }, 1900);
        return true;
    }

    // Cross-page jump-and-flash: the palette navigates to /?flash=<domain> when
    // the user isn't already on the dashboard. Flash once, then strip the param
    // so a refresh doesn't re-trigger it.
    function maybeFlashCertFromQuery() {
        try {
            var params = new URLSearchParams(window.location.search);
            var domain = params.get('flash');
            if (!domain) return;
            params.delete('flash');
            var qs = params.toString();
            history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : '') + window.location.hash);
            flashCertRow(domain);
        } catch (e) { /* old browser, skip */ }
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Paint the stats-card skeleton placeholders before the cert
        // fetch returns, so the surface is never an empty grid — count
        // is driven by STAT_METRICS_COUNT to stay in sync with the
        // updateStats() output (B4 fix).
        var statsContainer = document.getElementById('statsCards');
        if (statsContainer) statsContainer.innerHTML = statsSkeletonHtml(STAT_METRICS_COUNT);

        // Resolve the caller's role first so the initial cert list can
        // already render with the right buttons hidden — avoids the
        // viewer briefly seeing admin-only controls before they vanish.
        refreshCurrentRole().then(function () { loadCertificates().then(function () { maybeOpenCertFromQuery(); maybeFlashCertFromQuery(); }); });
        loadProviderAccounts();

        // Initialize the status filter (free-text search moved to the ⌘K palette)
        document.getElementById('statusFilter').addEventListener('change', filterCertificates);
        document.getElementById('domain').addEventListener('input', updateDnsAliasHelp);
        document.getElementById('san_domains').addEventListener('input', updateDnsAliasHelp);
        document.getElementById('wildcard-cert').addEventListener('change', updateDnsAliasHelp);
        document.getElementById('dns_alias_domain').addEventListener('input', updateDnsAliasHelp);
        document.getElementById('check_dns_alias_button').addEventListener('click', checkDnsAliasFromForm);
        updateDnsAliasHelp();

        // Close modal on outside click
        document.getElementById('curlModal').addEventListener('click', function (e) {
            if (e.target === this) {
                this.classList.add('hidden');
            }
        });

        // Listen for certificate updates from other pages (e.g., settings page)
        try {
            if (typeof BroadcastChannel !== 'undefined') {
                var channel = new BroadcastChannel('certmate_updates');
                channel.addEventListener('message', function (event) {
                    if (event.data && event.data.type === 'certificates_restored') {
                        addDebugLog('Certificates updated from another page - refreshing list...', 'info');
                        setTimeout(function () {
                            loadCertificates();
                            showMessage('Certificate list refreshed - certificates have been restored!', 'success');
                        }, 1000);
                    }
                });
            }

            window.addEventListener('storage', function (event) {
                if (event.key === 'certificates_updated') {
                    addDebugLog('Certificates updated detected - refreshing list...', 'info');
                    setTimeout(function () {
                        loadCertificates();
                        showMessage('Certificate list refreshed - certificates have been updated!', 'success');
                    }, 1000);
                    localStorage.removeItem('certificates_updated');
                }
            });

        } catch (e) {
            // Cross-page communication not available
        }

        setupCacheSettingsListener();
    });

    // Expose functions needed by HTML onclick handlers and SSE
    window.loadCertificates = loadCertificates;
    window.openCertDetail = openCertDetail;
    window.certRowKey = certRowKey;
    window.startEditReissue = startEditReissue;
    window.cancelEditReissue = cancelEditReissue;
    window.closeCertDetail = closeCertDetail;
    window.renewCertificate = renewCertificate;
    window.toggleAutoRenew = toggleAutoRenew;
    window.deleteCertificate = deleteCertificate;
    window.runDeployHooks = runDeployHooks;
    window.downloadCertificate = downloadCertificate;
    window.copyCurlCommand = copyCurlCommand;
    window.checkDeploymentStatus = checkDeploymentStatus;
    window.closeCurlModal = closeCurlModal;
    window.copyFromModal = copyFromModal;
    window.clearFilters = clearFilters;
    window.sortCertificates = sortCertificates;
    window.filterCertificates = filterCertificates;
    window.toggleDebugConsole = toggleDebugConsole;
    window.clearDebugConsole = clearDebugConsole;
    window.showCacheStats = showCacheStats;
    window.invalidateAllCache = invalidateAllCache;
    window.checkAllDeploymentStatuses = checkAllDeploymentStatuses;
    window.toggleAdvancedOptions = toggleAdvancedOptions;
    window.toggleCertKeyOptions = toggleCertKeyOptions;
    window.toggleDnsProviderVisibility = toggleDnsProviderVisibility;
    window.updateAccountSelection = updateAccountSelection;
    window.updateCAProviderInfo = updateCAProviderInfo;
    window.updateDnsAliasHelp = updateDnsAliasHelp;
    window.checkDnsAliasForCertificate = checkDnsAliasForCertificate;
    window.copyAliasValueToClipboard = copyAliasValueToClipboard;
    window.retryCreateJob = retryCreateJob;
    window.dismissPendingJob = dismissPendingJob;
    window.flashCertRow = flashCertRow;
})();
