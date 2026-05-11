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
        document.getElementById('progressBar').style.width = '0%';
        modal.classList.remove('hidden');

        // Simulate progress for better UX
        var progress = 0;
        var progressInterval = setInterval(function () {
            progress += Math.random() * 15;
            if (progress > 90) progress = 90; // Don't complete until actual completion
            document.getElementById('progressBar').style.width = progress + '%';
        }, 1000);

        return progressInterval;
    }

    // Hide loading modal and complete progress
    function hideLoadingModal(progressInterval) {
        document.getElementById('progressBar').style.width = '100%';
        setTimeout(function () {
            document.getElementById('loadingModal').classList.add('hidden');
            if (progressInterval) clearInterval(progressInterval);
        }, 500);
    }

    // Show message function with improved styling
    function showMessage(message, type) {
        CertMate.toast(message, type);
    }

    // Clear filters function
    function clearFilters() {
        document.getElementById('certificateSearch').value = '';
        document.getElementById('statusFilter').value = 'all';
        filterCertificates();
    }

    // Update statistics cards with deployment info
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
        var html = CertMate.html;
        var raw = CertMate.raw;

        function statCard(label, value, color, icon, valueId) {
            return html`
                <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm rounded-lg border border-gray-200 dark:border-gray-700 hover:shadow-md transition-shadow duration-200">
                    <div class="p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <div class="w-12 h-12 bg-${raw(color)}-100 dark:bg-${raw(color)}-900/30 rounded-lg flex items-center justify-center">
                                    <i class="fas ${raw(icon)} text-${raw(color)}-600 dark:text-${raw(color)}-400 text-xl"></i>
                                </div>
                            </div>
                            <div class="ml-4 flex-1">
                                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">${label}</p>
                                <p class="text-2xl font-bold text-${raw(color)}-600 dark:text-${raw(color)}-400"${valueId ? raw(' id="' + valueId + '"') : ''}>${value}</p>
                            </div>
                        </div>
                    </div>
                </div>`;
        }

        statsContainer.innerHTML = [
            // The Total card uses the gray-on-white treatment from the original
            // (text-gray-900 / text-white instead of color-tinted), so we render
            // it with a hand-rolled value paragraph.
            html`
                <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm rounded-lg border border-gray-200 dark:border-gray-700 hover:shadow-md transition-shadow duration-200">
                    <div class="p-6"><div class="flex items-center">
                        <div class="flex-shrink-0"><div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                            <i class="fas fa-certificate text-blue-600 dark:text-blue-400 text-xl"></i>
                        </div></div>
                        <div class="ml-4 flex-1">
                            <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Total Certificates</p>
                            <p class="text-2xl font-bold text-gray-900 dark:text-white">${total}</p>
                        </div>
                    </div></div>
                </div>`,
            statCard('Valid', valid, 'green', 'fa-check-circle'),
            statCard('Expiring Soon', expiring, 'yellow', 'fa-exclamation-triangle'),
            statCard('Deployment', raw('--'), 'indigo', 'fa-globe', 'deploymentCount')
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

    // Filter and search certificates
    function filterCertificates() {
        var searchTerm = document.getElementById('certificateSearch').value.toLowerCase();
        var statusFilter = document.getElementById('statusFilter').value;

        // Ensure allCertificates is an array
        if (!Array.isArray(allCertificates)) {
            allCertificates = [];
        }

        var filteredCerts = allCertificates.filter(function (cert) {
            // Search filter
            var matchesSearch = cert.domain.toLowerCase().indexOf(searchTerm) !== -1;

            // Status filter
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

            return matchesSearch && matchesStatus;
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
        // Update sort icons
        document.querySelectorAll('[id^="sort-icon-"]').forEach(function (icon) {
            icon.className = 'fas fa-sort ml-1 text-gray-400';
        });
        var activeIcon = document.getElementById('sort-icon-' + field);
        if (activeIcon) {
            activeIcon.className = 'fas fa-sort-' + (currentSort.dir === 'asc' ? 'up' : 'down') + ' ml-1 text-primary';
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
        return '<button type="button" data-action="toggle-auto-renew" data-domain="' + safeDomain +
            '" data-auto-renew="' + (autoRenewEnabled ? 'true' : 'false') + '" onclick="event.stopPropagation()" ' +
            'class="p-1.5 ' + color + ' rounded hover:bg-gray-100 dark:hover:bg-gray-700" ' +
            'title="' + title + '"><i class="fas ' + icon + '"></i></button>';
    }

    // Build deployment status badge HTML
    function deploymentBadgeHtml(cert) {
        var safeDomain = escapeHtml(cert.domain);
        var domainId = safeDomain.replace(/\./g, '-');
        var cachedStatus = deploymentCache.get(cert.domain);
        if (cachedStatus) {
            var sc, si, st;
            if (cachedStatus.deployed && cachedStatus.certificate_match) {
                sc = 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400'; si = 'fa-check-circle'; st = 'Deployed';
            } else if (cachedStatus.reachable && !cachedStatus.certificate_match) {
                sc = 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400'; si = 'fa-exclamation-triangle'; st = 'Wrong Cert';
            } else if (!cachedStatus.reachable) {
                sc = 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400'; si = 'fa-times-circle'; st = 'Not Deployed';
            } else {
                sc = 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'; si = 'fa-question-circle'; st = 'Unknown';
            }
            return '<span id="deployment-status-' + domainId + '" class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ' + sc + '"><i class="fas ' + si + ' mr-1"></i>' + st + '</span>';
        }
        return '<span id="deployment-status-' + domainId + '" class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300"><i class="fas fa-spinner fa-spin mr-1"></i>Checking...</span>';
    }

    function providerDisplayName(provider) {
        var safeProvider = escapeHtml(provider || '');
        return safeProvider ? safeProvider.charAt(0).toUpperCase() + safeProvider.slice(1) : '';
    }

    function displayCertificates(certificates) {
        var container = document.getElementById('certificatesList');
        var thead = document.querySelector('#certificatesTable thead');

        if (!Array.isArray(certificates)) {
            certificates = [];
        }

        if (certificates.length === 0) {
            var isFiltered = document.getElementById('certificateSearch').value ||
                document.getElementById('statusFilter').value !== 'all';
            thead.style.display = 'none';

            if (isFiltered) {
                container.innerHTML = '<tr><td colspan="6">' +
                    '<div class="px-6 py-12 text-center">' +
                    '<div class="mx-auto max-w-sm">' +
                    '<div class="mx-auto h-16 w-16 flex items-center justify-center bg-gray-100 dark:bg-gray-700 rounded-full mb-4">' +
                    '<i class="fas fa-search text-gray-400 text-2xl"></i>' +
                    '</div>' +
                    '<h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">No matching certificates</h3>' +
                    '<p class="text-gray-500 dark:text-gray-400 mb-6">Try adjusting your search criteria or filters.</p>' +
                    '<button onclick="clearFilters()" class="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600">' +
                    '<i class="fas fa-times mr-2"></i>Clear Filters</button>' +
                    '</div>' +
                    '</div>' +
                    '</td></tr>';
            } else {
                container.innerHTML = '<tr><td colspan="6">' +
                    '<div class="px-6 py-8"><div class="mx-auto max-w-lg">' +
                    '<div class="text-center mb-6">' +
                    '<div class="mx-auto h-16 w-16 flex items-center justify-center bg-blue-100 dark:bg-blue-900/30 rounded-full mb-4"><i class="fas fa-rocket text-blue-500 text-2xl"></i></div>' +
                    '<h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">Welcome to CertMate</h3>' +
                    '<p class="text-gray-500 dark:text-gray-400">Follow these steps to get started:</p>' +
                    '</div>' +
                    '<ol class="space-y-3 mb-6 text-sm">' +
                    '<li class="flex items-start"><span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-500 text-white rounded-full text-xs font-bold mr-3 mt-0.5">1</span>' +
                    '<span class="text-gray-700 dark:text-gray-300"><a href="/settings" class="text-blue-600 dark:text-blue-400 font-medium hover:underline">Go to Settings</a> and configure your DNS provider</span></li>' +
                    '<li class="flex items-start"><span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-500 text-white rounded-full text-xs font-bold mr-3 mt-0.5">2</span>' +
                    '<span class="text-gray-700 dark:text-gray-300">Add a domain above and create your first SSL certificate</span></li>' +
                    '<li class="flex items-start"><span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-500 text-white rounded-full text-xs font-bold mr-3 mt-0.5">3</span>' +
                    '<span class="text-gray-700 dark:text-gray-300">Enable <a href="/settings#users" class="text-blue-600 dark:text-blue-400 font-medium hover:underline">Local Authentication</a> in Settings to secure your instance</span></li>' +
                    '</ol>' +
                    '<div class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-3 mb-6">' +
                    '<p class="text-xs text-amber-800 dark:text-amber-200"><i class="fas fa-shield-alt mr-1"></i><strong>Security:</strong> Authentication is disabled by default. Enable it before exposing CertMate to the internet.</p>' +
                    '</div>' +
                    '<div class="text-center"><button onclick="document.getElementById(\'domain\').focus()" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary hover:bg-secondary"><i class="fas fa-plus mr-2"></i>Create Certificate</button></div>' +
                    '</div></div>' +
                    '</td></tr>';
            }
            return;
        }

        thead.style.display = '';
        var sorted = applySorting(certificates);

        var rowHtml = CertMate.html;
        var rowRaw = CertMate.raw;

        // Action button shorthand. cert.domain flows in raw \u2014 the helper
        // escapes it for both the data-domain attribute and the onclick
        // arg, so we no longer pre-compute a `safeDomain`.
        function actionBtn(action, domain, hoverColor, title, icon) {
            return rowHtml`<button type="button" data-action="${action}" data-domain="${domain}" onclick="event.stopPropagation()" class="p-1.5 text-gray-400 hover:text-${rowRaw(hoverColor)}-600 dark:hover:text-${rowRaw(hoverColor)}-400 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="${title}"><i class="fas ${rowRaw(icon)}"></i></button>`;
        }

        container.innerHTML = sorted.map(function (cert) {
            // providerDisplayName(...) already calls escapeHtml internally —
            // when interpolating into the rowHtml template we wrap it with
            // rowRaw() to opt out of re-escaping. cert.domain and
            // cert.domain_alias flow in unescaped; the helper escapes them.
            var providerLabel = providerDisplayName(cert.dns_provider);
            var domainAlias = cert.domain_alias || '';

            if (!cert.exists) {
                return rowHtml`<tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer" onclick="openCertDetail('${cert.domain}')">
                    <td class="px-6 py-4 whitespace-nowrap"><div class="text-sm font-medium text-gray-900 dark:text-white">${cert.domain}</div></td>
                    <td class="px-4 py-4 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400"><i class="fas fa-times-circle mr-1"></i>Not Found</span></td>
                    <td class="px-4 py-4 whitespace-nowrap hidden md:table-cell text-sm text-gray-500 dark:text-gray-400">\u2014</td>
                    <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-gray-500 dark:text-gray-400">${providerLabel || '\u2014'}</td>
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
            var statusClass, statusIcon, statusText;
            if (isExpired) {
                statusClass = 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400'; statusIcon = 'fa-times-circle'; statusText = 'Expired';
            } else if (isExpiringSoon) {
                statusClass = 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400'; statusIcon = 'fa-exclamation-triangle'; statusText = 'Expiring';
            } else {
                statusClass = 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400'; statusIcon = 'fa-check-circle'; statusText = 'Valid';
            }

            var expiryDate = new Date(cert.expiry_date);
            var expiryStr = expiryDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
            var daysClass = isExpired ? 'text-red-600 dark:text-red-400' : isExpiringSoon ? 'text-yellow-600 dark:text-yellow-400' : 'text-gray-500 dark:text-gray-400';

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
            return rowHtml`<tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors duration-150 cursor-pointer" onclick="openCertDetail('${cert.domain}')">
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                        <i class="fas fa-certificate text-gray-400 dark:text-gray-500 mr-2 text-sm" aria-hidden="true"></i>
                        <div class="min-w-0">
                            <div class="text-sm font-medium text-gray-900 dark:text-white">${cert.domain}</div>
                            ${domainAlias ? rowHtml`<div class="mt-1 flex items-center text-xs text-blue-600 dark:text-blue-300 min-w-0"><i class="fas fa-link mr-1 text-blue-500" aria-hidden="true"></i><span class="truncate" title="${domainAlias}">DNS-01 Alias: ${domainAlias}</span></div>` : false}
                        </div>
                    </div>
                </td>
                <td class="px-4 py-4 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${rowRaw(statusClass)}"><i class="fas ${rowRaw(statusIcon)} mr-1"></i>${statusText}</span></td>
                <td class="px-4 py-4 whitespace-nowrap hidden md:table-cell"><div class="text-sm text-gray-900 dark:text-white">${expiryStr}</div><div class="text-xs ${rowRaw(daysClass)}">${cert.days_until_expiry} days</div></td>
                <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell text-sm text-gray-500 dark:text-gray-400">${rowRaw(providerLabel) || '—'}</td>
                <td class="px-4 py-4 whitespace-nowrap hidden lg:table-cell">${rowRaw(deploymentBadgeHtml(cert))}</td>
                <td class="px-4 py-4 whitespace-nowrap text-right">
                    <div class="flex items-center justify-end gap-1">
                        ${roleAtLeast('operator') ? actionBtn('renew', cert.domain, 'green', 'Renew', 'fa-sync-alt') : false}
                        ${actionBtn('download', cert.domain, 'blue', 'Download', 'fa-download')}
                        ${actionBtn('curl', cert.domain, 'indigo', 'API', 'fa-code')}
                        ${roleAtLeast('operator') ? rowRaw(autoRenewButtonHtml(escapeHtml(cert.domain), cert.auto_renew !== false)) : false}
                        ${roleAtLeast('admin') ? actionBtn('delete', cert.domain, 'red', 'Delete certificate', 'fa-trash-alt') : false}
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
                    case 'download': downloadCertificate(domain); break;
                    case 'curl': copyCurlCommand(domain); break;
                    case 'toggle-auto-renew':
                        toggleAutoRenew(domain, btn.dataset.autoRenew === 'true');
                        break;
                    case 'delete': deleteCertificate(domain); break;
                }
            });
        });

        // Trigger deployment checks for uncached certs
        setTimeout(function () {
            if (Array.isArray(certificates)) {
                certificates.filter(function (c) { return c.exists; }).forEach(function (c) {
                    if (!deploymentCache.get(c.domain)) {
                        checkDeploymentStatus(c.domain);
                    }
                });
            }
        }, 100);
    }

    // Certificate detail slide-out panel
    function openCertDetail(domain) {
        var cert = allCertificates.find(function (c) { return c.domain === domain; });
        if (!cert) return;

        var panel = document.getElementById('certDetailPanel');
        var overlay = document.getElementById('certDetailOverlay');
        var content = document.getElementById('certDetailContent');
        document.getElementById('detailDomain').textContent = cert.domain;

        var safeDomain = escapeHtml(cert.domain);
        var providerLabel = providerDisplayName(cert.dns_provider);
        var safeDomainAlias = escapeHtml(cert.domain_alias || '');
        var aliasProviderLabel = providerDisplayName(cert.alias_dns_provider);
        var sanDomains = Array.isArray(cert.san_domains) ? cert.san_domains : [];
        var sanDomainsHtml = sanDomains.map(function (san) {
            return '<div class="break-all">' + escapeHtml(san) + '</div>';
        }).join('');

        if (!cert.exists) {
            content.innerHTML = '<div class="text-center py-8"><i class="fas fa-exclamation-triangle text-red-400 text-3xl mb-3"></i>' +
                '<p class="text-gray-500 dark:text-gray-400 mb-6">Certificate not found on disk.</p>' +
                (roleAtLeast('admin')
                    ? '<button type="button" onclick="deleteCertificate(\'' + safeDomain + '\')" class="inline-flex items-center px-4 py-2 border border-red-300 dark:border-red-700 shadow-sm text-sm font-medium rounded-md text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40"><i class="fas fa-trash-alt mr-2"></i>Remove from List</button>'
                    : '<p class="text-xs text-gray-400">Ask an admin to remove this entry.</p>') +
                '</div>';
        } else {
            var daysKnown2 = cert.days_until_expiry !== null && cert.days_until_expiry !== undefined;
            var isExpired = daysKnown2 && cert.days_until_expiry <= 0;
            var isExpiringSoon = daysKnown2 && cert.days_until_expiry > 0 && cert.days_until_expiry <= 30;
            var expiryDate = new Date(cert.expiry_date);
            var statusClass, statusText;
            if (isExpired) { statusClass = 'text-red-600 dark:text-red-400'; statusText = 'Expired'; }
            else if (isExpiringSoon) { statusClass = 'text-yellow-600 dark:text-yellow-400'; statusText = 'Expiring Soon'; }
            else { statusClass = 'text-green-600 dark:text-green-400'; statusText = 'Valid'; }

            content.innerHTML =
                '<div class="space-y-6">' +
                // Status banner
                '<div class="flex items-center justify-between p-4 rounded-lg ' +
                (isExpired ? 'bg-red-50 dark:bg-red-900/20' : isExpiringSoon ? 'bg-yellow-50 dark:bg-yellow-900/20' : 'bg-green-50 dark:bg-green-900/20') + '">' +
                '<div><div class="text-sm font-medium ' + statusClass + '">' + statusText + '</div>' +
                '<div class="text-2xl font-bold ' + statusClass + '">' + cert.days_until_expiry + ' days</div></div>' +
                '<i class="fas ' + (isExpired ? 'fa-times-circle' : isExpiringSoon ? 'fa-exclamation-triangle' : 'fa-check-circle') + ' text-3xl ' + statusClass + '"></i>' +
                '</div>' +
                // Details grid
                '<div class="space-y-3">' +
                '<h4 class="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">Details</h4>' +
                '<dl class="space-y-2">' +
                '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">Domain</dt><dd class="text-sm font-medium text-right text-gray-900 dark:text-white">' + safeDomain + '</dd></div>' +
                (sanDomains.length ? '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">SANs</dt><dd class="text-sm font-medium text-right text-gray-900 dark:text-white">' + sanDomainsHtml + '</dd></div>' : '') +
                '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">Expires</dt><dd class="text-sm font-medium text-right text-gray-900 dark:text-white">' + expiryDate.toLocaleDateString(undefined, { weekday: 'short', month: 'long', day: 'numeric', year: 'numeric' }) + '</dd></div>' +
                (providerLabel ? '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">DNS Provider</dt><dd class="text-sm font-medium text-right text-gray-900 dark:text-white">' + providerLabel + '</dd></div>' : '') +
                (safeDomainAlias ? '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">DNS-01 Alias</dt><dd class="text-sm font-medium text-right break-all text-blue-600 dark:text-blue-300">' + safeDomainAlias + '</dd></div>' : '') +
                (safeDomainAlias && aliasProviderLabel ? '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">Alias Provider</dt><dd class="text-sm font-medium text-right text-gray-900 dark:text-white">' + aliasProviderLabel + '</dd></div>' : '') +
                '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">Auto-Renew</dt><dd class="text-sm font-medium text-right ' + (cert.auto_renew !== false ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400') + '">' + (cert.auto_renew !== false ? 'Enabled' : 'Disabled') + '</dd></div>' +
                '<div class="flex justify-between gap-4 py-2 border-b dark:border-gray-700"><dt class="text-sm text-gray-500 dark:text-gray-400">Deployment</dt><dd>' + deploymentBadgeHtml(cert) + '</dd></div>' +
                '</dl>' +
                '</div>' +
                // Actions
                '<div class="space-y-3">' +
                '<h4 class="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">Actions</h4>' +
                '<div class="grid grid-cols-1 gap-2">' +
                (roleAtLeast('operator')
                    ? '<button type="button" onclick="renewCertificate(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"><i class="fas fa-sync-alt mr-2 text-green-600"></i>Renew Certificate</button>'
                    : '') +
                '<button type="button" onclick="downloadCertificate(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"><i class="fas fa-download mr-2 text-blue-600"></i>Download Certificate</button>' +
                '<button type="button" onclick="copyCurlCommand(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-blue-300 dark:border-blue-600 shadow-sm text-sm font-medium rounded-md text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 hover:bg-blue-100 dark:hover:bg-blue-900/50"><i class="fas fa-code mr-2"></i>Show API Command</button>' +
                '<button type="button" onclick="checkDeploymentStatus(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"><i class="fas fa-globe mr-2 text-indigo-600"></i>Check Deployment</button>' +
                (safeDomainAlias ? '<button type="button" onclick="checkDnsAliasForCertificate(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-blue-300 dark:border-blue-600 shadow-sm text-sm font-medium rounded-md text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 hover:bg-blue-100 dark:hover:bg-blue-900/50"><i class="fas fa-search mr-2"></i>Check DNS-01 Alias</button>' : '') +
                '<div id="cert_dns_alias_check_result" class="hidden"></div>' +
                (roleAtLeast('admin')
                    ? '<button type="button" onclick="runDeployHooks(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"><i class="fas fa-rocket mr-2 text-green-600"></i>Run Deploy Hooks Now</button>'
                    : '') +
                (roleAtLeast('operator')
                    ? '<button type="button" onclick="toggleAutoRenew(\'' + safeDomain + '\', ' + (cert.auto_renew !== false ? 'true' : 'false') + ')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"><i class="fas ' + (cert.auto_renew !== false ? 'fa-toggle-on text-purple-600' : 'fa-toggle-off text-amber-600') + ' mr-2"></i>' + (cert.auto_renew !== false ? 'Disable Auto-Renew' : 'Enable Auto-Renew') + '</button>'
                    : '') +
                (roleAtLeast('admin')
                    ? '<button type="button" onclick="deleteCertificate(\'' + safeDomain + '\')" class="w-full inline-flex items-center justify-center px-4 py-2 border border-red-300 dark:border-red-700 shadow-sm text-sm font-medium rounded-md text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40"><i class="fas fa-trash-alt mr-2"></i>Delete Certificate</button>'
                    : '') +
                '</div>' +
                '</div>' +
                '</div>';
        }

        overlay.classList.remove('hidden');
        requestAnimationFrame(function () {
            panel.classList.remove('translate-x-full');
        });
    }

    function closeCertDetail() {
        var panel = document.getElementById('certDetailPanel');
        var overlay = document.getElementById('certDetailOverlay');
        panel.classList.add('translate-x-full');
        setTimeout(function () { overlay.classList.add('hidden'); }, 300);
    }

    // Close detail panel on Escape key
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
            var statusElement = document.getElementById('deployment-status-' + cert.domain.replace(/\./g, '-'));
            var isDeployed = statusElement && statusElement.textContent.indexOf('Deployed') !== -1;
            return isDeployed;
        }).length;

        var deploymentCountElement = document.getElementById('deploymentCount');
        if (deploymentCountElement) {
            deploymentCountElement.textContent = deployedCount;
        }

        addDebugLog('Statistics updated: ' + deployedCount + ' certificates actively deployed', 'success');
    }

    // Check deployment status for all certificates
    function checkAllDeploymentStatuses() {
        var button = event.target;
        var originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Checking...';
        button.disabled = true;

        // Ensure allCertificates is an array
        if (!Array.isArray(allCertificates)) {
            allCertificates = [];
        }

        var certificatesToCheck = allCertificates.filter(function (cert) { return cert.exists; });

        if (certificatesToCheck.length === 0) {
            showMessage('No certificates found to check', 'info');
            button.innerHTML = originalText;
            button.disabled = false;
            return;
        }

        // Update button to show progress
        var completed = 0;
        var total = certificatesToCheck.length;

        function updateProgress() {
            var percentage = Math.round((completed / total) * 100);
            button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Checking... ' + completed + '/' + total + ' (' + percentage + '%)';
        }

        // Check certificates in batches to avoid overwhelming the server
        var batchSize = 3;
        var batches = [];
        for (var i = 0; i < certificatesToCheck.length; i += batchSize) {
            batches.push(certificatesToCheck.slice(i, i + batchSize));
        }

        var batchIndex = 0;
        function processBatch() {
            if (batchIndex >= batches.length) {
                updateDeploymentStats();
                showMessage('Deployment status updated for ' + total + ' certificates', 'success');
                button.innerHTML = originalText;
                button.disabled = false;
                return;
            }

            var batch = batches[batchIndex];
            var batchPromises = batch.map(function (cert) {
                return checkDeploymentStatus(cert.domain).then(function () {
                    completed++;
                    updateProgress();
                }).catch(function () {
                    completed++;
                    updateProgress();
                });
            });

            Promise.all(batchPromises).then(function () {
                batchIndex++;
                if (batchIndex < batches.length) {
                    setTimeout(processBatch, 500);
                } else {
                    processBatch();
                }
            });
        }

        processBatch();
    }

    // Check deployment status for a specific domain
    function checkDeploymentStatus(domain) {
        var statusElement = document.getElementById('deployment-status-' + domain.replace(/\./g, '-'));
        var textElement = document.getElementById('deployment-text-' + domain.replace(/\./g, '-'));

        if (!statusElement) {
            return Promise.resolve();
        }

        // Check cache first
        var cachedResult = deploymentCache.get(domain);
        if (cachedResult) {
            updateDeploymentUI(domain, cachedResult, statusElement);
            return Promise.resolve();
        }

        // Update UI to show checking state
        statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-600';
        statusElement.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Checking...';
        if (textElement) {
            textElement.textContent = 'Checking...';
            textElement.className = 'text-sm font-medium text-blue-600';
        }

        return fetch('/api/certificates/' + encodeURIComponent(domain) + '/deployment-status', {
            method: 'GET',
            headers: API_HEADERS
        }).then(function (response) {
            if (response.ok) {
                return response.json().then(function (result) {
                    deploymentCache.set(domain, result);
                    updateDeploymentUI(domain, result, statusElement);
                });
            }
            throw new Error('API failed');
        }).catch(function (apiError) {
            // Fallback to browser-based certificate check
            return checkDeploymentViaBrowser(domain).then(function (result) {
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
                deploymentCache.set(domain, result);
                updateDeploymentUI(domain, result, statusElement);
            });
        }).catch(function () {
            statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300';
            statusElement.innerHTML = '<i class="fas fa-question-circle mr-1"></i>Error';
        });
    }

    // Browser-based certificate check fallback
    function checkDeploymentViaBrowser(domain) {
        var controller = new AbortController();
        var timeoutId = setTimeout(function () { controller.abort(); }, 10000);

        return fetch('https://' + domain, {
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
    function updateDeploymentUI(domain, result, statusElement) {
        var textElement = document.getElementById('deployment-text-' + domain.replace(/\./g, '-'));

        if (result.deployed && result.certificate_match !== false) {
            statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400';
            statusElement.innerHTML = '<i class="fas fa-check-circle mr-1"></i>Deployed';
            if (textElement) {
                textElement.textContent = 'Active';
                textElement.className = 'text-sm font-medium text-green-600 dark:text-green-400';
            }

        } else if (result.reachable && result.certificate_match === false) {
            statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400';
            statusElement.innerHTML = '<i class="fas fa-exclamation-triangle mr-1"></i>Mismatch';
            if (textElement) {
                textElement.textContent = 'Mismatch';
                textElement.className = 'text-sm font-medium text-yellow-600 dark:text-yellow-400';
            }

        } else if (result.reachable) {
            statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400';
            statusElement.innerHTML = '<i class="fas fa-info-circle mr-1"></i>Unknown';
            if (textElement) {
                textElement.textContent = 'Unknown';
                textElement.className = 'text-sm font-medium text-blue-600 dark:text-blue-400';
            }

        } else {
            statusElement.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400';
            statusElement.innerHTML = '<i class="fas fa-times-circle mr-1"></i>Unreachable';
            if (textElement) {
                textElement.textContent = 'Unreachable';
                textElement.className = 'text-sm font-medium text-red-600 dark:text-red-400';
            }
        }

        // Add method info to title for debugging
        if (result.method) {
            statusElement.title = 'Checked via: ' + result.method + ' at ' + result.timestamp;
            if (textElement) {
                textElement.title = statusElement.title;
            }
        }
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

            // Check deployment status for all certificates after a short delay
            addDebugLog('Scheduling automatic deployment status checks...', 'info');

            setTimeout(function () {
                addDebugLog('Starting automatic deployment status checks for all certificates', 'info');

                var existingCerts = certificates.filter(function (cert) { return cert.exists; });
                if (existingCerts.length > 0) {
                    var promises = existingCerts.map(function (cert) { return checkDeploymentStatus(cert.domain); });
                    Promise.all(promises).then(function () {
                        updateDeploymentStats();
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

    // Listen for cache settings updates from settings page
    function setupCacheSettingsListener() {
        var lastUpdate = localStorage.getItem('cache-settings-updated');
        var lastClearSignal = localStorage.getItem('clear-deployment-cache');

        setInterval(function () {
            // Check for settings updates
            var currentUpdate = localStorage.getItem('cache-settings-updated');
            if (currentUpdate && currentUpdate !== lastUpdate) {
                deploymentCache.loadSettings();
                addDebugLog('Cache settings updated from settings page', 'info');
                lastUpdate = currentUpdate;
            }

            // Check for cache clear signals
            var currentClearSignal = localStorage.getItem('clear-deployment-cache');
            if (currentClearSignal && currentClearSignal !== lastClearSignal) {
                deploymentCache.clear();
                addDebugLog('Deployment cache cleared by admin request', 'warn');
                // Re-check all certificates
                setTimeout(function () {
                    if (Array.isArray(allCertificates) && allCertificates.length > 0) {
                        addDebugLog('Re-checking all certificates after cache clear...', 'info');
                        var existingCerts = allCertificates.filter(function (cert) { return cert.exists; });
                        existingCerts.forEach(function (cert) { checkDeploymentStatus(cert.domain); });
                    }
                }, 1000);
                lastClearSignal = currentClearSignal;
            }
        }, 2000);
    }

    // Multi-account support functions
    var providerAccounts = {};

    function loadProviderAccounts() {
        var providers = ['cloudflare', 'route53', 'digitalocean', 'azure', 'google', 'powerdns', 'rfc2136'];

        providers.forEach(function (provider) {
            fetch('/api/settings/dns-providers/' + provider + '/accounts', {
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
                case 'zerossl':
                    infoText = '<i class="fas fa-certificate mr-1 text-yellow-500"></i> Free certificates with 90-day validity via ZeroSSL (requires EAB)';
                    break;
                case 'google':
                    infoText = '<i class="fab fa-google mr-1 text-blue-500"></i> Free certificates from Google Trust Services (requires EAB)';
                    break;
                case 'buypass':
                    infoText = '<i class="fas fa-lock mr-1 text-green-500"></i> Free certificates with 180-day validity from BuyPass Go';
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

        if (optionsDiv.classList.contains('hidden')) {
            optionsDiv.classList.remove('hidden');
            chevron.classList.add('rotate-180');
        } else {
            optionsDiv.classList.add('hidden');
            chevron.classList.remove('rotate-180');
        }
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

    function normalizeDnsName(value) {
        return (value || '').trim().replace(/^\*\./, '').replace(/\.+$/, '');
    }

    function normalizeDnsAliasName(value) {
        return normalizeDnsName(value).replace(/^_acme-challenge\./i, '');
    }

    function parseSanDomainsInput(value) {
        return value
            ? value.split(',').map(function (d) { return d.trim(); }).filter(function (d) { return d; })
            : [];
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
            ? 'text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
            : 'text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
        var icon = ok ? 'fa-check-circle' : 'fa-times-circle';
        var title = ok ? 'All DNS-01 alias CNAMEs are present' : 'DNS-01 alias CNAMEs need attention';

        var rows = checks.map(function (check) {
            var rowClass = check.ok ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300';
            var found = check.found_targets && check.found_targets.length
                ? check.found_targets.join(', ')
                : 'No CNAME found';
            if (check.error) {
                found = check.error;
            }
            return '<div class="mt-2 text-xs ' + rowClass + '">' +
                '<div><i class="fas ' + (check.ok ? 'fa-check' : 'fa-times') + ' mr-1"></i>' +
                '<code class="font-mono bg-gray-100 dark:bg-gray-700 px-1 rounded">' + escapeHtml(check.source) + '</code></div>' +
                '<div class="mt-1 ml-5">Expected: <code class="font-mono bg-gray-100 dark:bg-gray-700 px-1 rounded">' + escapeHtml(check.expected_target) + '</code></div>' +
                '<div class="mt-1 ml-5">Found: <code class="font-mono bg-gray-100 dark:bg-gray-700 px-1 rounded">' + escapeHtml(found) + '</code></div>' +
                '</div>';
        }).join('');

        if (!rows) {
            rows = '<div class="mt-2 text-xs text-gray-600 dark:text-gray-300">No DNS-01 alias records to check.</div>';
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
            resultTarget.className = 'mt-2 rounded-md border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20 p-3 text-xs text-blue-700 dark:text-blue-300';
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
            resultTarget.className = 'mt-3 rounded-md border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20 p-3 text-xs text-blue-700 dark:text-blue-300';
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

    // Create certificate
    document.getElementById('createCertForm').addEventListener('submit', function (e) {
        e.preventDefault();

        var domain = document.getElementById('domain').value.trim();
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

        var progressInterval = showLoadingModal(
            'Creating Certificate for ' + domainsDisplay,
            'Validating domain ownership and generating certificate...'
        );

        var requestBody = { domain: domain };
        if (sanDomains.length > 0) {
            requestBody.san_domains = sanDomains;
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
        if (dnsAliasDomain) {
            requestBody.domain_alias = dnsAliasDomain;
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

        fetch('/api/certificates/create', {
            method: 'POST',
            headers: API_HEADERS,
            body: JSON.stringify(requestBody)
        }).then(function (response) {
            return response.json().then(function (result) {
                if (response.ok && result.success !== false) {
                    showMessage('Certificate created successfully for ' + domainsDisplay + '!');
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
                    updateAccountSelection();
                    loadCertificates();
                } else {
                    var errorMsg = result.error || result.message || 'Failed to create certificate';
                    if (result.hint) {
                        errorMsg += '\n\n\ud83d\udca1 ' + result.hint;
                    }
                    showMessage(errorMsg, 'error');
                }
            });
        }).catch(function (error) {
            console.error('Error creating certificate:', error);
            showMessage('Failed to create certificate. Please check your network connection and try again.', 'error');
        }).then(function () {
            hideLoadingModal(progressInterval);
        });
    });

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
    function runDeployHooks(domain) {
        if (!window.confirm('Run deploy hooks for ' + domain + ' now?\n\nAll enabled global and domain-specific hooks will execute with CERTMATE_EVENT=manual.')) {
            return;
        }
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
                showMessage(msg, 'error');
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
        }).then(function () {
            hideLoadingModal(progressInterval);
        });
    }

    // Toggle per-cert auto-renew (issue #111).
    function toggleAutoRenew(domain, currentlyEnabled) {
        var nextState = !currentlyEnabled;
        var verb = nextState ? 'Enable' : 'Disable';
        if (!window.confirm(verb + ' automatic renewal for ' + domain + '?')) {
            return;
        }
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
        if (!window.confirm('Delete certificate for ' + domain + '?\n\nThis removes the certificate files from disk and removes the domain from settings. This action cannot be undone.')) {
            return;
        }
        fetch('/api/certificates/' + encodeURIComponent(domain), {
            method: 'DELETE'
        }).then(function (response) {
            return response.json().then(function (result) {
                return { ok: response.ok, result: result };
            });
        }).then(function (data) {
            if (data.ok) {
                showMessage('Certificate deleted for ' + domain, 'success');
                closeCertDetail();
                loadCertificates();
            } else {
                showMessage(data.result.error || 'Failed to delete certificate', 'error');
            }
        }).catch(function (error) {
            console.error('Error deleting certificate:', error);
            showMessage('Failed to delete certificate. Please try again.', 'error');
        });
    }

    function renewCertificate(domain) {
        var progressInterval = showLoadingModal(
            'Renewing Certificate for ' + domain,
            'This may take a few minutes...'
        );

        fetch('/api/certificates/' + encodeURIComponent(domain) + '/renew', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).then(function (response) {
            return response.json().then(function (result) {
                return { ok: response.ok, result: result };
            });
        }).then(function (data) {
            if (data.ok) {
                showMessage('Certificate renewed successfully for ' + domain + '!', 'success');
                setTimeout(function () { loadCertificates(); }, 2000);
            } else {
                showMessage(data.result.error || data.result.message || 'Failed to renew certificate', 'error');
            }
        }).catch(function (error) {
            console.error('Error renewing certificate:', error);
            showMessage('Failed to renew certificate. Please try again.', 'error');
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

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function () {
        // Resolve the caller's role first so the initial cert list can
        // already render with the right buttons hidden — avoids the
        // viewer briefly seeing admin-only controls before they vanish.
        refreshCurrentRole().then(function () { loadCertificates(); });
        loadProviderAccounts();

        // Initialize search and filters
        document.getElementById('certificateSearch').addEventListener('input', filterCertificates);
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
})();
