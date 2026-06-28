/**
 * Client Certificate Management — static/js/client-certs.js
 * Loaded on the unified certificates page (client tab).
 */
(function() {
    'use strict';

    var escapeHtml = CertMate.escapeHtml;
    var currentCertId = null;
    var certificatesData = [];
    var ccCurrentUsage = '';   // '' = all — driven by the usage filter chips
    var ccCurrentStatus = '';  // '' = all — driven by the status filter chips
    var _initialized = false;

    // Public init — called when client tab becomes visible
    window.initClientCerts = function() {
        if (_initialized) return;
        _initialized = true;
        ccLoadStatistics();
        ccLoadCertificates();
        ccSetupEventListeners();
    };

    function ccSetupEventListeners() {
        var singleBtn = document.getElementById('singleTabBtn');
        var batchBtn = document.getElementById('batchTabBtn');
        if (singleBtn) singleBtn.addEventListener('click', function() { ccSwitchTab('single'); });
        if (batchBtn) batchBtn.addEventListener('click', function() { ccSwitchTab('batch'); });
        if (singleBtn) singleBtn.addEventListener('keydown', ccTabKeydown);
        if (batchBtn) batchBtn.addEventListener('keydown', ccTabKeydown);

        var form = document.getElementById('createClientCertForm');
        if (form) form.addEventListener('submit', ccHandleCreateCert);

        var dropZone = document.getElementById('dropZone');
        if (dropZone) {
            dropZone.addEventListener('click', function() { document.getElementById('csvFile').click(); });
            dropZone.addEventListener('dragover', function(e) {
                e.preventDefault();
                dropZone.classList.add('border-primary', 'bg-blue-50', 'dark:bg-blue-900/20');
            });
            dropZone.addEventListener('dragleave', function() {
                dropZone.classList.remove('border-primary', 'bg-blue-50', 'dark:bg-blue-900/20');
            });
            dropZone.addEventListener('drop', function(e) {
                e.preventDefault();
                dropZone.classList.remove('border-primary', 'bg-blue-50', 'dark:bg-blue-900/20');
                var file = e.dataTransfer.files[0];
                if (file && file.name.endsWith('.csv')) ccHandleCSVFile(file);
            });
        }
        var csvInput = document.getElementById('csvFile');
        if (csvInput) csvInput.addEventListener('change', function(e) {
            if (e.target.files[0]) ccHandleCSVFile(e.target.files[0]);
        });

        var submitBatchBtn = document.getElementById('submitBatchBtn');
        if (submitBatchBtn) submitBatchBtn.addEventListener('click', ccHandleBatchSubmit);
        // Status/usage filtering is driven by the header chips (onclick ->
        // ccSetStatusFilter / ccSetUsageFilter); no select listeners needed.
    }

    function ccLoadStatistics() {
        fetch('/api/client-certs/stats')
            .then(function(r) { return r.json(); })
            .then(function(stats) {
                var el = function(id) { return document.getElementById(id); };
                if (el('totalCount')) el('totalCount').textContent = stats.total || 0;
                if (el('activeCount')) el('activeCount').textContent = stats.active || 0;
                if (el('revokedCount')) el('revokedCount').textContent = stats.revoked || 0;
                // Status filter chip counts (mirror the server chips).
                var setChipCount = function (k, v) { var c = document.querySelector('[data-cc-status-count="' + k + '"]'); if (c) { c.textContent = v; } };
                setChipCount('all', stats.total || 0);
                setChipCount('active', stats.active || 0);
                setChipCount('revoked', stats.revoked || 0);
                var byUsage = stats.by_usage || {};
                var usageText = Object.entries(byUsage).map(function(e) { return e[1] + ' ' + e[0]; }).join(', ') || 'No certs';
                // The strip value truncates to one line; keep the full breakdown
                // available on hover.
                if (el('usageBreakdown')) { el('usageBreakdown').textContent = usageText; el('usageBreakdown').title = usageText; }
            })
            .catch(function(e) { console.error('Error loading client cert statistics:', e); });
    }

    function ccLoadCertificates() {
        fetch('/api/client-certs')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                certificatesData = data.certificates || [];
                ccRenderCertificates();
            })
            .catch(function(e) { console.error('Error loading client certificates:', e); });
    }

    function ccRenderCertificates() {
        var tbody = document.getElementById('certTableBody');
        if (!tbody) return;
        if (certificatesData.length === 0) {
            // Distinguish "none exist yet" (offer a CTA) from "none match the
            // active usage/status filter" (offer a reorientation hint).
            var usageSel = document.getElementById('filterUsage');
            var statusSel = document.getElementById('filterStatus');
            var isFiltered = (usageSel && usageSel.value) || (statusSel && statusSel.value);
            if (isFiltered) {
                tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-12">' +
                    '<div class="mx-auto max-w-sm text-center">' +
                    '<div class="mx-auto h-14 w-14 flex items-center justify-center bg-surface-2 rounded-full mb-3"><i class="fas fa-filter text-gray-400 text-xl" aria-hidden="true"></i></div>' +
                    '<h3 class="text-base font-medium text-foreground mb-1">No matching client certificates</h3>' +
                    '<p class="text-sm text-muted">Try a different usage or status filter.</p>' +
                    '</div></td></tr>';
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-12">' +
                    '<div class="mx-auto max-w-sm text-center">' +
                    '<div class="mx-auto h-16 w-16 flex items-center justify-center bg-info-surface rounded-full mb-4"><i class="fas fa-id-card text-blue-500 text-2xl" aria-hidden="true"></i></div>' +
                    '<h3 class="text-lg font-medium text-foreground mb-2">No client certificates yet</h3>' +
                    '<p class="text-muted mb-6">Issue mTLS / client identity certificates for VPN access, API authentication, or user login.</p>' +
                    '<button type="button" onclick="openCertDrawer(\'client\')" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary hover:bg-secondary"><i class="fas fa-plus mr-2" aria-hidden="true"></i>New Client Certificate</button>' +
                    '</div></td></tr>';
            }
            return;
        }

        tbody.innerHTML = ccApplySort(certificatesData).map(function(cert) {
            var expiresDate = new Date(cert.expires_at);
            var createdDate = new Date(cert.created_at);
            var isExpiringSoon = expiresDate - new Date() < 30 * 24 * 60 * 60 * 1000;
            // Match the server table's coloured left border: revoked = red,
            // expiring-soon = amber, otherwise green (see .health-* in input.css).
            var healthClass = cert.revoked ? 'health-expired' : (isExpiringSoon ? 'health-warning' : 'health-valid');
            var safeCN = escapeHtml(cert.common_name);
            var safeEmail = escapeHtml(cert.email || '-');
            var safeUsage = escapeHtml(cert.cert_usage);
            var safeId = escapeHtml(cert.identifier);

            // Whole row opens the detail modal (role=button + keyboard); the
            // action buttons stopPropagation so they don't also open it.
            return '<tr data-cc-id="' + safeId + '" role="button" tabindex="0" aria-label="View details for ' + safeCN + '" class="' + healthClass + ' cursor-pointer hover:bg-blue-50/40 dark:hover:bg-blue-900/10 transition-colors focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary">' +
                '<td class="px-6 py-4 text-sm font-medium text-foreground cm-mono">' + safeCN + '</td>' +
                '<td class="px-6 py-4 text-sm text-muted hidden md:table-cell">' + safeEmail + '</td>' +
                '<td class="px-6 py-4 text-sm hidden lg:table-cell"><span class="px-2 py-1 bg-info-surface text-info-strong rounded text-xs font-medium">' + safeUsage + '</span></td>' +
                '<td class="px-6 py-4 text-sm text-muted hidden lg:table-cell">' + createdDate.toLocaleDateString() + '</td>' +
                '<td class="px-6 py-4 text-sm ' + (isExpiringSoon ? 'text-danger-fg font-semibold' : 'text-muted') + '">' + expiresDate.toLocaleDateString() + '</td>' +
                '<td class="px-6 py-4 text-sm">' +
                    (cert.revoked
                        ? '<span class="px-2 py-1 bg-danger-surface text-danger-strong rounded text-xs font-medium">Revoked</span>'
                        : '<span class="px-2 py-1 bg-success-surface text-success-strong rounded text-xs font-medium">Active</span>') +
                '</td>' +
                '<td class="px-6 py-4 text-sm text-right">' +
                    '<div class="flex items-center justify-end gap-1">' +
                        '<button type="button" data-cc-action="details" data-id="' + safeId + '" class="p-1.5 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded hover:bg-hover" title="Details"><i class="fas fa-eye"></i></button>' +
                        (!cert.revoked ? '<button type="button" data-cc-action="revoke" data-id="' + safeId + '" class="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded hover:bg-hover" title="Revoke"><i class="fas fa-ban"></i></button>' : '') +
                        '<button type="button" data-cc-action="renew" data-id="' + safeId + '" class="p-1.5 text-gray-400 hover:text-green-600 dark:hover:text-green-400 rounded hover:bg-hover" title="Renew"><i class="fas fa-sync"></i></button>' +
                    '</div>' +
                '</td>' +
            '</tr>';
        }).join('');

        tbody.querySelectorAll('button[data-cc-action]').forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();  // don't also trigger the row-open handler
                var id = btn.dataset.id;
                switch (btn.dataset.ccAction) {
                    case 'details': ccShowCertDetails(id); break;
                    case 'revoke': ccRevokeCert(id); break;
                    case 'renew': ccRenewCert(id); break;
                }
            });
        });

        tbody.querySelectorAll('tr[data-cc-id]').forEach(function(tr) {
            tr.addEventListener('click', function() { ccShowCertDetails(tr.dataset.ccId); });
            tr.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); ccShowCertDetails(tr.dataset.ccId); }
            });
        });
    }

    // Sort state + comparator for the client-cert table (mirrors the server
    // table). Dates sort chronologically; status sorts Active-before-Revoked;
    // everything else is a case-insensitive string compare.
    var ccSort = { field: 'expires_at', dir: 'asc' };

    function ccApplySort(list) {
        var f = ccSort.field, dir = ccSort.dir === 'asc' ? 1 : -1;
        return list.slice().sort(function(a, b) {
            if (f === 'created_at' || f === 'expires_at') {
                return dir * ((new Date(a[f]).getTime() || 0) - (new Date(b[f]).getTime() || 0));
            }
            if (f === 'status') {
                return dir * ((a.revoked ? 1 : 0) - (b.revoked ? 1 : 0));
            }
            var av = (a[f] || '').toString().toLowerCase();
            var bv = (b[f] || '').toString().toLowerCase();
            return dir * av.localeCompare(bv);
        });
    }

    window.ccSortCertificates = function(field) {
        if (ccSort.field === field) {
            ccSort.dir = ccSort.dir === 'asc' ? 'desc' : 'asc';
        } else {
            ccSort.field = field; ccSort.dir = 'asc';
        }
        document.querySelectorAll('[id^="cc-sort-icon-"]').forEach(function(i) { i.className = 'fas fa-sort ml-1 text-gray-400'; });
        document.querySelectorAll('[id^="cc-sort-th-"]').forEach(function(th) { th.setAttribute('aria-sort', 'none'); });
        var ic = document.getElementById('cc-sort-icon-' + field);
        if (ic) ic.className = 'fas fa-sort-' + (ccSort.dir === 'asc' ? 'up' : 'down') + ' ml-1 text-primary';
        var th = document.getElementById('cc-sort-th-' + field);
        if (th) th.setAttribute('aria-sort', ccSort.dir === 'asc' ? 'ascending' : 'descending');
        ccRenderCertificates();
    };

    function ccSwitchTab(tab) {
        var singleForm = document.getElementById('createClientCertForm');
        var batchForm = document.getElementById('batchForm');
        var singleBtn = document.getElementById('singleTabBtn');
        var batchBtn = document.getElementById('batchTabBtn');
        if (!singleForm || !batchForm) return;

        var singleActive = tab === 'single';
        if (singleActive) {
            singleForm.classList.remove('hidden');
            batchForm.classList.add('hidden');
            singleBtn.classList.add('border-primary', 'text-primary');
            singleBtn.classList.remove('border-transparent', 'text-gray-600', 'dark:text-gray-300');
            batchBtn.classList.remove('border-primary', 'text-primary');
            batchBtn.classList.add('border-transparent', 'text-gray-600', 'dark:text-gray-300');
        } else {
            singleForm.classList.add('hidden');
            batchForm.classList.remove('hidden');
            batchBtn.classList.add('border-primary', 'text-primary');
            batchBtn.classList.remove('border-transparent', 'text-gray-600', 'dark:text-gray-300');
            singleBtn.classList.remove('border-primary', 'text-primary');
            singleBtn.classList.add('border-transparent', 'text-gray-600', 'dark:text-gray-300');
        }
        // Keep ARIA state and the roving tabindex in sync with the visual state.
        singleBtn.setAttribute('aria-selected', singleActive ? 'true' : 'false');
        batchBtn.setAttribute('aria-selected', singleActive ? 'false' : 'true');
        singleBtn.setAttribute('tabindex', singleActive ? '0' : '-1');
        batchBtn.setAttribute('tabindex', singleActive ? '-1' : '0');
    }

    // WAI-ARIA tabs keyboard nav for the single/bulk client-cert tabs.
    function ccTabKeydown(event) {
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight' &&
            event.key !== 'Home' && event.key !== 'End') return;
        event.preventDefault();
        // Two tabs: Left/Home -> single, Right/End -> batch.
        var goSingle = (event.key === 'ArrowLeft' || event.key === 'Home');
        ccSwitchTab(goSingle ? 'single' : 'batch');
        var target = document.getElementById(goSingle ? 'singleTabBtn' : 'batchTabBtn');
        if (target) target.focus();
    }

    function ccHandleCreateCert(e) {
        e.preventDefault();
        var data = {
            common_name: document.getElementById('commonName').value,
            email: document.getElementById('email').value,
            organization: document.getElementById('organization').value,
            cert_usage: document.getElementById('certUsage').value,
            days_valid: parseInt(document.getElementById('daysValid').value),
            generate_key: document.getElementById('generateKey').checked,
            notes: document.getElementById('notes').value
        };

        fetch('/api/client-certs/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(function(response) {
            if (response.ok) {
                CertMate.toast('Client certificate created!', 'success');
                document.getElementById('createClientCertForm').reset();
                ccLoadCertificates();
                ccLoadStatistics();
            } else {
                CertMate.toast('Error creating certificate', 'error');
            }
        }).catch(function() {
            CertMate.toast('Error creating certificate', 'error');
        });
    }

    function ccHandleBatchSubmit() {
        if (!window.csvData || !window.csvData.rows || window.csvData.rows.length === 0) {
            CertMate.toast('No CSV data to upload', 'warning');
            return;
        }
        var btn = document.getElementById('submitBatchBtn');
        if (btn) btn.disabled = true;

        fetch('/api/client-certs/batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                headers: window.csvData.headers,
                rows: window.csvData.rows
            })
        }).then(function(response) {
            return response.json().then(function(body) {
                return { ok: response.ok, body: body };
            });
        }).then(function(res) {
            if (res.ok) {
                var b = res.body || {};
                var msg = (b.successful || 0) + '/' + (b.total || 0) + ' certificates created';
                if (b.failed) msg += ' (' + b.failed + ' failed)';
                CertMate.toast(msg, b.failed ? 'warning' : 'success');
                document.getElementById('csvPreview').classList.add('hidden');
                document.getElementById('submitBatchBtn').classList.add('hidden');
                document.getElementById('csvFile').value = '';
                window.csvData = null;
                ccLoadCertificates();
                ccLoadStatistics();
            } else {
                var err = (res.body && (res.body.message || res.body.error)) || 'Batch upload failed';
                CertMate.toast(err, 'error');
            }
        }).catch(function() {
            CertMate.toast('Batch upload failed', 'error');
        }).finally(function() {
            if (btn) btn.disabled = false;
        });
    }

    function ccHandleCSVFile(file) {
        if (file.size > 5 * 1024 * 1024) {
            CertMate.toast('CSV file too large (max 5 MB)', 'warning');
            return;
        }
        var reader = new FileReader();
        reader.onload = function(e) {
            var rows = e.target.result.split('\n').map(function(l) { return l.split(',').map(function(c) { return c.trim(); }); });
            var headers = rows[0];
            var dataRows = rows.slice(1).filter(function(r) { return r[0]; });

            document.getElementById('headerRow').innerHTML = headers.map(function(h) { return '<th class="px-3 py-2 text-left">' + escapeHtml(h) + '</th>'; }).join('');
            document.getElementById('previewBody').innerHTML = dataRows.map(function(row) {
                return '<tr class="border-t">' + row.map(function(c) { return '<td class="px-3 py-2 text-label">' + escapeHtml(c) + '</td>'; }).join('') + '</tr>';
            }).join('');
            document.getElementById('rowCount').textContent = dataRows.length;
            document.getElementById('csvPreview').classList.remove('hidden');
            document.getElementById('submitBatchBtn').classList.remove('hidden');
            document.getElementById('certCountText').textContent = ' ' + dataRows.length + ' Certificates';
            window.csvData = { headers: headers, rows: dataRows };
        };
        reader.readAsText(file);
    }

    // Status/usage filter chips — the clicked chip becomes aria-pressed; the
    // rest reset. ccCurrent{Status,Usage} are the source of truth read below.
    function ccSetStatusFilter(value) {
        ccCurrentStatus = value;
        document.querySelectorAll('[data-cc-status-chip]').forEach(function (chip) {
            chip.setAttribute('aria-pressed', chip.getAttribute('data-cc-status-chip') === value ? 'true' : 'false');
        });
        ccFilterCertificates();
    }
    function ccSetUsageFilter(value) {
        ccCurrentUsage = value;
        document.querySelectorAll('[data-cc-usage-chip]').forEach(function (chip) {
            chip.setAttribute('aria-pressed', chip.getAttribute('data-cc-usage-chip') === value ? 'true' : 'false');
        });
        ccFilterCertificates();
    }
    function ccRefresh() {
        ccLoadStatistics();
        ccLoadCertificates();
    }
    window.ccSetStatusFilter = ccSetStatusFilter;
    window.ccSetUsageFilter = ccSetUsageFilter;
    window.ccRefresh = ccRefresh;

    function ccFilterCertificates() {
        var usage = ccCurrentUsage;
        var status = ccCurrentStatus;

        // Re-fetch original data and filter (free-text CN/email search now lives
        // in the global ⌘K palette).
        fetch('/api/client-certs')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var all = data.certificates || [];
                certificatesData = all.filter(function(cert) {
                    var matchUsage = !usage || cert.cert_usage === usage;
                    var matchStatus = !status || (status === 'active' && !cert.revoked) || (status === 'revoked' && cert.revoked);
                    return matchUsage && matchStatus;
                });
                ccRenderCertificates();
            })
            .catch(function(e) { console.error('Error filtering client certificates:', e); });
    }

    function ccShowCertDetails(id) {
        var cert = certificatesData.find(function(c) { return c.identifier === id; });
        if (!cert) return;
        currentCertId = id;

        var expiresDate = new Date(cert.expires_at);
        var expired = expiresDate < new Date();
        var expiringSoon = !expired && (expiresDate - new Date() < 30 * 24 * 60 * 60 * 1000);
        var danger = cert.revoked || expired;
        var bannerBg = danger ? 'bg-danger-surface' : expiringSoon ? 'bg-warning-surface' : 'bg-success-surface';
        var bannerFg = danger ? 'text-danger-fg' : expiringSoon ? 'text-warning-fg' : 'text-success-fg';
        var bannerIcon = cert.revoked ? 'fa-ban' : expired ? 'fa-circle-xmark' : expiringSoon ? 'fa-triangle-exclamation' : 'fa-circle-check';
        var statusLabel = cert.revoked ? 'Revoked' : expired ? 'Expired' : expiringSoon ? 'Expiring soon' : 'Active';

        function row(label, val, mono) {
            if (val === undefined || val === null || val === '') return '';
            return '<div class="flex items-start justify-between gap-4 py-2.5">' +
                '<dt class="text-sm text-muted flex-shrink-0">' + label + '</dt>' +
                '<dd class="text-sm font-medium text-right text-foreground min-w-0 ' + (mono ? 'font-mono text-xs break-all' : 'break-words') + '">' + escapeHtml(String(val)) + '</dd></div>';
        }

        document.getElementById('modalContent').innerHTML =
            // Status banner — status + expiry date integrated (mirrors the server modal)
            '<div class="flex items-center gap-3 p-4 rounded-lg ' + bannerBg + ' mb-4">' +
                '<i class="fas ' + bannerIcon + ' text-2xl ' + bannerFg + ' flex-shrink-0"></i>' +
                '<div class="min-w-0">' +
                    '<div class="text-lg font-semibold ' + bannerFg + '">' + statusLabel + '</div>' +
                    '<div class="text-sm ' + bannerFg + ' opacity-80">' + (expired ? 'Expired ' : 'Expires ') + expiresDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + '</div>' +
                '</div>' +
            '</div>' +
            '<dl class="divide-y divide-border">' +
                row('Common Name', cert.common_name) +
                row('Email', cert.email || 'N/A') +
                row('Organization', cert.organization) +
                row('Usage', cert.cert_usage) +
                row('Serial', cert.serial_number, true) +
                row('Created', new Date(cert.created_at).toLocaleString()) +
                row('Identifier', cert.identifier, true) +
            '</dl>';

        var titleEl = document.getElementById('certModalTitle');
        if (titleEl) titleEl.textContent = cert.common_name || 'Certificate Details';
        document.getElementById('certModal').classList.remove('hidden');
        if (CertMate.lockScroll) CertMate.lockScroll();
    }

    // Global functions referenced by onclick in the partial HTML
    window.closeCertModal = function() {
        var modal = document.getElementById('certModal');
        if (modal.classList.contains('hidden')) return;  // already closed — don't double-unlock
        modal.classList.add('hidden');
        if (CertMate.unlockScroll) CertMate.unlockScroll();
    };
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && !document.getElementById('certModal').classList.contains('hidden')) {
            window.closeCertModal();
        }
    });

    window.downloadCertFile = function(type) {
        if (!currentCertId) return;
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(currentCertId)) return;
        if (['crt', 'key', 'csr'].indexOf(type) === -1) return;
        window.location.href = '/api/client-certs/' + encodeURIComponent(currentCertId) + '/download/' + encodeURIComponent(type);
    };

    function ccRevokeCert(id) {
        CertMate.confirm('Are you sure you want to revoke this certificate?', 'Revoke Certificate').then(function(confirmed) {
            if (!confirmed) return;
            fetch('/api/client-certs/' + id + '/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: 'User requested' })
            }).then(function(response) {
                if (response.ok) {
                    CertMate.toast('Certificate revoked', 'success');
                    ccLoadCertificates();
                    ccLoadStatistics();
                } else {
                    CertMate.toast('Error revoking certificate', 'error');
                }
            }).catch(function() {
                CertMate.toast('Error revoking certificate', 'error');
            });
        });
    }

    function ccRenewCert(id) {
        fetch('/api/client-certs/' + id + '/renew', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }).then(function(response) {
            if (response.ok) {
                CertMate.toast('Certificate renewed!', 'success');
                ccLoadCertificates();
                ccLoadStatistics();
            } else {
                CertMate.toast('Error renewing certificate', 'error');
            }
        }).catch(function() {
            CertMate.toast('Error renewing certificate', 'error');
        });
    }
})();
