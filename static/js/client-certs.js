/**
 * Client Certificate Management — static/js/client-certs.js
 * Loaded on the unified certificates page (client tab).
 */
(function() {
    'use strict';

    var escapeHtml = CertMate.escapeHtml;
    var currentCertId = null;
    var certificatesData = [];
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

        var form = document.getElementById('createCertForm');
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

        var search = document.getElementById('searchInput');
        var fUsage = document.getElementById('filterUsage');
        var fStatus = document.getElementById('filterStatus');
        if (search) search.addEventListener('input', ccFilterCertificates);
        if (fUsage) fUsage.addEventListener('change', ccFilterCertificates);
        if (fStatus) fStatus.addEventListener('change', ccFilterCertificates);
    }

    function ccLoadStatistics() {
        fetch('/api/client-certs/stats')
            .then(function(r) { return r.json(); })
            .then(function(stats) {
                var el = function(id) { return document.getElementById(id); };
                if (el('totalCount')) el('totalCount').textContent = stats.total || 0;
                if (el('activeCount')) el('activeCount').textContent = stats.active || 0;
                if (el('revokedCount')) el('revokedCount').textContent = stats.revoked || 0;
                var byUsage = stats.by_usage || {};
                var usageText = Object.entries(byUsage).map(function(e) { return e[1] + ' ' + e[0]; }).join(', ') || 'No certs';
                if (el('usageBreakdown')) el('usageBreakdown').textContent = usageText;
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
            tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No client certificates found</td></tr>';
            return;
        }

        tbody.innerHTML = certificatesData.map(function(cert) {
            var expiresDate = new Date(cert.expires_at);
            var createdDate = new Date(cert.created_at);
            var isExpiringSoon = expiresDate - new Date() < 30 * 24 * 60 * 60 * 1000;
            var safeCN = escapeHtml(cert.common_name);
            var safeEmail = escapeHtml(cert.email || '-');
            var safeUsage = escapeHtml(cert.cert_usage);
            var safeId = escapeHtml(cert.identifier);

            return '<tr class="hover:bg-gray-50 dark:hover:bg-gray-700 transition">' +
                '<td class="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">' + safeCN + '</td>' +
                '<td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-300 hidden md:table-cell">' + safeEmail + '</td>' +
                '<td class="px-6 py-4 text-sm hidden lg:table-cell"><span class="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded text-xs font-medium">' + safeUsage + '</span></td>' +
                '<td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-300 hidden lg:table-cell">' + createdDate.toLocaleDateString() + '</td>' +
                '<td class="px-6 py-4 text-sm ' + (isExpiringSoon ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-gray-600 dark:text-gray-300') + '">' + expiresDate.toLocaleDateString() + '</td>' +
                '<td class="px-6 py-4 text-sm">' +
                    (cert.revoked
                        ? '<span class="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 rounded text-xs font-medium">Revoked</span>'
                        : '<span class="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 rounded text-xs font-medium">Active</span>') +
                '</td>' +
                '<td class="px-6 py-4 text-sm text-right">' +
                    '<div class="flex items-center justify-end gap-1">' +
                        '<button type="button" data-cc-action="details" data-id="' + safeId + '" class="p-1.5 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Details"><i class="fas fa-eye"></i></button>' +
                        (!cert.revoked ? '<button type="button" data-cc-action="revoke" data-id="' + safeId + '" class="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Revoke"><i class="fas fa-ban"></i></button>' : '') +
                        '<button type="button" data-cc-action="renew" data-id="' + safeId + '" class="p-1.5 text-gray-400 hover:text-green-600 dark:hover:text-green-400 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Renew"><i class="fas fa-sync"></i></button>' +
                    '</div>' +
                '</td>' +
            '</tr>';
        }).join('');

        tbody.querySelectorAll('button[data-cc-action]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = btn.dataset.id;
                switch (btn.dataset.ccAction) {
                    case 'details': ccShowCertDetails(id); break;
                    case 'revoke': ccRevokeCert(id); break;
                    case 'renew': ccRenewCert(id); break;
                }
            });
        });
    }

    function ccSwitchTab(tab) {
        var singleForm = document.getElementById('createCertForm');
        var batchForm = document.getElementById('batchForm');
        var singleBtn = document.getElementById('singleTabBtn');
        var batchBtn = document.getElementById('batchTabBtn');
        if (!singleForm || !batchForm) return;

        if (tab === 'single') {
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
    }

    async function ccHandleCreateCert(e) {
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

        try {
            var response = await fetch('/api/client-certs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                CertMate.toast('Client certificate created!', 'success');
                document.getElementById('createCertForm').reset();
                ccLoadCertificates();
                ccLoadStatistics();
            } else {
                CertMate.toast('Error creating certificate', 'error');
            }
        } catch (err) {
            console.error('Error:', err);
            CertMate.toast('Error creating certificate', 'error');
        }
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
                return '<tr class="border-t">' + row.map(function(c) { return '<td class="px-3 py-2 text-gray-700 dark:text-gray-300">' + escapeHtml(c) + '</td>'; }).join('') + '</tr>';
            }).join('');
            document.getElementById('rowCount').textContent = dataRows.length;
            document.getElementById('csvPreview').classList.remove('hidden');
            document.getElementById('submitBatchBtn').classList.remove('hidden');
            document.getElementById('certCountText').textContent = ' ' + dataRows.length + ' Certificates';
            window.csvData = { headers: headers, rows: dataRows };
        };
        reader.readAsText(file);
    }

    function ccFilterCertificates() {
        var search = (document.getElementById('searchInput').value || '').toLowerCase();
        var usage = document.getElementById('filterUsage').value;
        var status = document.getElementById('filterStatus').value;

        // Re-fetch original data and filter
        fetch('/api/client-certs')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var all = data.certificates || [];
                certificatesData = all.filter(function(cert) {
                    var matchSearch = !search || cert.common_name.toLowerCase().indexOf(search) !== -1 || (cert.email || '').toLowerCase().indexOf(search) !== -1;
                    var matchUsage = !usage || cert.cert_usage === usage;
                    var matchStatus = !status || (status === 'active' && !cert.revoked) || (status === 'revoked' && cert.revoked);
                    return matchSearch && matchUsage && matchStatus;
                });
                ccRenderCertificates();
            });
    }

    function ccShowCertDetails(id) {
        var cert = certificatesData.find(function(c) { return c.identifier === id; });
        if (!cert) return;
        currentCertId = id;
        var content = document.getElementById('modalContent');
        content.innerHTML =
            '<div><strong>Identifier:</strong> ' + escapeHtml(cert.identifier || '') + '</div>' +
            '<div><strong>Common Name:</strong> ' + escapeHtml(cert.common_name || '') + '</div>' +
            '<div><strong>Email:</strong> ' + escapeHtml(cert.email || 'N/A') + '</div>' +
            '<div><strong>Organization:</strong> ' + escapeHtml(cert.organization || '') + '</div>' +
            '<div><strong>Usage:</strong> ' + escapeHtml(cert.cert_usage || '') + '</div>' +
            '<div><strong>Serial:</strong> ' + escapeHtml(String(cert.serial_number || '')) + '</div>' +
            '<div><strong>Created:</strong> ' + escapeHtml(new Date(cert.created_at).toLocaleString()) + '</div>' +
            '<div><strong>Expires:</strong> ' + escapeHtml(new Date(cert.expires_at).toLocaleString()) + '</div>' +
            '<div><strong>Status:</strong> ' + (cert.revoked ? 'Revoked' : 'Active') + '</div>';
        document.getElementById('certModal').classList.remove('hidden');
    }

    // Global functions referenced by onclick in the partial HTML
    window.closeCertModal = function() {
        document.getElementById('certModal').classList.add('hidden');
    };

    window.downloadCertFile = function(type) {
        if (!currentCertId) return;
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(currentCertId)) return;
        if (['crt', 'key', 'csr'].indexOf(type) === -1) return;
        window.location.href = '/api/client-certs/' + encodeURIComponent(currentCertId) + '/download/' + encodeURIComponent(type);
    };

    async function ccRevokeCert(id) {
        if (!await CertMate.confirm('Are you sure you want to revoke this certificate?', 'Revoke Certificate')) return;
        try {
            var response = await fetch('/api/client-certs/' + id + '/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: 'User requested' })
            });
            if (response.ok) {
                CertMate.toast('Certificate revoked', 'success');
                ccLoadCertificates();
                ccLoadStatistics();
            } else {
                CertMate.toast('Error revoking certificate', 'error');
            }
        } catch (err) { console.error('Error:', err); }
    }

    async function ccRenewCert(id) {
        try {
            var response = await fetch('/api/client-certs/' + id + '/renew', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            if (response.ok) {
                CertMate.toast('Certificate renewed!', 'success');
                ccLoadCertificates();
                ccLoadStatistics();
            } else {
                CertMate.toast('Error renewing certificate', 'error');
            }
        } catch (err) { console.error('Error:', err); }
    }
})();
