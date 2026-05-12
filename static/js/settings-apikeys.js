(function () {
    'use strict';

    // Local proxy to core's showMessage (toast + debug log).
    function showMessage(message, type, options) {
        var ns = window.CmSettings;
        if (ns && typeof ns.showMessage === 'function') ns.showMessage(message, type, options);
    }

    // Parse the comma-separated allowed_domains input into:
    //   - undefined  → unrestricted (omit the field from the payload)
    //   - []         → locked-out key (empty list)
    //   - [d1, d2…]  → scoped list
    function parseAllowedDomains(raw) {
        if (typeof raw !== 'string') return undefined;
        var trimmed = raw.trim();
        if (trimmed === '') return undefined;
        return trimmed.split(',')
            .map(function (s) { return s.trim().toLowerCase(); })
            .filter(function (s) { return s.length > 0; });
    }

    // Alpine.js component: API key CRUD.
    function apiKeyManager() {
        return {
            keys: {},
            loading: true,
            createdToken: '',
            newKey: { name: '', role: 'viewer', expires_at: '', allowed_domains: '' },

            loadKeys: function () {
                var self = this;
                self.loading = true;
                fetch('/api/keys', { credentials: 'same-origin' })
                    .then(function (r) {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(function (data) {
                        self.keys = data.keys || {};
                        self.loading = false;
                    })
                    .catch(function () {
                        self.loading = false;
                    });
            },

            createKey: function () {
                var self = this;
                if (!self.newKey.name.trim()) {
                    showMessage('Key name is required', 'error');
                    return;
                }

                var domains = parseAllowedDomains(self.newKey.allowed_domains);

                // F-4 (2026-05-12 API auth audit follow-up): make the
                // "unrestricted scope" default explicit. An admin who
                // submits the form with the allowed_domains field empty
                // is creating a key with access to every certificate on
                // the install — surface that intent with a confirm
                // dialog so it doesn't happen by accident. When the
                // field has at least one pattern (even a wildcard like
                // *.example.com), the dialog is skipped.
                var proceed;
                if (domains === undefined) {
                    proceed = CertMate.confirm(
                        'This key will have no domain restrictions and will be ' +
                        'authorized to operate on every certificate on this CertMate ' +
                        'instance, scoped only by the role you selected. ' +
                        'To restrict the key to specific domains, cancel and fill in ' +
                        'the Allowed Domains field (comma-separated, supports wildcards ' +
                        'like *.example.com). Create this unrestricted key?',
                        'Create Unrestricted API Key'
                    );
                } else {
                    proceed = Promise.resolve(true);
                }

                proceed.then(function (ok) {
                    if (!ok) {
                        // Bring the user back to the input they likely
                        // intended to fill so the recovery is one click.
                        var field = document.querySelector(
                            "[x-data*='apiKeyManager'] input[x-model='newKey.allowed_domains']"
                        );
                        if (field) field.focus();
                        return;
                    }
                    self._postCreate(domains);
                });
            },

            _postCreate: function (domains) {
                var self = this;
                var payload = {
                    name: self.newKey.name.trim(),
                    role: self.newKey.role
                };
                if (self.newKey.expires_at) {
                    payload.expires_at = new Date(self.newKey.expires_at).toISOString();
                }
                if (domains !== undefined) {
                    payload.allowed_domains = domains;
                }
                fetch('/api/keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                })
                    .then(function (r) {
                        return r.json().then(function (data) {
                            if (r.ok) {
                                self.createdToken = data.token;
                                self.newKey = { name: '', role: 'viewer', expires_at: '', allowed_domains: '' };
                                self.loadKeys();
                                showMessage('API key "' + data.name + '" created', 'success');
                            } else {
                                showMessage(data.error || 'Failed to create API key', 'error', {
                                    errorContext: {
                                        endpoint: 'POST /api/keys',
                                        status: r.status,
                                        code: data.code,
                                        message: data.error,
                                        hint: data.hint
                                    }
                                });
                            }
                        });
                    })
                    .catch(function () {
                        showMessage('Failed to create API key', 'error', {
                            errorContext: {
                                endpoint: 'POST /api/keys',
                                status: 0,
                                code: 'NETWORK_ERROR',
                                message: 'network error or unparseable response'
                            }
                        });
                    });
            },

            revokeKey: function (keyId, keyName) {
                var self = this;
                CertMate.confirm(
                    'Are you sure you want to revoke API key "' + CertMate.escapeHtml(keyName) + '"? This cannot be undone.',
                    'Revoke API Key'
                ).then(function (confirmed) {
                    if (!confirmed) return;
                    fetch('/api/keys/' + keyId, {
                        method: 'DELETE',
                        credentials: 'same-origin'
                    })
                        .then(function (r) {
                            return r.json().then(function (data) {
                                if (r.ok) {
                                    showMessage('API key revoked', 'success');
                                    self.loadKeys();
                                } else {
                                    showMessage(data.error || 'Failed to revoke key', 'error');
                                }
                            });
                        })
                        .catch(function () { showMessage('Failed to revoke API key', 'error'); });
                });
            },

            copyToken: function () {
                var self = this;
                if (navigator.clipboard && self.createdToken) {
                    navigator.clipboard.writeText(self.createdToken).then(function () {
                        showMessage('Token copied to clipboard', 'success');
                    });
                }
            }
        };
    }

    window.apiKeyManager = apiKeyManager;
})();
