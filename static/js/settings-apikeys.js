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
            newKey: { name: '', role: 'viewer', expires_at: '', allowed_domains: '', is_agent: false },

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
                // Mark this key as belonging to an AI/MCP agent so its actions
                // are attributed in the audit trail as actor.kind='agent'.
                if (self.newKey.is_agent) {
                    payload.is_agent = true;
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
                                self.newKey = { name: '', role: 'viewer', expires_at: '', allowed_domains: '', is_agent: false };
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
                if (!self.createdToken) return;
                // Shared helper with a non-secure-context fallback (#427).
                // navigator.clipboard is undefined over plain HTTP, which is
                // how CertMate is commonly run on a LAN: this used to do
                // nothing at all, silently, and the token is shown exactly
                // once — so it was gone for good.
                CertMate.copyText(self.createdToken).then(function (ok) {
                    if (ok) {
                        showMessage('Token copied to clipboard', 'success');
                    } else {
                        showMessage('Could not copy automatically — select the token above and copy it now, it is shown only once.', 'error');
                    }
                });
            }
        };
    }

    window.apiKeyManager = apiKeyManager;

    // Configurable API rate limits (#319). Self-contained: reads/writes the
    // dedicated /api/settings/rate-limits endpoint, independent of the main
    // settings form.
    function rateLimitManager() {
        return {
            enabled: true,
            limits: {},
            keys: [],
            loading: true,
            saving: false,
            load: function () {
                var self = this;
                fetch('/api/settings/rate-limits', { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (d) {
                        self.enabled = d.enabled !== false;
                        self.keys = Object.keys(d.defaults || {});
                        self.limits = Object.assign({}, d.defaults || {}, d.limits || {});
                        self.loading = false;
                    })
                    .catch(function () {
                        self.loading = false;
                        showMessage('Failed to load rate limits', 'error');
                    });
            },
            save: function () {
                var self = this;
                self.saving = true;
                var limits = {};
                self.keys.forEach(function (k) {
                    var v = parseInt(self.limits[k], 10);
                    if (!isNaN(v)) limits[k] = v;
                });
                fetch('/api/settings/rate-limits', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ enabled: self.enabled, limits: limits })
                })
                    .then(function (r) {
                        return r.json().then(function (b) { return { ok: r.ok, b: b }; });
                    })
                    .then(function (res) {
                        self.saving = false;
                        if (res.ok) showMessage('Rate limits saved', 'success');
                        else showMessage((res.b && res.b.error) || 'Failed to save rate limits', 'error');
                    })
                    .catch(function () {
                        self.saving = false;
                        showMessage('Failed to save rate limits', 'error');
                    });
            },
            label: function (k) {
                return k.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
            }
        };
    }

    window.rateLimitManager = rateLimitManager;
})();
