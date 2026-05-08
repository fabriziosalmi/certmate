(function () {
    'use strict';

    // Local proxy to core's showMessage (toast + debug log).
    function showMessage(message, type) {
        var ns = window.CmSettings;
        if (ns && typeof ns.showMessage === 'function') ns.showMessage(message, type);
    }

    // Alpine.js component: API key CRUD.
    function apiKeyManager() {
        return {
            keys: {},
            loading: true,
            createdToken: '',
            newKey: { name: '', role: 'viewer', expires_at: '' },

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
                var payload = {
                    name: self.newKey.name.trim(),
                    role: self.newKey.role
                };
                if (self.newKey.expires_at) {
                    payload.expires_at = new Date(self.newKey.expires_at).toISOString();
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
                                self.newKey = { name: '', role: 'viewer', expires_at: '' };
                                self.loadKeys();
                                showMessage('API key "' + data.name + '" created', 'success');
                            } else {
                                showMessage(data.error || 'Failed to create API key', 'error');
                            }
                        });
                    })
                    .catch(function () { showMessage('Failed to create API key', 'error'); });
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
