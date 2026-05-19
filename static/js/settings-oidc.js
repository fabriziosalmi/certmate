(function () {
    'use strict';

    function showMessage(message, type, options) {
        var ns = window.CmSettings;
        if (ns && typeof ns.showMessage === 'function') {
            ns.showMessage(message, type, options);
        }
    }

    function defaultCfg() {
        return {
            enabled: false,
            provider_name: 'SSO',
            issuer_url: '',
            client_id: '',
            client_secret: '',
            scopes: ['openid', 'email', 'profile', 'groups'],
            redirect_uri_override: '',
            username_claim: 'preferred_username',
            email_claim: 'email',
            role_claim: 'groups',
            role_mappings: [],
            default_role: 'viewer',
            auto_create_users: true,
            link_by_email: true,
            post_logout_redirect_uri: ''
        };
    }

    // Normalise the comma/space-separated scopes string into an array
    // matching the server-side schema.
    function parseScopes(s) {
        if (typeof s !== 'string') return [];
        return s
            .split(/[\s,]+/)
            .map(function (t) { return t.trim(); })
            .filter(function (t) { return t.length > 0; });
    }

    function oidcSettings() {
        return {
            loading: true,
            saving: false,
            cfg: defaultCfg(),
            scopesString: 'openid email profile groups',
            // Computed only for display; the actual redirect URI sent to
            // the IdP is built server-side from the request (so a user
            // behind a reverse proxy doesn't need to override it).
            get redirectUriHint() {
                try {
                    return window.location.origin + '/api/auth/oidc/callback';
                } catch (e) {
                    return '/api/auth/oidc/callback';
                }
            },

            load: function () {
                var self = this;
                self.loading = true;
                fetch('/api/auth/oidc/settings', { credentials: 'same-origin' })
                    .then(function (r) {
                        if (r.status === 403) {
                            throw new Error('Admin role required');
                        }
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(function (data) {
                        var merged = Object.assign(defaultCfg(), data || {});
                        // role_mappings may be missing in older configs;
                        // ensure each row has both fields so Alpine bindings
                        // don't break on undefined.
                        merged.role_mappings = (merged.role_mappings || []).map(function (m) {
                            return {
                                claim_value: (m && m.claim_value) || '',
                                role: (m && m.role) || 'viewer'
                            };
                        });
                        self.cfg = merged;
                        self.scopesString = (merged.scopes || []).join(' ');
                        self.loading = false;
                    })
                    .catch(function (err) {
                        self.loading = false;
                        showMessage('Failed to load SSO settings: ' + (err && err.message ? err.message : err), 'error');
                    });
            },

            addMapping: function () {
                if (!Array.isArray(this.cfg.role_mappings)) this.cfg.role_mappings = [];
                this.cfg.role_mappings.push({ claim_value: '', role: 'viewer' });
            },

            removeMapping: function (idx) {
                if (!Array.isArray(this.cfg.role_mappings)) return;
                this.cfg.role_mappings.splice(idx, 1);
            },

            save: function () {
                var self = this;
                if (self.saving) return;

                // Drop empty mapping rows — leaving them in fails server-side
                // validation (claim_value must be a non-empty string).
                var mappings = (self.cfg.role_mappings || []).filter(function (m) {
                    return m && typeof m.claim_value === 'string' && m.claim_value.trim().length > 0;
                });

                var payload = Object.assign({}, self.cfg, {
                    scopes: parseScopes(self.scopesString),
                    role_mappings: mappings
                });

                self.saving = true;
                fetch('/api/auth/oidc/settings', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                })
                    .then(function (r) {
                        return r.json().then(function (data) { return { ok: r.ok, data: data }; });
                    })
                    .then(function (res) {
                        self.saving = false;
                        if (!res.ok) {
                            showMessage('Save failed: ' + (res.data && res.data.error ? res.data.error : 'unknown'), 'error');
                            return;
                        }
                        showMessage('SSO settings saved', 'success');
                        // Re-fetch so masked client_secret comes back as the
                        // sentinel and any normalisation from the server is
                        // reflected in the UI.
                        self.load();
                    })
                    .catch(function (err) {
                        self.saving = false;
                        showMessage('Save failed: ' + (err && err.message ? err.message : err), 'error');
                    });
            }
        };
    }

    window.oidcSettings = oidcSettings;
})();
