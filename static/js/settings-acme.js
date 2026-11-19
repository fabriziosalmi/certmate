(function () {
    'use strict';

    // Settings > ACME (#476): the server's options, its EAB keys and the
    // accounts they enrolled. Everything here goes through /api/acme, admin
    // only; the HMAC key of a new EAB key is held in this component until the
    // page is left, and never fetched again, because the server never sends it
    // again.

    function splitNames(text) {
        return (text || '').split(/[\s,]+/).map(function (s) { return s.trim(); })
            .filter(function (s) { return s.length > 0; });
    }

    // The fields a refusal can be about, by the `field` the server names
    // (API contract 2.72): the toast leads with its label and the field is marked.
    var KEY_FIELDS = {
        allowed_identifiers: { label: 'Names and addresses it may order', id: 'acmeKeyNames' },
        kid: { label: 'Key identifier', id: 'acmeKeyKid' },
        note: { label: 'Note', id: 'acmeKeyNote' }
    };
    var OPTION_FIELDS = {
        validity_days: { label: 'Certificate validity', id: 'acmeValidity' },
        allowed_identifiers: { label: 'Names and addresses an account without an EAB key may order', id: 'acmeOpenNames' }
    };

    function acmeManager() {
        return {
            loading: true,
            saving: false,
            server: { enabled: false, allow_http: false, eab_required: true, validity_days: 45,
                      allowed_identifiers: [], directory_url: '', eab_keys: [] },
            // What the server has, as the last read or save left it: the badge
            // and the directory URL follow it, not the ticked box, because
            // nothing is served until Save (UX audit P27).
            savedEnabled: false,
            openNames: '',
            accounts: [],
            newKey: { kid: '', names: '', note: '' },
            created: null,
            client: 'certbot',
            clients: [
                { id: 'certbot', label: 'certbot' },
                { id: 'lego', label: 'lego' },
                { id: 'acmesh', label: 'acme.sh' },
                { id: 'certmanager', label: 'cert-manager' }
            ],

            get rootUrl() { return this.server.directory_url.replace(/directory$/, 'root'); },
            get snippet() {
                if (!this.created) return '';
                return CertMateAcme.snippets({
                    directory: this.server.directory_url, kid: this.created.kid, hmac: this.created.hmac_key,
                    patterns: this.created.allowed_identifiers
                })[this.client];
            },
            formatDate: function (value) { return CertMate.formatDate(value); },
            shortId: function (value) { return (value || '').slice(0, 8); },
            joined: function (list) { return (list || []).join(', '); },
            isClient: function (id) { return this.client === id; },
            pickClient: function (id) { this.client = id; },

            // keepOptions: a refresh after a key or an account changed keeps
            // the options as edited; only the first read fills them in.
            load: function (keepOptions) {
                var self = this;
                if (!keepOptions) self.loading = true;
                Promise.all([CertMate.api('GET', '/api/acme/server'), CertMate.api('GET', '/api/acme/accounts')])
                    .then(function (answers) {
                        self.savedEnabled = answers[0].enabled === true;
                        if (keepOptions) {
                            self.server.eab_keys = answers[0].eab_keys;
                            self.server.directory_url = answers[0].directory_url;
                        } else {
                            self.server = answers[0];
                            self.openNames = self.joined(answers[0].allowed_identifiers);
                        }
                        self.accounts = answers[1].accounts;
                    })
                    .catch(function (error) { CertMate.toast(error.message || 'Could not load the ACME server', 'error'); })
                    .then(function () { self.loading = false; });
            },

            save: function () {
                var self = this;
                self.saving = true;
                CertMate.api('PATCH', '/api/acme/server', {
                    enabled: self.server.enabled,
                    allow_http: self.server.allow_http,
                    eab_required: self.server.eab_required,
                    validity_days: parseInt(self.server.validity_days, 10),
                    allowed_identifiers: splitNames(self.openNames)
                })
                    .then(function (view) {
                        self.server = view;
                        self.savedEnabled = view.enabled === true;
                        self.openNames = self.joined(view.allowed_identifiers);
                        CertMate.toast('ACME server saved', 'success');
                    })
                    .catch(function (error) {
                        CertMate.toast(CertMate.markFieldError(error.message || 'Could not save',
                            error.body && error.body.field, OPTION_FIELDS), 'error');
                    })
                    .then(function () { self.saving = false; });
            },

            createKey: function () {
                var self = this;
                var body = { allowed_identifiers: splitNames(self.newKey.names), note: self.newKey.note };
                if (self.newKey.kid.trim()) body.kid = self.newKey.kid.trim();
                CertMate.api('POST', '/api/acme/eab-keys', body)
                    .then(function (created) {
                        self.created = created;
                        self.client = 'certbot';
                        self.newKey = { kid: '', names: '', note: '' };
                        self.load(true);
                    })
                    .catch(function (error) {
                        // The toast leads with the label of the field the
                        // server names, which is marked and focused (UX audit P61).
                        CertMate.toast(CertMate.markFieldError(error.message || 'Could not create the key',
                            error.body && error.body.field, KEY_FIELDS), 'error');
                    });
            },

            copy: function (text) {
                CertMate.copyText(text).then(function (ok) {
                    CertMate.toast(ok ? 'Copied' : 'Copy failed', ok ? 'success' : 'error');
                });
            },
            copyHmac: function () { this.copy(this.created.hmac_key); },
            copySnippet: function () { this.copy(this.snippet); },
            copyDirectory: function () { this.copy(this.server.directory_url); },
            forget: function () { this.created = null; },

            disableKey: function (kid) {
                var self = this;
                CertMate.confirm('Disable EAB key "' + kid + '"? It enrols no one again. The accounts it '
                    + 'enrolled keep working; deactivate them below to stop them.', 'Disable EAB key')
                    .then(function (yes) {
                        if (!yes) return;
                        CertMate.api('DELETE', '/api/acme/eab-keys/' + encodeURIComponent(kid))
                            .then(function () { CertMate.toast('EAB key disabled', 'success'); self.load(true); })
                            .catch(function (error) { CertMate.toast(error.message || 'Could not disable', 'error'); });
                    });
            },

            deactivateAccount: function (account) {
                var self = this;
                CertMate.confirm('Deactivate this ACME account for good? It orders nothing again. '
                    + 'Its certificates stay valid until they expire or you revoke them.', 'Deactivate account')
                    .then(function (yes) {
                        if (!yes) return;
                        CertMate.api('POST', '/api/acme/accounts/' + encodeURIComponent(account.id) + '/deactivate')
                            .then(function () { CertMate.toast('Account deactivated', 'success'); self.load(true); })
                            .catch(function (error) { CertMate.toast(error.message || 'Could not deactivate', 'error'); });
                    });
            }
        };
    }

    window.acmeManager = acmeManager;
    document.addEventListener('alpine:init', function () {
        Alpine.data('acmeManager', acmeManager);
    });
})();
