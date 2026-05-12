(function () {
    'use strict';

    // Local proxy to core's addDebugLog. Resolves at call time so script load
    // order between core (settings.js) and this module doesn't matter — by
    // the time Alpine evaluates x-data, both IIFEs have executed.
    function addDebugLog(message, type) {
        var ns = window.CmSettings;
        if (ns && typeof ns.addDebugLog === 'function') ns.addDebugLog(message, type);
    }

    // Alpine.js component: deploy hooks (global + per-domain) and history.
    function deployManager() {
        return {
            config: {
                enabled: false,
                global_hooks: [],
                domain_hooks: {}
            },
            showGlobal: false,
            showDomain: false,
            showHistory: false,
            history: [],
            newDomain: '',

            loadConfig: function () {
                var self = this;
                fetch('/api/deploy/config', { credentials: 'same-origin' })
                    .then(function (r) {
                        return r.json().then(function (data) {
                            return { ok: r.ok, body: data };
                        });
                    })
                    .then(function (res) {
                        if (res.ok && res.body && !res.body.error) {
                            self.config.enabled = res.body.enabled || false;
                            self.config.global_hooks = res.body.global_hooks || [];
                            self.config.domain_hooks = res.body.domain_hooks || {};
                            addDebugLog('Loaded deploy config: '
                                + (self.config.global_hooks.length) + ' global hooks, '
                                + Object.keys(self.config.domain_hooks).length + ' domain section(s)',
                                'info');
                        } else {
                            addDebugLog('Failed to load deploy config: '
                                + ((res.body && res.body.error) || 'HTTP ' + (res.ok ? 'OK' : 'error')),
                                'error');
                        }
                    })
                    .catch(function (err) {
                        addDebugLog('Deploy config request failed: ' + (err && err.message || err), 'error');
                    });
            },

            saveConfig: function () {
                var self = this;
                addDebugLog('Saving deploy config…', 'info');
                fetch('/api/deploy/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(self.config)
                })
                    // Use HTTP status as source of truth — the previous code
                    // checked d.status === 'saved' but the server returns
                    // {message: ...} on success, so the success branch never
                    // ran and users always saw a "Save failed: unknown"
                    // toast even when the save actually worked (issue #110).
                    .then(function (r) {
                        return r.json().then(function (body) {
                            return { ok: r.ok, body: body };
                        });
                    })
                    .then(function (res) {
                        if (res.ok) {
                            addDebugLog('Deploy settings saved', 'info');
                            CertMate.toast('Deploy settings saved', 'success');
                        } else {
                            var msg = (res.body && res.body.error) || 'unknown error';
                            addDebugLog('Deploy settings save failed: ' + msg, 'error');
                            CertMate.toast('Save failed: ' + msg, 'error');
                        }
                    })
                    .catch(function (err) {
                        addDebugLog('Deploy settings save request failed: ' + (err && err.message || err), 'error');
                        CertMate.toast('Failed to save', 'error');
                    });
            },

            _generateId: function () {
                if (typeof crypto !== 'undefined' && crypto.randomUUID) {
                    return crypto.randomUUID();
                }
                return Date.now().toString(36) + Math.random().toString(36).substr(2);
            },

            addGlobalHook: function () {
                this.config.global_hooks.push({
                    id: this._generateId(),
                    name: '',
                    command: '',
                    enabled: true,
                    timeout: 30,
                    on_events: ['created', 'renewed']
                });
                this.showGlobal = true;
            },

            addDomainSection: function () {
                var d = this.newDomain.trim().toLowerCase();
                if (!d) return;
                if (!this.config.domain_hooks[d]) {
                    this.config.domain_hooks[d] = [];
                    // Force Alpine reactivity
                    this.config.domain_hooks = Object.assign({}, this.config.domain_hooks);
                }
                this.newDomain = '';
            },

            addDomainHook: function (domain) {
                if (!this.config.domain_hooks[domain]) {
                    this.config.domain_hooks[domain] = [];
                }
                this.config.domain_hooks[domain].push({
                    id: this._generateId(),
                    name: '',
                    command: '',
                    enabled: true,
                    timeout: 30,
                    on_events: ['created', 'renewed']
                });
            },

            removeDomain: function (domain) {
                var self = this;
                CertMate.confirm('Remove all hooks for ' + domain + '?', 'Remove Domain').then(function (confirmed) {
                    if (!confirmed) return;
                    delete self.config.domain_hooks[domain];
                    self.config.domain_hooks = Object.assign({}, self.config.domain_hooks);
                });
            },

            toggleEvent: function (hook, evt) {
                if (!hook.on_events) hook.on_events = [];
                var idx = hook.on_events.indexOf(evt);
                if (idx === -1) hook.on_events.push(evt);
                else hook.on_events.splice(idx, 1);
            },

            testHook: function (hook) {
                var hookLabel = hook.name || hook.id || 'unnamed';
                addDebugLog('Testing hook: ' + hookLabel, 'info');
                CertMate.toast('Testing hook: ' + hookLabel + '...', 'info');
                fetch('/api/deploy/test/' + hook.id, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ domain: 'test.example.com' })
                })
                    .then(function (r) { return r.json(); })
                    .then(function (d) {
                        if (d.success) {
                            addDebugLog('Hook "' + hookLabel + '" test passed (exit ' + d.exit_code + ')', 'info');
                            CertMate.toast('Hook test passed (exit ' + d.exit_code + ')', 'success');
                        } else {
                            var detail = d.error || 'exit ' + d.exit_code;
                            addDebugLog('Hook "' + hookLabel + '" test failed: ' + detail, 'error');
                            CertMate.toast('Hook test failed: ' + detail, 'error');
                        }
                    })
                    .catch(function (err) {
                        addDebugLog('Test request failed for hook "' + hookLabel + '": ' + (err && err.message || err), 'error');
                        CertMate.toast('Test request failed', 'error');
                    });
            },

            loadHistory: function () {
                var self = this;
                fetch('/api/deploy/history?limit=50', { credentials: 'same-origin' })
                    .then(function (r) {
                        return r.json().then(function (data) {
                            return { ok: r.ok, body: data };
                        });
                    })
                    .then(function (res) {
                        // Backend returns {history: [...]} — keep accepting a
                        // raw array too for forward/backward compatibility.
                        var entries = null;
                        if (res.ok && res.body) {
                            if (Array.isArray(res.body)) {
                                entries = res.body;
                            } else if (Array.isArray(res.body.history)) {
                                entries = res.body.history;
                            }
                        }
                        if (entries) {
                            self.history = entries;
                            addDebugLog('Loaded deploy history: ' + entries.length + ' entries', 'info');
                        } else {
                            addDebugLog('Failed to load deploy history: '
                                + ((res.body && res.body.error) || 'unexpected response'),
                                'error');
                        }
                    })
                    .catch(function (err) {
                        addDebugLog('Deploy history request failed: ' + (err && err.message || err), 'error');
                    });
            }
        };
    }

    window.deployManager = deployManager;
})();
