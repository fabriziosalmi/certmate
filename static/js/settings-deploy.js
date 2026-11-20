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

            // What the template needs and an expression may not reach or say:
            // there is no `Object` inside one, and it is one statement.
            get domainNames() { return Object.keys(this.config.domain_hooks).sort(); },
            toggleHistory: function () {
                this.showHistory = !this.showHistory;
                if (this.showHistory) this.loadHistory();
            },
            newDomain: '',
            // Drives the execution-detail modal in settings_deploy.html.
            // null = nothing selected; the modal is gated on this via x-if so
            // the bindings are skipped entirely until showExecutionDetail()
            // sets it from a row click.
            selectedExecution: null,
            // What the server runs and records of each hook, by id: its name
            // (in the run record and the audit entry), command and timeout.
            // Test runs the hook the server has: on a hook it does not have it
            // answered a 404 that blamed sync or the safety check (#1511, P40),
            // and on an edited one it would run the saved fields, not the ones
            // on screen. So Test waits for the save.
            savedHooks: {},
            // The hook and field the last refused save named, so the field is
            // marked (aria-invalid) instead of left for the operator to find.
            refused: null,

            _rememberSaved: function (config) {
                var saved = {};
                var hooks = (config.global_hooks || []).slice();
                Object.keys(config.domain_hooks || {}).forEach(function (domain) {
                    hooks = hooks.concat(config.domain_hooks[domain] || []);
                });
                var self = this;
                hooks.forEach(function (hook) { saved[hook.id] = self._runsAs(hook); });
                this.savedHooks = saved;
            },

            _runsAs: function (hook) {
                return JSON.stringify([hook.name, hook.command, hook.timeout]);
            },

            isSaved: function (hook) {
                return Object.prototype.hasOwnProperty.call(this.savedHooks, hook.id)
                    && this.savedHooks[hook.id] === this._runsAs(hook);
            },

            refusedField: function (hook, field) {
                return !!this.refused && this.refused.hook_id === hook.id && this.refused.field === field;
            },

            // Resolves true when the configuration was read and is on screen.
            loadConfig: function () {
                var self = this;
                return fetch('/api/deploy/config', { credentials: 'same-origin' })
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
                            self._rememberSaved(self.config);
                            addDebugLog('Loaded deploy config: '
                                + (self.config.global_hooks.length) + ' global hooks, '
                                + Object.keys(self.config.domain_hooks).length + ' domain section(s)',
                                'info');
                            return true;
                        }
                        addDebugLog('Failed to load deploy config: '
                            + ((res.body && res.body.error) || 'HTTP ' + (res.ok ? 'OK' : 'error')),
                            'error');
                        return false;
                    })
                    .catch(function (err) {
                        addDebugLog('Deploy config request failed: ' + (err && err.message || err), 'error');
                        return false;
                    });
            },

            // True while a save is on its way: the hook fields are read-only
            // and clicks on the hook editor are held (held() below), because
            // the save reads the configuration back into the fields and an
            // edit made meanwhile would be overwritten (#1511 review).
            saving: false,

            held: function (event) {
                if (!this.saving) return;
                event.preventDefault();
                event.stopImmediatePropagation();
            },

            saveConfig: function () {
                var self = this;
                if (self.saving) return;
                self.saving = true;
                // Kept for when the read-back fails: then the page compares
                // with what it sent, and says it could not read the result.
                var sent = JSON.parse(JSON.stringify(self.config));
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
                            // Read back what the server kept, into the fields
                            // and the snapshot Test compares with: it is not
                            // always what was sent (a timeout is held to
                            // 1..300 s, an empty one becomes 30), and the run
                            // uses the saved value.
                            self.refused = null;
                            addDebugLog('Deploy settings saved', 'info');
                            CertMate.toast('Deploy settings saved', 'success');
                            return self.loadConfig().then(function (read) {
                                if (read) return;
                                self._rememberSaved(sent);
                                CertMate.toast('Deploy settings saved, but the page could not read them back: '
                                    + 'if the server adjusted a value (a timeout is held to 1-300 s), the page '
                                    + 'does not show it. Reload the page to see what was saved.', 'warning');
                            });
                        }
                        var msg = (res.body && res.body.error) || 'unknown error';
                        self.refused = (res.body && res.body.hook_id)
                            ? { hook_id: res.body.hook_id, field: res.body.field } : null;
                        addDebugLog('Deploy settings save failed: ' + msg, 'error');
                        CertMate.toast('Save failed: ' + msg, 'error');
                    })
                    .catch(function (err) {
                        addDebugLog('Deploy settings save request failed: ' + (err && err.message || err), 'error');
                        CertMate.toast('Failed to save', 'error');
                    })
                    .then(function () { self.saving = false; });
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

            // --- Maintenance windows (#632) ---------------------------------
            // Absent means "deploy immediately", which is what every existing
            // hook does. The toggle adds and removes the whole object rather
            // than leaving an empty one behind: the server treats any window
            // object as a reason to defer, so a leftover {} would hold every
            // deploy for a window with no hours in it.

            windowDays: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'],

            toggleWindow: function (hook) {
                if (hook.window) {
                    delete hook.window;
                } else {
                    // Defaults to the small hours, every day, in the browser's
                    // own zone — the answer an operator opening this almost
                    // always wants, and the zone they are thinking in.
                    var zone = 'UTC';
                    try {
                        zone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
                    } catch (e) {
                        zone = 'UTC';
                    }
                    hook.window = {
                        start: '02:00', end: '04:00', days: [], timezone: zone
                    };
                }
            },

            toggleWindowDay: function (hook, day) {
                if (!hook.window) return;
                if (!hook.window.days) hook.window.days = [];
                var idx = hook.window.days.indexOf(day);
                if (idx === -1) hook.window.days.push(day);
                else hook.window.days.splice(idx, 1);
            },

            describeWindow: function (hook) {
                if (!hook.window) return 'Runs as soon as the certificate is issued or renewed.';
                var w = hook.window;
                var days = (w.days && w.days.length) ? w.days.join(', ') : 'every day';
                var wraps = w.start > w.end
                    ? ' (crosses midnight into the next morning)' : '';
                return 'Held until ' + w.start + '-' + w.end + ' ' +
                    (w.timezone || 'UTC') + ', ' + days + wraps + '.';
            },

            testHook: function (hook) {
                var hookLabel = hook.name || hook.id || 'unnamed';
                var btn = event && event.target ? event.target.closest('button') : null;
                var originalHTML;
                if (btn) {
                    originalHTML = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i aria-hidden="true" class="fas fa-spinner fa-spin mr-1"></i> Testing...';
                }
                addDebugLog('Testing hook: ' + hookLabel, 'info');
                // The result takes the place of this toast (P34).
                var toastKey = 'hook-test:' + hook.id;
                CertMate.toast('Testing hook: ' + hookLabel + '...', 'info', undefined, { key: toastKey });
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
                            CertMate.toast('Hook test passed (exit ' + d.exit_code + ')', 'success', undefined, { key: toastKey });
                        } else {
                            var detail = d.error || 'exit ' + d.exit_code;
                            addDebugLog('Hook "' + hookLabel + '" test failed: ' + detail, 'error');
                            CertMate.toast('Hook test failed: ' + detail, 'error', undefined, { key: toastKey });
                        }
                    })
                    .catch(function (err) {
                        addDebugLog('Test request failed for hook "' + hookLabel + '": ' + (err && err.message || err), 'error');
                        CertMate.toast('Test request failed', 'error', undefined, { key: toastKey });
                    })
                    .then(function () {
                        if (btn) {
                            btn.disabled = false;
                            btn.innerHTML = originalHTML;
                        }
                    });
            },

            showExecutionDetail: function (entry) {
                // Open the drill-down modal for a single deploy_history.jsonl
                // row. All fields already arrive via /api/deploy/history; this
                // surface is read-only and never re-fetches.
                this.selectedExecution = entry;
                if (window.CertMate && CertMate.modal && typeof CertMate.modal.open === 'function') {
                    CertMate.modal.open('executionDetailModal');
                }
                var label = (entry && entry.hook_name) || (entry && entry.hook_id) || 'unnamed';
                addDebugLog('Opened execution detail: ' + label + ' on ' + (entry && entry.domain), 'info');
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

    // Registered by name as well: the build of Alpine in use evaluates an
    // expression without `eval` and reaches nothing outside the component,
    // so `x-data="deployManager()"` finds it here and not on `window`.
    document.addEventListener('alpine:init', function () {
        Alpine.data('deployManager', deployManager);
    });
})();
