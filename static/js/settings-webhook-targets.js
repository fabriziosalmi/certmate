(function () {
    'use strict';

    // Alpine.js component: webhook deploy targets (#218), in Settings -> Deploy.
    //
    // A component of its own, not more of deployManager, for one reason: what it
    // writes. deployManager posts {enabled, global_hooks, domain_hooks} and the
    // server merges per top-level key, so a save there leaves `targets` alone.
    // This component posts ONLY `targets`, and a `targets` value REPLACES the list.
    // So every write here reads the list the server holds at that moment, changes
    // the one target it is about, and sends the list back: the copy this page
    // loaded ten minutes ago, or one an API client has edited since, is never the
    // base of an overwrite. Targets of another type (Kubernetes secrets) pass
    // through untouched.

    var EVENT_CHOICES = ['created', 'renewed', 'revoked'];
    var METHOD_CHOICES = ['POST', 'PUT', 'PATCH'];
    var CERT_VARIABLES = ['cert', 'fullchain', 'chain'];
    var KEY_VARIABLES = ['privkey_pkcs8', 'privkey_traditional'];
    var EVENT_VARIABLES = ['domain', 'event', 'timestamp', 'certificate_sha256'];

    // The same test the server applies (`key_variables` in deploy_target_webhook.py):
    // a placeholder may have spaces inside the braces.
    var KEY_REFERENCE = /\{\{\s*privkey_(?:pkcs8|traditional)\s*\}\}/;

    // A starting point that does NOT carry the key. Sending the key is a choice
    // made by adding a key variable, not one a default makes for the operator.
    var STARTER_TEMPLATE = '{\n  "name": "{{domain}}",\n  "certificate": "{{fullchain}}"\n}';

    // Every config field this form owns. Anything else an API client put there is
    // carried through a save unchanged rather than dropped because the form
    // has never heard of it.
    var MANAGED_CONFIG = ['url', 'method', 'payload_template', 'auth_type', 'auth_token',
        'auth_username', 'auth_password', 'auth_header', 'signing_secret', 'ca_cert',
        'pin_sha256', 'allow_internal', 'timeout', 'attempts', 'acknowledge_key_delivery_to'];

    function clone(value) {
        return JSON.parse(JSON.stringify(value));
    }

    // The host the way the server reads it (`urlparse(url).hostname`, lower-cased):
    // no port, no brackets around an IPv6 literal. The typed confirmation is
    // compared with this, and so is the consent the server recorded.
    function hostOf(url) {
        try {
            return new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, '');
        } catch (e) {
            return '';
        }
    }

    function sendsKey(template) {
        return KEY_REFERENCE.test(template || '');
    }

    function parseDomains(text) {
        var seen = {};
        return String(text || '').split(/[\s,]+/).map(function (d) {
            return d.trim().toLowerCase();
        }).filter(function (d) {
            if (!d || seen[d]) return false;
            seen[d] = true;
            return true;
        });
    }

    function newId() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    function emptyDraft() {
        return {
            id: newId(), isNew: true, original: null, consent: null,
            name: '', enabled: true, domainsText: '',
            events: { created: true, renewed: true, revoked: false },
            url: '', method: 'POST',
            auth_type: 'none', auth_token: '', auth_username: '', auth_password: '', auth_header: '',
            signing_secret: '',
            trust: 'system', ca_cert: '', pin_sha256: '',
            allow_internal: false, timeout: '', attempts: '',
            payload_template: ''
        };
    }

    // The stored target -> the flat shape the form edits.
    function toDraft(target) {
        var cfg = target.config || {};
        var events = target.on_events && target.on_events.length ? target.on_events : ['created', 'renewed'];
        return {
            id: target.id, isNew: false, original: clone(target), consent: target.delivery_consent || null,
            name: target.name || '',
            // The runner treats a missing `enabled` as off, so the form does too.
            enabled: !!target.enabled,
            domainsText: (target.domains || []).join('\n'),
            events: {
                created: events.indexOf('created') !== -1,
                renewed: events.indexOf('renewed') !== -1,
                revoked: events.indexOf('revoked') !== -1
            },
            url: cfg.url || '', method: (cfg.method || 'POST').toUpperCase(),
            auth_type: cfg.auth_type || 'none', auth_token: cfg.auth_token || '',
            auth_username: cfg.auth_username || '', auth_password: cfg.auth_password || '',
            auth_header: cfg.auth_header || '',
            signing_secret: cfg.signing_secret || '',
            trust: cfg.pin_sha256 ? 'pin' : (cfg.ca_cert ? 'ca' : 'system'),
            ca_cert: cfg.ca_cert || '', pin_sha256: cfg.pin_sha256 || '',
            allow_internal: cfg.allow_internal === true,
            timeout: cfg.timeout === undefined || cfg.timeout === null ? '' : cfg.timeout,
            attempts: cfg.attempts === undefined || cfg.attempts === null ? '' : cfg.attempts,
            payload_template: cfg.payload_template || ''
        };
    }

    // The form -> the stored shape. Never carries `delivery_consent`: the server
    // writes it, and a page that could post its own would be confirming for itself.
    function toTarget(draft) {
        var target = draft.original ? clone(draft.original) : {};
        delete target.delivery_consent;
        var cfg = target.config && typeof target.config === 'object' ? target.config : {};
        MANAGED_CONFIG.forEach(function (key) { delete cfg[key]; });

        target.id = draft.id;
        target.type = 'webhook';
        target.name = draft.name.trim();
        target.enabled = !!draft.enabled;
        target.domains = parseDomains(draft.domainsText);
        target.on_events = EVENT_CHOICES.filter(function (e) { return draft.events[e]; });

        cfg.url = draft.url.trim();
        cfg.method = draft.method;
        cfg.payload_template = draft.payload_template;
        cfg.allow_internal = !!draft.allow_internal;
        cfg.auth_type = draft.auth_type;
        if (draft.auth_type === 'bearer') {
            cfg.auth_token = draft.auth_token;
        } else if (draft.auth_type === 'basic') {
            cfg.auth_username = draft.auth_username;
            cfg.auth_password = draft.auth_password;
        } else if (draft.auth_type === 'header') {
            cfg.auth_token = draft.auth_token;
            if (draft.auth_header.trim()) cfg.auth_header = draft.auth_header.trim();
        }
        if (draft.signing_secret) cfg.signing_secret = draft.signing_secret;
        // One trust mode at a time: the server refuses a CA together with a pin,
        // and a field left over from another mode must not ride along.
        if (draft.trust === 'ca' && draft.ca_cert.trim()) cfg.ca_cert = draft.ca_cert.trim();
        if (draft.trust === 'pin' && draft.pin_sha256.trim()) cfg.pin_sha256 = draft.pin_sha256.trim();
        if (draft.timeout !== '' && draft.timeout !== null) cfg.timeout = draft.timeout;
        if (draft.attempts !== '' && draft.attempts !== null) cfg.attempts = draft.attempts;
        target.config = cfg;
        return target;
    }

    // fetch -> {ok, body}. A body that is not JSON (a proxy's HTML error page, a
    // 403) becomes {} rather than an exception that hides the status.
    function requestJson(url, options) {
        var init = Object.assign({ credentials: 'same-origin' }, options || {});
        if (init.body !== undefined) init.headers = { 'Content-Type': 'application/json' };
        return fetch(url, init).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (body) {
                return { ok: r.ok, status: r.status, body: body };
            });
        });
    }

    // A consent is written by the server and only by it: it records who confirmed
    // what, and a page that posted one back would be free to post a different one.
    // Every webhook target leaves here without it; the server keeps the stored
    // consent for a target whose host did not change and asks again for one whose
    // host did.
    function withoutConsent(list) {
        return list.map(function (target) {
            if (!target || target.type !== 'webhook' || !('delivery_consent' in target)) return target;
            var copy = Object.assign({}, target);
            delete copy.delivery_consent;
            return copy;
        });
    }

    function webhookTargets() {
        return {
            open: false,
            loaded: false,
            loadError: '',
            targets: [],
            draft: null,
            confirmHost: '',
            formError: '',
            saving: false,
            previewing: false,
            preview: null,
            previewedFor: '',
            previewError: '',

            eventChoices: EVENT_CHOICES,
            methodChoices: METHOD_CHOICES,
            certVariables: CERT_VARIABLES,
            keyVariables: KEY_VARIABLES,
            eventVariables: EVENT_VARIABLES,

            // --- reading ---------------------------------------------------

            load: function () {
                var self = this;
                return requestJson('/api/deploy/config').then(function (res) {
                    if (res.ok && res.body && !res.body.error) {
                        self.targets = Array.isArray(res.body.targets) ? res.body.targets : [];
                        self.loadError = '';
                    } else {
                        self.loadError = (res.body && res.body.error) || 'Could not load the deploy targets.';
                    }
                    self.loaded = true;
                }).catch(function () {
                    self.loadError = 'Could not load the deploy targets.';
                    self.loaded = true;
                });
            },

            isWebhook: function (target) {
                return !!target && target.type === 'webhook';
            },

            targetHost: function (target) {
                return hostOf(target && target.config && target.config.url);
            },

            // What the list says about a stored target's key: nothing when it does
            // not send one; the destination when it does and the server has a
            // matching confirmation; a warning when it does and has none (the
            // target then refuses to send).
            keyStatus: function (target) {
                var cfg = (target && target.config) || {};
                if (!sendsKey(cfg.payload_template)) return '';
                var consent = target.delivery_consent || {};
                var host = this.targetHost(target);
                return consent.host && consent.host === host ? 'confirmed' : 'unconfirmed';
            },

            // The one line under a target's name. A target of another type is listed
            // and left alone: this form edits webhook targets only.
            describe: function (target) {
                if (!this.isWebhook(target)) {
                    return 'Managed through the API; this screen does not edit it.';
                }
                var cfg = target.config || {};
                var domains = (target.domains || []).join(', ') || 'no domains';
                return (cfg.method || 'POST').toUpperCase() + ' ' + (this.targetHost(target) || 'no host')
                    + ' \u00b7 ' + domains + ' \u00b7 ' + this.eventSummary(target);
            },

            // The braces are built here, not written in the template: the page is
            // a Jinja template, and a literal pair of them there is an expression.
            placeholder: function (name) {
                return '{{' + name + '}}';
            },

            // Where the request goes, as a URL: the preview's host and port, with
            // the brackets an IPv6 literal needs and the default port left out.
            previewDestination: function () {
                var pv = this.preview || {};
                var host = (pv.host || '').indexOf(':') !== -1 ? '[' + pv.host + ']' : (pv.host || '');
                var port = pv.port && pv.port !== 443 ? ':' + pv.port : '';
                return (pv.method || '') + ' https://' + host + port + (pv.path || '/');
            },

            previewHeaders: function () {
                var headers = (this.preview && this.preview.headers) || {};
                return Object.keys(headers).map(function (name) { return [name, headers[name]]; });
            },

            eventSummary: function (target) {
                var events = target.on_events && target.on_events.length ? target.on_events : ['created', 'renewed'];
                return events.join(', ');
            },

            // --- the editor ------------------------------------------------

            startNew: function () {
                this.draft = emptyDraft();
                this._resetEditorState();
            },

            edit: function (target) {
                this.draft = toDraft(target);
                this._resetEditorState();
            },

            cancel: function () {
                this.draft = null;
                this._resetEditorState();
            },

            _resetEditorState: function () {
                this.confirmHost = '';
                this.formError = '';
                this.preview = null;
                this.previewedFor = '';
                this.previewError = '';
            },

            draftHost: function () {
                return this.draft ? hostOf(this.draft.url) : '';
            },

            draftSendsKey: function () {
                return !!this.draft && sendsKey(this.draft.payload_template);
            },

            draftKeyVariables: function () {
                var template = this.draft ? this.draft.payload_template : '';
                return KEY_VARIABLES.filter(function (name) {
                    return new RegExp('\\{\\{\\s*' + name + '\\s*\\}\\}').test(template);
                });
            },

            // A confirmation the server already holds for THIS host. A different
            // host, or none, means the operator has to confirm again: the consent
            // was about a destination, and the destination changed.
            consentCoversDraft: function () {
                var consent = this.draft && this.draft.consent;
                return !!(consent && consent.host && consent.host === this.draftHost());
            },

            consentWasForAnotherHost: function () {
                var consent = this.draft && this.draft.consent;
                return !!(consent && consent.host && consent.host !== this.draftHost());
            },

            needsConfirmation: function () {
                return this.draftSendsKey() && !this.consentCoversDraft();
            },

            // The typed host must equal the destination: copying it from the
            // screen is easy, and that is not the point. Typing it is what makes
            // the operator read which host is about to receive the key.
            confirmationMatches: function () {
                var host = this.draftHost();
                return host !== '' && this.confirmHost.trim().toLowerCase() === host;
            },

            canSave: function () {
                if (this.saving || !this.draft) return false;
                return !this.needsConfirmation() || this.confirmationMatches();
            },

            insertVariable: function (name) {
                if (!this.draft) return;
                var text = '{{' + name + '}}';
                var box = this.$refs && this.$refs.template;
                var value = this.draft.payload_template || '';
                var start = box && typeof box.selectionStart === 'number' ? box.selectionStart : value.length;
                var end = box && typeof box.selectionEnd === 'number' ? box.selectionEnd : value.length;
                this.draft.payload_template = value.slice(0, start) + text + value.slice(end);
                var caret = start + text.length;
                this.$nextTick(function () {
                    if (box) {
                        box.focus();
                        box.setSelectionRange(caret, caret);
                    }
                });
            },

            useStarter: function () {
                if (this.draft) this.draft.payload_template = STARTER_TEMPLATE;
            },

            // Problems worth saying before a round trip. The server validates
            // everything again and its reason is what the operator sees for the
            // rest; this only spares a request for the three obvious omissions.
            localProblem: function () {
                var d = this.draft;
                if (!d.name.trim()) return 'Give the target a name.';
                if (!parseDomains(d.domainsText).length) {
                    return 'List the domains it applies to. A target that sends certificate material is never applied to "all domains" by default.';
                }
                if (!d.url.trim()) return 'Enter the URL it sends to.';
                if (!d.payload_template.trim()) return 'Write the payload template, or start from the example.';
                return '';
            },

            // --- preview ---------------------------------------------------

            previewVisible: function () {
                return !!this.preview && this.previewedFor === JSON.stringify(this.draft);
            },

            runPreview: function () {
                var self = this;
                var problem = this.localProblem();
                if (problem) {
                    this.previewError = problem;
                    this.preview = null;
                    return;
                }
                this.previewing = true;
                this.previewError = '';
                var snapshot = JSON.stringify(this.draft);
                var domains = parseDomains(this.draft.domainsText);
                var domain = domains.length && domains[0].indexOf('*') === -1 ? domains[0] : 'example.com';
                requestJson('/api/deploy/targets/preview?domain=' + encodeURIComponent(domain), {
                    method: 'POST',
                    body: JSON.stringify(toTarget(this.draft))
                }).then(function (res) {
                    if (res.ok && res.body && !res.body.error) {
                        self.preview = res.body;
                        self.previewedFor = snapshot;
                    } else {
                        self.preview = null;
                        self.previewError = (res.body && res.body.error) || 'The preview failed (HTTP ' + res.status + ').';
                    }
                }).catch(function () {
                    self.preview = null;
                    self.previewError = 'The preview request failed.';
                }).then(function () {
                    self.previewing = false;
                });
            },

            // --- writing ---------------------------------------------------

            // Read what the server holds now, let `change` edit that list, write
            // it back. See the note at the top of the file for why the list this
            // page loaded earlier is never the thing that gets written.
            _write: function (change) {
                return requestJson('/api/deploy/config').then(function (current) {
                    if (!current.ok || !current.body || current.body.error) {
                        return { ok: false, body: { error: 'Could not read the current configuration, so nothing was changed.' } };
                    }
                    var list = Array.isArray(current.body.targets) ? current.body.targets.slice() : [];
                    return requestJson('/api/deploy/config', {
                        method: 'POST',
                        body: JSON.stringify({ targets: withoutConsent(change(list)) })
                    });
                });
            },

            save: function () {
                var self = this;
                var problem = this.localProblem();
                if (problem) {
                    this.formError = problem;
                    return;
                }
                if (!this.canSave()) return;
                var target = toTarget(this.draft);
                if (this.needsConfirmation()) {
                    target.config.acknowledge_key_delivery_to = this.confirmHost.trim().toLowerCase();
                }
                this.saving = true;
                this.formError = '';
                this._write(function (list) {
                    var at = -1;
                    list.forEach(function (t, i) { if (t && t.id === target.id) at = i; });
                    if (at === -1) list.push(target); else list[at] = target;
                    return list;
                }).then(function (res) {
                    if (res.ok) {
                        CertMate.toast('Deploy target saved', 'success');
                        self.draft = null;
                        self._resetEditorState();
                        return self.load();
                    }
                    self.formError = (res.body && res.body.error) || 'The target could not be saved.';
                }).catch(function () {
                    self.formError = 'The save request failed.';
                }).then(function () {
                    self.saving = false;
                });
            },

            toggleEnabled: function (target) {
                var self = this;
                this._write(function (list) {
                    return list.map(function (t) {
                        return t && t.id === target.id ? Object.assign({}, t, { enabled: !t.enabled }) : t;
                    });
                }).then(function (res) {
                    if (!res.ok) CertMate.toast((res.body && res.body.error) || 'Could not change the target', 'error');
                    return self.load();
                }).catch(function () {
                    CertMate.toast('Could not change the target', 'error');
                });
            },

            remove: function (target) {
                var self = this;
                CertMate.confirm('Delete the target "' + (target.name || target.id) + '"? Nothing more will be sent to it.',
                    'Delete target').then(function (confirmed) {
                    if (!confirmed) return null;
                    return self._write(function (list) {
                        return list.filter(function (t) { return !t || t.id !== target.id; });
                    }).then(function (res) {
                        if (res.ok) CertMate.toast('Deploy target deleted', 'success');
                        else CertMate.toast((res.body && res.body.error) || 'Could not delete the target', 'error');
                        return self.load();
                    });
                }).catch(function () {
                    CertMate.toast('Could not delete the target', 'error');
                });
            }
        };
    }

    window.webhookTargets = webhookTargets;
    // The pure parts, reachable from a browser test without driving the form.
    window.CertMateWebhookTargets = {
        hostOf: hostOf, sendsKey: sendsKey, parseDomains: parseDomains,
        toDraft: toDraft, toTarget: toTarget
    };
})();
