(function () {
    'use strict';

    // Alpine.js component: notification settings (SMTP, webhooks, deliveries).
    // Self-contained — only depends on window.CertMate (toast).
    function notificationSettings() {
        return {
            config: {
                enabled: false,
                digest_enabled: true,
                events: [],
                channels: {
                    smtp: { enabled: false, host: '', port: 587, username: '', password: '', from_address: '', to_addresses: [], use_tls: true },
                    webhooks: []
                }
            },
            showSmtp: false,
            showWebhooks: false,
            showDeliveries: false,
            deliveries: [],
            get smtpToStr() { return (this.config.channels.smtp.to_addresses || []).join(', '); },
            set smtpToStr(v) { this.config.channels.smtp.to_addresses = v.split(',').map(function (s) { return s.trim(); }).filter(Boolean); },
            toggleEvent: function (evt) {
                var idx = this.config.events.indexOf(evt);
                if (idx === -1) this.config.events.push(evt);
                else this.config.events.splice(idx, 1);
            },
            loadConfig: function () {
                var self = this;
                fetch('/api/notifications/config', { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (data && typeof data === 'object' && !data.error) {
                            self.config.enabled = data.enabled || false;
                            self.config.digest_enabled = data.digest_enabled !== false;
                            self.config.events = data.events || [];
                            if (data.channels) {
                                if (data.channels.smtp) Object.assign(self.config.channels.smtp, data.channels.smtp);
                                if (data.channels.webhooks) self.config.channels.webhooks = data.channels.webhooks;
                            }
                        }
                    })
                    .catch(function (err) {
                        // Don't toast — this fires on tab switch and a stale
                        // session would spam the user. Devs still want it in
                        // the console for triage.
                        console.error('Failed to load notification config:', err);
                    });
            },
            saveConfig: function () {
                var self = this;
                var btn = document.querySelector('[x-ref="saveNotifBtn"], [data-action="save-notifications"]');
                var originalHTML;
                if (btn) {
                    originalHTML = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Saving...';
                }
                // _preview is editor state, not configuration.
                (self.config.channels.webhooks || []).forEach(function (wh) { if (wh && wh._preview) delete wh._preview; });
                fetch('/api/notifications/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(self.config)
                })
                    // r.ok must gate the toast: /api/notifications/config is
                    // admin-only and answers JSON on 403/400/503, so reading
                    // the body alone made every failure render as a green
                    // "saved" — the operator closed the tab believing SMTP
                    // was configured and no alert ever fired (#415).
                    .then(function (r) {
                        return r.json()
                            .catch(function () { return {}; })
                            .then(function (data) { return { ok: r.ok, status: r.status, data: data }; });
                    })
                    .then(function (res) {
                        if (!res.ok) {
                            var msg = (res.data && (res.data.error || res.data.message))
                                || ('Failed to save (HTTP ' + res.status + ')');
                            CertMate.toast(msg, 'error');
                            return;
                        }
                        CertMate.toast('Notification settings saved', 'success');
                    })
                    .catch(function () { CertMate.toast('Failed to save', 'error'); })
                    .then(function () {
                        if (btn) {
                            btn.disabled = false;
                            btn.innerHTML = originalHTML;
                        }
                    });
            },
            testSmtp: function () {
                var self = this;
                var btn = document.querySelector('[x-ref="testSmtpBtn"], [data-action="test-smtp"]');
                var originalHTML;
                if (btn) {
                    originalHTML = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Testing...';
                }
                fetch('/api/notifications/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ channel_type: 'smtp', config: self.config.channels.smtp })
                })
                    .then(function (r) { return r.json(); })
                    .then(function (d) { CertMate.toast(d.success ? 'Test email sent!' : ('Email failed: ' + (d.error || 'unknown')), d.success ? 'success' : 'error'); })
                    .catch(function () { CertMate.toast('Test failed', 'error'); })
                    .then(function () {
                        if (btn) {
                            btn.disabled = false;
                            btn.innerHTML = originalHTML;
                        }
                    });
            },
            sendDigest: function () {
                var btn = document.querySelector('[x-ref="sendDigestBtn"], [data-action="send-digest"]');
                var originalHTML;
                if (btn) {
                    originalHTML = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Sending...';
                }
                fetch('/api/digest/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin'
                })
                    .then(function (r) { return r.json(); })
                    .then(function (d) {
                        if (d.success) CertMate.toast('Weekly digest sent!', 'success');
                        else CertMate.toast('Digest: ' + (d.error || d.skipped || 'unknown error'), d.skipped ? 'warning' : 'error');
                    })
                    .catch(function () { CertMate.toast('Failed to send digest', 'error'); })
                    .then(function () {
                        if (btn) {
                            btn.disabled = false;
                            btn.innerHTML = originalHTML;
                        }
                    });
            },
            testWebhook: function (wh) {
                var btn = event && event.target ? event.target.closest('button') : null;
                var originalHTML;
                if (btn) {
                    originalHTML = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Testing...';
                }
                fetch('/api/notifications/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ channel_type: 'webhook', config: wh })
                })
                    .then(function (r) { return r.json(); })
                    .then(function (d) { CertMate.toast(d.success ? 'Webhook test sent!' : ('Webhook failed: ' + (d.error || 'unknown')), d.success ? 'success' : 'error'); })
                    .catch(function () { CertMate.toast('Test failed', 'error'); })
                    .then(function () {
                        if (btn) {
                            btn.disabled = false;
                            btn.innerHTML = originalHTML;
                        }
                    });
            },
            // Payload-template editor (#218): the placeholder chips, insertion at
            // the caret, and a dry render through /api/notifications/webhook/preview.
            templateVariables: ['event', 'title', 'message', 'timestamp', 'domain', 'details', 'details.error', 'details.days_until_expiry', 'details.expires_at'],
            insertPlaceholder: function (wh, name, ev) {
                var token = '{{' + name + '}}';
                var card = ev && ev.target ? ev.target.closest('.border.rounded-lg') : null;
                var area = card ? card.querySelector('textarea[aria-label="Payload template"]') : null;
                var current = wh.payload_template || '';
                if (area && typeof area.selectionStart === 'number') {
                    var start = area.selectionStart, end = area.selectionEnd;
                    wh.payload_template = current.slice(0, start) + token + current.slice(end);
                    var self = this;
                    self.$nextTick(function () {
                        area.focus();
                        area.setSelectionRange(start + token.length, start + token.length);
                    });
                } else {
                    wh.payload_template = current + token;
                }
            },
            previewWebhook: function (wh) {
                var payload = Object.assign({}, wh);
                delete payload._preview;
                fetch('/api/notifications/webhook/preview', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ config: payload })
                })
                    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
                    .then(function (res) {
                        if (!res.ok || res.d.error) {
                            CertMate.toast('Preview: ' + (res.d.error || 'failed'), 'error');
                            wh._preview = null;
                            return;
                        }
                        var headers = Object.keys(res.d.headers || {}).map(function (k) { return k + ': ' + res.d.headers[k]; }).join('\n');
                        var body = res.d.body;
                        try { body = JSON.stringify(JSON.parse(res.d.body), null, 2); } catch (e) { /* show raw */ }
                        wh._preview = { method: res.d.method, url: res.d.url, text: headers + '\n\n' + body };
                    })
                    .catch(function () { CertMate.toast('Preview failed', 'error'); });
            },
            toggleWebhookEvent: function (wh, evt) {
                if (!wh.events) wh.events = [];
                var idx = wh.events.indexOf(evt);
                if (idx === -1) wh.events.push(evt);
                else wh.events.splice(idx, 1);
            },
            loadDeliveries: function () {
                var self = this;
                fetch('/api/webhooks/deliveries?limit=50', { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (Array.isArray(data)) self.deliveries = data;
                    })
                    .catch(function (err) {
                        console.error('Failed to load webhook deliveries:', err);
                    });
            }
        };
    }

    window.notificationSettings = notificationSettings;
})();
