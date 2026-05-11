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
                fetch('/api/notifications/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(self.config)
                })
                    .then(function (r) { return r.json(); })
                    .then(function () { CertMate.toast('Notification settings saved', 'success'); })
                    .catch(function () { CertMate.toast('Failed to save', 'error'); });
            },
            testSmtp: function () {
                var self = this;
                fetch('/api/notifications/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ channel_type: 'smtp', config: self.config.channels.smtp })
                })
                    .then(function (r) { return r.json(); })
                    .then(function (d) { CertMate.toast(d.success ? 'Test email sent!' : ('Email failed: ' + (d.error || 'unknown')), d.success ? 'success' : 'error'); })
                    .catch(function () { CertMate.toast('Test failed', 'error'); });
            },
            sendDigest: function () {
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
                    .catch(function () { CertMate.toast('Failed to send digest', 'error'); });
            },
            testWebhook: function (wh) {
                fetch('/api/notifications/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ channel_type: 'webhook', config: wh })
                })
                    .then(function (r) { return r.json(); })
                    .then(function (d) { CertMate.toast(d.success ? 'Webhook test sent!' : ('Webhook failed: ' + (d.error || 'unknown')), d.success ? 'success' : 'error'); })
                    .catch(function () { CertMate.toast('Test failed', 'error'); });
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
