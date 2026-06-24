(function () {
    'use strict';

    function addDebugLog(message, type) {
        var ns = window.CmSettings;
        if (ns && typeof ns.addDebugLog === 'function') ns.addDebugLog(message, type);
    }

    // Alpine.js component: deployment probe management.
    function probeManager() {
        return {
            // All certificates (with probe fields), loaded from /api/certificates
            certificates: [],
            // Certificates that have a probe configured
            configured: [],
            // Certificates without a probe
            unconfigured: [],
            // Search/filter
            search: '',
            // "Add probe" section state
            addDomain: '',
            addPort: '',
            addProtocol: 'https-tls',
            addProtoOpen: false,
            // "Edit" state
            editingDomain: null,
            editPort: '',
            editProtocol: 'https-tls',
            editProtoOpen: false,

            loadCertificates: function () {
                var self = this;
                addDebugLog('Loading certificates for probe list…', 'info');
                fetch('/api/certificates', { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (!Array.isArray(data)) {
                            addDebugLog('Invalid response from /api/certificates', 'error');
                            return;
                        }
                        self.certificates = data;
                        self._partition();
                        addDebugLog('Loaded ' + data.length + ' certificates, '
                            + self.configured.length + ' with probes', 'info');
                    })
                    .catch(function (err) {
                        addDebugLog('Failed to load certificates: ' + (err && err.message || err), 'error');
                        CertMate.toast('Failed to load certificates', 'error');
                    });
            },

            _partition: function () {
                var self = this;
                var conf = [];
                var unconf = [];
                self.certificates.forEach(function (cert) {
                    if (cert.deployment_port || cert.deployment_protocol) {
                        conf.push(cert);
                    } else {
                        unconf.push(cert);
                    }
                });
                self.configured = conf;
                self.unconfigured = unconf;
            },

            get filteredConfigured() {
                var q = this.search.toLowerCase();
                return this.configured.filter(function (c) {
                    return !q || c.domain.toLowerCase().indexOf(q) !== -1;
                });
            },

            get filteredUnconfigured() {
                var q = this.search.toLowerCase();
                return this.unconfigured.filter(function (c) {
                    return !q || c.domain.toLowerCase().indexOf(q) !== -1;
                });
            },

            addProbe: function () {
                var domain = this.addDomain.trim();
                if (!domain) {
                    CertMate.toast('Enter a domain name', 'error');
                    return;
                }
                var self = this;
                var body = {};
                var portNum = parseInt(this.addPort, 10);
                if (this.addPort !== '' && !isNaN(portNum) && portNum >= 1 && portNum <= 65535) {
                    body.deployment_port = portNum;
                } else if (this.addPort !== '') {
                    CertMate.toast('Invalid port. Must be 1-65535 or empty for default.', 'error');
                    return;
                }
                if (this.addProtocol) {
                    body.deployment_protocol = this.addProtocol;
                }

                fetch('/api/certificates/' + encodeURIComponent(domain), {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(body)
                })
                    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, body: d }; }); })
                    .then(function (res) {
                        if (res.ok) {
                            CertMate.toast('Probe configured for ' + domain, 'success');
                            addDebugLog('Probe configured for ' + domain, 'info');
                            self.addDomain = '';
                            self.addPort = '';
                            self.addProtocol = 'https-tls';
                            self.loadCertificates();
                        } else {
                            var msg = (res.body && res.body.error) || 'unknown error';
                            CertMate.toast('Failed: ' + msg, 'error');
                            addDebugLog('Failed to configure probe for ' + domain + ': ' + msg, 'error');
                        }
                    })
                    .catch(function (err) {
                        CertMate.toast('Request failed: ' + (err && err.message || err), 'error');
                    });
            },

            startEdit: function (cert) {
                this.editingDomain = cert.domain;
                this.editPort = cert.deployment_port || '';
                this.editProtocol = cert.deployment_protocol || 'https-tls';
            },

            cancelEdit: function () {
                this.editingDomain = null;
                this.editPort = '';
                this.editProtocol = 'https-tls';
            },

            saveEdit: function () {
                var self = this;
                var domain = this.editingDomain;
                var body = {};
                var portNum = parseInt(this.editPort, 10);
                if (this.editPort !== '' && !isNaN(portNum) && portNum >= 1 && portNum <= 65535) {
                    body.deployment_port = portNum;
                } else if (this.editPort !== '') {
                    CertMate.toast('Invalid port. Must be 1-65535 or empty for default.', 'error');
                    return;
                } else {
                    body.deployment_port = null;
                }
                if (this.editProtocol) {
                    body.deployment_protocol = this.editProtocol;
                }

                fetch('/api/certificates/' + encodeURIComponent(domain), {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(body)
                })
                    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, body: d }; }); })
                    .then(function (res) {
                        if (res.ok) {
                            CertMate.toast('Probe updated for ' + domain, 'success');
                            addDebugLog('Probe updated for ' + domain, 'info');
                            self.cancelEdit();
                            self.loadCertificates();
                        } else {
                            var msg = (res.body && res.body.error) || 'unknown error';
                            CertMate.toast('Failed: ' + msg, 'error');
                        }
                    })
                    .catch(function (err) {
                        CertMate.toast('Request failed: ' + (err && err.message || err), 'error');
                    });
            },

            removeProbe: function (domain) {
                var self = this;
                CertMate.confirm('Remove deployment probe for ' + domain + '?', 'Remove Probe')
                    .then(function (confirmed) {
                        if (!confirmed) return;
                        fetch('/api/certificates/' + encodeURIComponent(domain), {
                            method: 'PATCH',
                            headers: { 'Content-Type': 'application/json' },
                            credentials: 'same-origin',
                            body: JSON.stringify({
                                deployment_port: null,
                                deployment_protocol: null
                            })
                        })
                            .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, body: d }; }); })
                            .then(function (res) {
                                if (res.ok) {
                                    CertMate.toast('Probe removed for ' + domain, 'success');
                                    addDebugLog('Probe removed for ' + domain, 'info');
                                    self.loadCertificates();
                                } else {
                                    var msg = (res.body && res.body.error) || 'unknown error';
                                    CertMate.toast('Failed: ' + msg, 'error');
                                }
                            })
                            .catch(function (err) {
                                CertMate.toast('Request failed: ' + (err && err.message || err), 'error');
                            });
                    });
            },

            protocolLabel: function (protocol) {
                var labels = {
                    'https-tls': 'HTTPS/TLS',
                    'tls': 'TLS',
                    'smtp-starttls': 'SMTP STARTTLS'
                };
                return labels[protocol] || protocol || '—';
            }
        };
    }

    window.probeManager = probeManager;
})();
