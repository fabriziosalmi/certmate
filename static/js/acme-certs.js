(function () {
    'use strict';

    // The dashboard's ACME view (#476, H1): what the ACME server issued, to a
    // viewer as client certificates are (H2), with revocation for an admin
    // (H3). Loaded the first time the view is shown, and again on each return.

    function acmeCertificates() {
        return {
            loading: false,
            loaded: false,
            certificates: [],
            filter: '',
            // Kept here, not read from CertMate.role in an expression: that is
            // filled in by a request of its own and is not reactive, so a getter
            // over it answered "not an admin" once and never again.
            isAdmin: false,

            init: function () {
                var self = this;
                this.$watch('$store.certs.view', function (view) { if (view === 'acme') self.load(); });
                if (this.$store.certs.view === 'acme') this.load();
            },

            get shown() {
                var needle = this.filter.trim().toLowerCase();
                if (!needle) return this.certificates;
                return this.certificates.filter(function (c) {
                    return c.names.join(' ').toLowerCase().indexOf(needle) !== -1
                        || (c.eab_kid || '').toLowerCase().indexOf(needle) !== -1;
                });
            },
            get empty() { return this.loaded && this.certificates.length === 0; },
            formatDate: function (value) { return CertMate.formatDate(value); },
            shortId: function (value) { return (value || '').slice(0, 8); },
            joined: function (list) { return (list || []).join(', '); },
            badge: function (status) {
                if (status === 'valid') return 'bg-success-surface text-success-strong';
                if (status === 'revoked') return 'bg-danger-surface text-danger-strong';
                return 'bg-warning-surface text-warning-strong';
            },

            load: function () {
                var self = this;
                self.loading = true;
                CertMate.refreshRole().then(function () { self.isAdmin = CertMate.roleAtLeast('admin'); });
                CertMate.api('GET', '/api/acme/certificates')
                    .then(function (answer) { self.certificates = answer.certificates; })
                    .catch(function (error) { CertMate.toast(error.message || 'Could not load the ACME certificates', 'error'); })
                    .then(function () { self.loading = false; self.loaded = true; });
            },

            revoke: function (certificate) {
                var self = this;
                CertMate.confirm('Revoke the certificate for ' + certificate.names.join(', ') + '? The ACME CRL '
                    + 'lists it from now on. This cannot be undone.', 'Revoke certificate')
                    .then(function (yes) {
                        if (!yes) return;
                        CertMate.api('POST', '/api/acme/certificates/' + encodeURIComponent(certificate.id) + '/revoke', {})
                            .then(function () { CertMate.toast('Certificate revoked', 'success'); self.load(); })
                            .catch(function (error) { CertMate.toast(error.message || 'Could not revoke', 'error'); });
                    });
            }
        };
    }

    window.acmeCertificates = acmeCertificates;
    document.addEventListener('alpine:init', function () {
        Alpine.data('acmeCertificates', acmeCertificates);
    });
})();
