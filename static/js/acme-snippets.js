/*
 * The commands a client needs to enrol with CertMate's ACME server (#476, H4).
 *
 * Shown once, next to the HMAC key of a new EAB key, filled in with the
 * directory URL, the key identifier and the key itself: that is what turns
 * "I have a key" into "I have a certificate" without reading a manual. The
 * lego 5.5 (`lego run`), acme.sh 3.1 and cert-manager 1.21 forms are the ones
 * the runs in tests/interop used against this server (cert-manager there as
 * an Issuer; a ClusterIssuer takes the same spec). certbot's protocol client
 * runs in the test suite; its command line here uses the flags `certbot
 * --help all` documents, --eab-kid and --eab-hmac-key.
 *
 * acme.sh renews 29 days after issuance unless given --days; below 45 days of
 * validity its command carries a negative --days, a third of the lifetime
 * before expiry, which is when the others renew.
 *
 * Pure: no DOM, so tests/test_the_acme_settings_give_client_commands.py runs
 * it under node.
 */
(function (root) {
    'use strict';

    // A name the key may order, to put in the examples: the pattern itself,
    // or a host below a "*." pattern.
    function sampleName(patterns) {
        var first = (patterns && patterns[0]) || 'host.example.internal';
        return first.indexOf('*.') === 0 ? 'host.' + first.slice(2) : first;
    }

    function acmeshDays(validityDays) {
        if (!validityDays || validityDays >= 45) return '';
        return ' --days -' + Math.max(1, Math.floor(validityDays / 3));
    }

    function snippets(input) {
        var dir = input.directory;
        var kid = input.kid;
        var hmac = input.hmac;
        var name = sampleName(input.patterns);
        var email = input.email || 'ops@example.internal';
        return {
            certbot: [
                'certbot certonly --standalone \\',
                '  --server ' + dir + ' \\',
                '  --eab-kid ' + kid + ' --eab-hmac-key ' + hmac + ' \\',
                '  --email ' + email + ' --agree-tos \\',
                '  -d ' + name
            ].join('\n'),
            lego: [
                'lego run --server ' + dir + ' \\',
                '  --eab --eab.kid ' + kid + ' --eab.hmac ' + hmac + ' \\',
                '  --email ' + email + ' --accept-tos \\',
                '  --domains ' + name + ' --http'
            ].join('\n'),
            acmesh: [
                'acme.sh --register-account --server ' + dir + ' \\',
                '  --eab-kid ' + kid + ' --eab-hmac-key ' + hmac + ' -m ' + email,
                'acme.sh --issue --standalone --server ' + dir + ' -d ' + name + acmeshDays(input.validityDays)
            ].join('\n'),
            certmanager: [
                'apiVersion: v1',
                'kind: Secret',
                'metadata:',
                '  name: certmate-eab',
                '  namespace: cert-manager',
                'stringData:',
                '  secret: ' + hmac,
                '---',
                'apiVersion: cert-manager.io/v1',
                'kind: ClusterIssuer',
                'metadata:',
                '  name: certmate',
                'spec:',
                '  acme:',
                '    server: ' + dir,
                '    email: ' + email,
                '    privateKeySecretRef:',
                '      name: certmate-acme-account',
                '    externalAccountBinding:',
                '      keyID: ' + kid,
                '      keySecretRef:',
                '        name: certmate-eab',
                '        key: secret',
                '    solvers:',
                '      - http01:',
                '          ingress:',
                '            ingressClassName: nginx'
            ].join('\n')
        };
    }

    root.CertMateAcme = { snippets: snippets, sampleName: sampleName };
})(typeof window !== 'undefined' ? window : globalThis);
