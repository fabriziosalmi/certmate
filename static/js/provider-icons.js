/*
 * Provider brand icons.
 *
 * Replaces the generic FontAwesome glyph on each DNS-provider radio card with
 * a real brand logo (vendored SVGs under /static/img/providers/) or, for
 * providers with no brand mark, an elegant monogram chip. Centralising the
 * mapping here keeps the ~30 provider cards in settings_dns.html untouched and
 * makes window.providerIconHtml() reusable anywhere a provider is shown.
 *
 * Logos are MIT-licensed marks from simple-icons, used nominatively to
 * identify each provider. Regional / family variants (ovh-eu, kimsufi, …)
 * collapse onto their parent brand.
 */
(function () {
    'use strict';

    // value → brand logo slug (file: /static/img/providers/<slug>.svg)
    var LOGO = {
        cloudflare: 'cloudflare',
        route53: 'amazonwebservices', 'us-east-1': 'amazonwebservices',
        digitalocean: 'digitalocean',
        azure: 'microsoftazure',
        google: 'googlecloud',
        vultr: 'vultr',
        linode: 'linode',
        edgedns: 'akamai',
        hetzner: 'hetzner', 'hetzner-cloud': 'hetzner',
        gandi: 'gandi',
        godaddy: 'godaddy',
        namecheap: 'namecheap',
        ovh: 'ovh', 'ovh-ca': 'ovh', 'ovh-eu': 'ovh', 'ovh-us': 'ovh',
        'kimsufi-ca': 'ovh', 'kimsufi-eu': 'ovh',
        'soyoustart-ca': 'ovh', 'soyoustart-eu': 'ovh',
        scaleway: 'scaleway',
        porkbun: 'porkbun',
        infomaniak: 'infomaniak'
    };

    // value → monogram initials for providers without a brand logo.
    var MONO = {
        powerdns: 'PD', rfc2136: 'RF', 'acme-dns': 'AD', desec: 'dS',
        arvancloud: 'AC', nsone: 'NS', dnsmadeeasy: 'DM', dynudns: 'DY',
        duckdns: 'DD', 'he-ddns': 'HE'
    };

    function escapeAttr(s) {
        return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function logoHtml(slug, label, sizeCls) {
        return '<img src="/static/img/providers/' + slug + '.svg" alt="' + escapeAttr(label) + '" ' +
            'class="inline-block object-contain ' + (sizeCls || 'h-6 w-6 mb-1') + '" loading="lazy" draggable="false">';
    }

    function monoHtml(initials, label, sizeCls, textCls) {
        return '<span class="inline-flex items-center justify-center rounded-md bg-surface-2 text-muted font-semibold tracking-tight ' +
            (sizeCls || 'h-6 w-6 mb-1') + ' ' + (textCls || 'text-[10px]') + '" ' +
            'role="img" aria-label="' + escapeAttr(label) + '">' + escapeAttr(initials) + '</span>';
    }

    // Icon HTML for a provider value, or null to leave the existing glyph
    // (challenge types, custom-script, anything unmapped). opts.sizeCls and
    // opts.textCls override the default card sizing for inline contexts (e.g.
    // the certificate detail modal uses a smaller, margin-free variant).
    window.providerIconHtml = function (value, label, opts) {
        opts = opts || {};
        label = label || value;
        if (LOGO[value]) return logoHtml(LOGO[value], label, opts.sizeCls);
        if (MONO[value]) return monoHtml(MONO[value], label, opts.sizeCls, opts.textCls);
        return null;
    };

    function enhance() {
        document.querySelectorAll('input[name="dns_provider"]').forEach(function (input) {
            var card = input.closest('label');
            if (!card) return;
            var host = card.querySelector('.text-center');
            if (!host) return;
            // Only the leading glyph (direct child <i>) — never the nested
            // account-count icon inside #<provider>-accounts.
            var glyph = host.querySelector(':scope > i');
            if (!glyph) return;
            var labelEl = host.querySelector('.text-xs.font-medium');
            var label = labelEl ? labelEl.textContent.trim() : input.value;
            var html = window.providerIconHtml(input.value, label);
            if (!html) return;
            var tmp = document.createElement('div');
            tmp.innerHTML = html;
            if (tmp.firstChild) glyph.replaceWith(tmp.firstChild);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', enhance);
    } else {
        enhance();
    }
})();
