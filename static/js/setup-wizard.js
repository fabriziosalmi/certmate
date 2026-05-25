/**
 * First-Time Setup Wizard — static/js/setup-wizard.js
 * Shows a guided 3-step wizard when setup_completed is false.
 */
(function() {
    'use strict';

    var escapeHtml = CertMate.escapeHtml;

    // DNS provider definitions with required fields.
    // Field keys must match modules/core/utils.py _MULTI_PROVIDER_REQUIRED_FIELDS
    // and the per-provider create_*_config() signatures, since these values are
    // posted verbatim to /api/web/settings and consumed by certbot plugins.
    var PROVIDERS = {
        cloudflare:    { label: 'Cloudflare', icon: 'fa-cloud', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        route53:       { label: 'AWS Route 53', icon: 'fa-cloud-upload-alt', fields: [{ key: 'access_key_id', label: 'Access Key ID', type: 'text' }, { key: 'secret_access_key', label: 'Secret Access Key', type: 'password' }, { key: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1' }] },
        digitalocean:  { label: 'DigitalOcean', icon: 'fa-water', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        hetzner:       { label: 'Hetzner', icon: 'fa-server', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        gandi:         { label: 'Gandi', icon: 'fa-globe', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        linode:        { label: 'Akamai Connected Cloud (Linode)', icon: 'fa-cloud', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }] },
        edgedns:       { label: 'Akamai Edge DNS', icon: 'fa-cloud', fields: [{ key: 'client_token', label: 'Client Token', type: 'password' }, { key: 'client_secret', label: 'Client Secret', type: 'password' }, { key: 'access_token', label: 'Access Token', type: 'password' }, { key: 'host', label: 'API Host', type: 'text', placeholder: 'akab-XXXX.luna.akamaiapis.net' }] },
        porkbun:       { label: 'Porkbun', icon: 'fa-globe', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }, { key: 'secret_key', label: 'Secret Key', type: 'password' }] },
        godaddy:       { label: 'GoDaddy', icon: 'fa-globe', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }, { key: 'secret', label: 'API Secret', type: 'password' }] },
        namecheap:     { label: 'Namecheap', icon: 'fa-globe', fields: [{ key: 'username', label: 'Username', type: 'text' }, { key: 'api_key', label: 'API Key', type: 'password' }] },
        vultr:         { label: 'Vultr', icon: 'fa-cloud', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }] },
        ovh:           { label: 'OVH', icon: 'fa-globe', fields: [{ key: 'endpoint', label: 'Endpoint', type: 'text', placeholder: 'ovh-eu' }, { key: 'application_key', label: 'Application Key', type: 'text' }, { key: 'application_secret', label: 'Application Secret', type: 'password' }, { key: 'consumer_key', label: 'Consumer Key', type: 'password' }] },
        azure:         { label: 'Azure DNS', icon: 'fa-cube', fields: [{ key: 'subscription_id', label: 'Subscription ID', type: 'text' }, { key: 'resource_group', label: 'Resource Group', type: 'text' }, { key: 'tenant_id', label: 'Tenant ID', type: 'text' }, { key: 'client_id', label: 'Client ID', type: 'text' }, { key: 'client_secret', label: 'Client Secret', type: 'password' }] },
        google:        { label: 'Google Cloud DNS', icon: 'fa-cloud-meatball', fields: [{ key: 'project_id', label: 'Project ID', type: 'text' }, { key: 'service_account_key', label: 'Service Account Key (JSON)', type: 'textarea' }] },
        powerdns:      { label: 'PowerDNS', icon: 'fa-bolt', fields: [{ key: 'api_url', label: 'API URL', type: 'text', placeholder: 'https://powerdns.example.com:8081' }, { key: 'api_key', label: 'API Key', type: 'password' }] },
        rfc2136:       { label: 'RFC2136 (BIND/Knot)', icon: 'fa-network-wired', fields: [{ key: 'nameserver', label: 'Nameserver', type: 'text', placeholder: 'ns.example.com' }, { key: 'tsig_key', label: 'TSIG Key Name', type: 'text', placeholder: 'mykey' }, { key: 'tsig_secret', label: 'TSIG Secret', type: 'password', placeholder: 'Base64-encoded secret' }] },
        dnsmadeeasy:   { label: 'DNS Made Easy', icon: 'fa-globe', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }, { key: 'secret_key', label: 'Secret Key', type: 'password' }] },
        nsone:         { label: 'NS1', icon: 'fa-network-wired', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }] },
        'he-ddns':     { label: 'Hurricane Electric', icon: 'fa-bolt', fields: [{ key: 'username', label: 'Username', type: 'text' }, { key: 'password', label: 'Password', type: 'password' }] },
        dynudns:       { label: 'Dynu', icon: 'fa-globe', fields: [{ key: 'token', label: 'API Token', type: 'password' }] },
        duckdns:       { label: 'DuckDNS', icon: 'fa-cloud', fields: [{ key: 'api_token', label: 'Account Token', type: 'password', placeholder: 'UUID-format token from your DuckDNS account page' }] }
    };

    var state = { step: 1, email: '', provider: '', credentials: {} };

    function checkSetup() {
        var t = new Date().getTime();
        fetch('/api/web/settings?t=' + t, { credentials: 'same-origin', cache: 'no-store' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data && data.certmate_recovery_suggested) {
                    showRecoveryPrompt();
                } else if (data && data.setup_completed === false) {
                    showWizard();
                }
            })
            .catch(function(err) {
                // Wizard auto-detect is best-effort: if the request fails
                // (e.g. user is on /login and hits 401) we silently skip.
                // Log for triage but don't show a toast — the page may
                // legitimately be in a state where /api/web/settings 401s.
                console.error('Setup-detection request failed:', err);
            });
    }

    function showRecoveryPrompt() {
        var overlay = document.createElement('div');
        overlay.id = 'setupRecoveryPrompt';
        overlay.className = 'fixed inset-0 z-[110] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'recoveryPromptTitle');
        overlay.innerHTML =
            '<div class="bg-surface rounded-2xl shadow-2xl w-full max-w-lg p-8 text-center">' +
                '<div class="w-16 h-16 bg-warning-surface rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-exclamation-triangle text-warning-fg text-2xl"></i>' +
                '</div>' +
                '<h2 id="recoveryPromptTitle" class="text-xl font-bold text-foreground mb-2">Existing Data Detected</h2>' +
                '<p class="text-sm text-muted mb-6">' +
                    'CertMate found certificates on this volume but no matching configuration. ' +
                    'This usually happens after a downgrade. You can restore the latest backup to recover your users and domains, or start fresh.' +
                '</p>' +
                '<div class="space-y-3">' +
                    '<button id="recoveryRestore" class="w-full px-6 py-3 bg-primary hover:bg-secondary text-white font-medium rounded-lg text-sm transition">' +
                        '<i class="fas fa-archive mr-2"></i>Restore from Backup' +
                    '</button>' +
                    '<button id="recoveryFresh" class="w-full px-6 py-3 border border-border text-label font-medium rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700 transition">' +
                        'Start Fresh Setup' +
                    '</button>' +
                '</div>' +
                '<p class="mt-4 text-xs text-gray-400">' +
                    'Need help? Check the logs for <code class="bg-surface-2 px-1 rounded">DOWNGRADE DETECTED</code> or run <code class="bg-surface-2 px-1 rounded">scripts/reset_admin_password.py</code> inside the container to regain access.' +
                '</p>' +
            '</div>';
        document.body.appendChild(overlay);
        document.getElementById('recoveryRestore').addEventListener('click', function() {
            window.location.href = '/settings#backup';
        });
        document.getElementById('recoveryFresh').addEventListener('click', closeRecoveryPrompt);
        document.getElementById('recoveryFresh').addEventListener('click', showWizard);

        // Focus trapping within the recovery prompt
        overlay.addEventListener('keydown', function(e) {
            if (e.key !== 'Tab') return;
            var focusable = overlay.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (!focusable.length) return;
            var first = focusable[0];
            var last = focusable[focusable.length - 1];
            if (e.shiftKey) {
                if (document.activeElement === first) { e.preventDefault(); last.focus(); }
            } else {
                if (document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        });

        // Auto-focus first button
        setTimeout(function() { document.getElementById('recoveryRestore').focus(); }, 50);
    }

    function closeRecoveryPrompt() {
        var el = document.getElementById('setupRecoveryPrompt');
        if (el) el.remove();
    }

    function showWizard() {
        var overlay = document.createElement('div');
        overlay.id = 'setupWizard';
        overlay.className = 'fixed inset-0 z-[110] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'wizardTitle');
        overlay.innerHTML =
            '<div class="bg-surface rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">' +
                '<div class="px-6 py-5 border-b border-border">' +
                    '<div class="flex items-center justify-between">' +
                        '<div>' +
                            '<h2 id="wizardTitle" class="text-xl font-bold text-foreground">Welcome to CertMate</h2>' +
                            '<p class="text-sm text-muted mt-1">Let\'s get you set up in a few steps</p>' +
                        '</div>' +
                        '<div class="flex items-center gap-1.5" id="wizardSteps"></div>' +
                    '</div>' +
                '</div>' +
                '<div id="wizardBody" class="px-6 py-6"></div>' +
                '<div id="wizardFooter" class="px-6 py-4 border-t border-border flex items-center justify-between"></div>' +
            '</div>';
        document.body.appendChild(overlay);

        // Focus trapping within the wizard overlay
        overlay.addEventListener('keydown', function(e) {
            if (e.key !== 'Tab') return;
            var focusable = overlay.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (!focusable.length) return;
            var first = focusable[0];
            var last = focusable[focusable.length - 1];
            if (e.shiftKey) {
                if (document.activeElement === first) { e.preventDefault(); last.focus(); }
            } else {
                if (document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        });

        renderStep();
    }

    function renderStep() {
        renderStepIndicator();
        if (state.step === 1) renderStep1();
        else if (state.step === 2) renderStep2();
        else if (state.step === 3) renderStep3();
    }

    function renderStepIndicator() {
        var el = document.getElementById('wizardSteps');
        if (!el) return;
        var html = '';
        for (var i = 1; i <= 3; i++) {
            var cls = i === state.step
                ? 'w-8 h-8 rounded-full bg-primary text-white flex items-center justify-center text-sm font-bold'
                : i < state.step
                    ? 'w-8 h-8 rounded-full bg-green-500 text-white flex items-center justify-center text-sm'
                    : 'w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-600 text-muted flex items-center justify-center text-sm';
            html += '<div class="' + cls + '">' + (i < state.step ? '<i class="fas fa-check text-xs"></i>' : i) + '</div>';
            if (i < 3) html += '<div class="w-6 h-0.5 ' + (i < state.step ? 'bg-green-500' : 'bg-gray-200 dark:bg-gray-600') + '"></div>';
        }
        el.innerHTML = html;
    }

    function renderStep1() {
        var body = document.getElementById('wizardBody');
        body.innerHTML =
            '<div class="text-center mb-6">' +
                '<div class="w-16 h-16 bg-info-surface rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-envelope text-info-fg text-2xl"></i>' +
                '</div>' +
                '<h3 class="text-lg font-semibold text-foreground">Contact Email</h3>' +
                '<p class="text-sm text-muted mt-1">Required by certificate authorities for important notifications</p>' +
            '</div>' +
            '<div>' +
                '<label for="wizEmail" class="block text-sm font-medium text-label mb-2">Email Address</label>' +
                '<input type="email" id="wizEmail" value="' + escapeHtml(state.email) + '" placeholder="admin@example.com" ' +
                       'class="w-full px-4 py-3 border text-foreground border-border rounded-lg bg-input focus:ring-2 focus:ring-primary focus:border-primary text-sm" required>' +
                '<p class="mt-2 text-xs text-gray-400"><i class="fas fa-info-circle mr-1"></i>Used by Let\'s Encrypt for expiry warnings and account recovery</p>' +
            '</div>';

        var footer = document.getElementById('wizardFooter');
        footer.innerHTML =
            '<button type="button" id="wizSkip" class="text-sm text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">Skip wizard</button>' +
            '<button type="button" id="wizNext1" class="px-6 py-2.5 bg-primary hover:bg-secondary text-white font-medium rounded-lg text-sm transition">Next <i class="fas fa-arrow-right ml-1"></i></button>';

        document.getElementById('wizNext1').addEventListener('click', function() {
            var email = document.getElementById('wizEmail').value.trim();
            var emailError = document.getElementById('wizEmailError');
            if (!email || email.indexOf('@') === -1) {
                document.getElementById('wizEmail').classList.add('border-red-500');
                if (!emailError) {
                    var errEl = document.createElement('p');
                    errEl.id = 'wizEmailError';
                    errEl.className = 'text-xs text-red-500 mt-1';
                    errEl.textContent = 'Please enter a valid email address';
                    document.getElementById('wizEmail').parentNode.appendChild(errEl);
                }
                return;
            }
            // Clear error state on success
            document.getElementById('wizEmail').classList.remove('border-red-500');
            if (emailError) emailError.remove();
            state.email = email;
            state.step = 2;
            renderStep();
        });

        document.getElementById('wizSkip').addEventListener('click', closeWizard);
        document.getElementById('wizEmail').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') document.getElementById('wizNext1').click();
        });
        setTimeout(function() { document.getElementById('wizEmail').focus(); }, 100);
    }

    function renderStep2() {
        var body = document.getElementById('wizardBody');
        var html =
            '<div class="text-center mb-6">' +
                '<div class="w-16 h-16 bg-success-surface rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-server text-success-fg text-2xl"></i>' +
                '</div>' +
                '<h3 class="text-lg font-semibold text-foreground">DNS Provider</h3>' +
                '<p class="text-sm text-muted mt-1">Select where your domains are managed</p>' +
            '</div>' +
            '<div class="grid grid-cols-2 sm:grid-cols-3 gap-2" id="providerGrid">';

        Object.keys(PROVIDERS).forEach(function(key) {
            var p = PROVIDERS[key];
            var selected = state.provider === key;
            html += '<button type="button" data-provider="' + key + '" class="wiz-provider flex flex-col items-center p-3 rounded-lg border-2 transition text-sm ' + (selected ? 'border-primary bg-primary/5 text-primary' : 'border-border text-muted hover:border-gray-400') + '">' +
                '<i class="fas ' + escapeHtml(p.icon) + ' text-lg mb-1"></i>' +
                '<span class="text-xs font-medium">' + escapeHtml(p.label) + '</span>' +
            '</button>';
        });
        html += '</div>';

        // Credential fields (shown when provider selected)
        html += '<div id="credFields" class="' + (state.provider ? 'mt-4 space-y-3' : 'hidden') + '">';
        if (state.provider && PROVIDERS[state.provider]) {
            html += renderCredentialFields(state.provider);
        }
        html += '</div>';

        body.innerHTML = html;

        // Provider selection handlers
        body.querySelectorAll('.wiz-provider').forEach(function(btn) {
            btn.addEventListener('click', function() {
                state.provider = btn.dataset.provider;
                state.credentials = {};
                renderStep(); // re-render to show credentials
            });
        });

        var footer = document.getElementById('wizardFooter');
        footer.innerHTML =
            '<button type="button" id="wizBack2" class="px-4 py-2 text-sm text-muted hover:text-gray-900 dark:hover:text-white"><i class="fas fa-arrow-left mr-1"></i> Back</button>' +
            '<button type="button" id="wizNext2" class="px-6 py-2.5 bg-primary hover:bg-secondary text-white font-medium rounded-lg text-sm transition ' + (!state.provider ? 'opacity-50 cursor-not-allowed' : '') + '" ' + (!state.provider ? 'disabled' : '') + '>Save & Finish <i class="fas fa-check ml-1"></i></button>';

        document.getElementById('wizBack2').addEventListener('click', function() {
            state.step = 1;
            renderStep();
        });

        document.getElementById('wizNext2').addEventListener('click', function() {
            if (!state.provider) return;
            // Collect credentials
            var providerDef = PROVIDERS[state.provider];
            var creds = {};
            var valid = true;
            providerDef.fields.forEach(function(f) {
                var el = document.getElementById('wiz_' + f.key);
                var val = el ? el.value.trim() : '';
                if (!val) {
                    if (el) el.classList.add('border-red-500');
                    valid = false;
                }
                creds[f.key] = val;
            });
            if (!valid) return;
            state.credentials = creds;
            saveSettings();
        });
    }

    function renderCredentialFields(provider) {
        var pDef = PROVIDERS[provider];
        if (!pDef) return '';
        var html = '<div class="border-t border-border pt-4">' +
            '<h4 class="text-sm font-medium text-label mb-3"><i class="fas fa-key mr-1.5 text-yellow-500"></i>' + escapeHtml(pDef.label) + ' Credentials</h4>';

        pDef.fields.forEach(function(f) {
            var savedVal = state.credentials[f.key] || '';
            if (f.type === 'textarea') {
                html += '<div><label class="block text-xs font-medium text-muted mb-1">' + escapeHtml(f.label) + '</label>' +
                    '<textarea id="wiz_' + f.key + '" rows="3" class="w-full px-3 py-2 border text-foreground border-border rounded-lg bg-input text-sm focus:ring-2 focus:ring-primary focus:border-primary" placeholder="' + escapeHtml(f.placeholder || '') + '">' + escapeHtml(savedVal) + '</textarea></div>';
            } else {
                html += '<div><label class="block text-xs font-medium text-muted mb-1">' + escapeHtml(f.label) + '</label>' +
                    '<input type="' + f.type + '" id="wiz_' + f.key + '" value="' + escapeHtml(savedVal) + '" placeholder="' + escapeHtml(f.placeholder || '') + '" ' +
                    'class="w-full px-3 py-2 border text-foreground border-border rounded-lg bg-input text-sm focus:ring-2 focus:ring-primary focus:border-primary"></div>';
            }
        });
        html += '</div>';
        return html;
    }

    function saveSettings() {
        var btn = document.getElementById('wizNext2');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Saving...';
        }

        var dnsProviders = {};
        dnsProviders[state.provider] = { accounts: { default: state.credentials } };

        var payload = {
            email: state.email,
            dns_provider: state.provider,
            dns_providers: dnsProviders,
            auto_renew: true,
            setup_completed: true
        };

        fetch('/api/web/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(payload)
        })
        .then(function(r) {
            if (!r.ok) throw new Error('Save failed');
            return r.json();
        })
        .then(function() {
            state.step = 3;
            renderStep();
        })
        .catch(function(err) {
            console.error('Setup wizard save error:', err);
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = 'Save & Finish <i class="fas fa-check ml-1"></i>';
            }
            CertMate.toast('Failed to save settings. Please try again.', 'error');
        });
    }

    function renderStep3() {
        var body = document.getElementById('wizardBody');
        body.innerHTML =
            '<div class="text-center">' +
                '<div class="w-20 h-20 bg-success-surface rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-check-circle text-green-500 text-4xl"></i>' +
                '</div>' +
                '<h3 class="text-xl font-bold text-foreground mb-2">You\'re All Set!</h3>' +
                '<p class="text-sm text-muted mb-4">CertMate is configured and ready to manage your certificates.</p>' +
                '<div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-left text-sm space-y-2">' +
                    '<div class="flex items-center"><i class="fas fa-check text-green-500 mr-2 w-4"></i><span class="text-label">Email: <strong>' + escapeHtml(state.email) + '</strong></span></div>' +
                    '<div class="flex items-center"><i class="fas fa-check text-green-500 mr-2 w-4"></i><span class="text-label">DNS Provider: <strong>' + escapeHtml(PROVIDERS[state.provider] ? PROVIDERS[state.provider].label : state.provider) + '</strong></span></div>' +
                    '<div class="flex items-center"><i class="fas fa-check text-green-500 mr-2 w-4"></i><span class="text-label">Auto-renewal: <strong>Enabled</strong></span></div>' +
                '</div>' +
            '</div>';

        var footer = document.getElementById('wizardFooter');
        footer.innerHTML =
            '<a href="/settings" class="text-sm text-muted hover:text-gray-700 dark:hover:text-gray-200">Advanced Settings</a>' +
            '<button type="button" id="wizFinish" class="px-6 py-2.5 bg-primary hover:bg-secondary text-white font-medium rounded-lg text-sm transition"><i class="fas fa-certificate mr-1"></i> Create Your First Certificate</button>';

        document.getElementById('wizFinish').addEventListener('click', function() {
            closeWizard();
            // Focus the domain input on the main page
            setTimeout(function() {
                var domainInput = document.getElementById('domain');
                if (domainInput) {
                    domainInput.focus();
                    domainInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }, 300);
        });
    }

    function closeWizard() {
        var el = document.getElementById('setupWizard');
        if (el) el.remove();
    }

    // Auto-check on page load (only on dashboard)
    if (window.location.pathname === '/') {
        setTimeout(checkSetup, 500);
    }
})();
