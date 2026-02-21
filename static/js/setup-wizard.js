/**
 * First-Time Setup Wizard — static/js/setup-wizard.js
 * Shows a guided 3-step wizard when setup_completed is false.
 */
(function() {
    'use strict';

    var escapeHtml = CertMate.escapeHtml;

    // DNS provider definitions with required fields
    var PROVIDERS = {
        cloudflare:    { label: 'Cloudflare', icon: 'fa-cloud', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        route53:       { label: 'AWS Route 53', icon: 'fa-aws', fields: [{ key: 'access_key_id', label: 'Access Key ID', type: 'text' }, { key: 'secret_access_key', label: 'Secret Access Key', type: 'password' }, { key: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1' }] },
        digitalocean:  { label: 'DigitalOcean', icon: 'fa-digital-ocean', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        hetzner:       { label: 'Hetzner', icon: 'fa-server', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        gandi:         { label: 'Gandi', icon: 'fa-globe', fields: [{ key: 'api_token', label: 'API Token', type: 'password' }] },
        linode:        { label: 'Linode/Akamai', icon: 'fa-cloud', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }] },
        porkbun:       { label: 'Porkbun', icon: 'fa-globe', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }, { key: 'secret_api_key', label: 'Secret API Key', type: 'password' }] },
        godaddy:       { label: 'GoDaddy', icon: 'fa-globe', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }, { key: 'api_secret', label: 'API Secret', type: 'password' }] },
        namecheap:     { label: 'Namecheap', icon: 'fa-globe', fields: [{ key: 'username', label: 'Username', type: 'text' }, { key: 'api_key', label: 'API Key', type: 'password' }] },
        vultr:         { label: 'Vultr', icon: 'fa-cloud', fields: [{ key: 'api_key', label: 'API Key', type: 'password' }] },
        ovh:           { label: 'OVH', icon: 'fa-globe', fields: [{ key: 'endpoint', label: 'Endpoint', type: 'text', placeholder: 'ovh-eu' }, { key: 'application_key', label: 'Application Key', type: 'text' }, { key: 'application_secret', label: 'Application Secret', type: 'password' }, { key: 'consumer_key', label: 'Consumer Key', type: 'password' }] },
        azure:         { label: 'Azure DNS', icon: 'fa-microsoft', fields: [{ key: 'subscription_id', label: 'Subscription ID', type: 'text' }, { key: 'resource_group', label: 'Resource Group', type: 'text' }, { key: 'tenant_id', label: 'Tenant ID', type: 'text' }, { key: 'client_id', label: 'Client ID', type: 'text' }, { key: 'client_secret', label: 'Client Secret', type: 'password' }] },
        google:        { label: 'Google Cloud DNS', icon: 'fa-google', fields: [{ key: 'project_id', label: 'Project ID', type: 'text' }, { key: 'service_account_key', label: 'Service Account Key (JSON)', type: 'textarea' }] }
    };

    var state = { step: 1, email: '', provider: '', credentials: {} };

    function checkSetup() {
        fetch('/api/web/settings', { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data && data.setup_completed === false) {
                    showWizard();
                }
            })
            .catch(function() {});
    }

    function showWizard() {
        var overlay = document.createElement('div');
        overlay.id = 'setupWizard';
        overlay.className = 'fixed inset-0 z-[110] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4';
        overlay.innerHTML =
            '<div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">' +
                '<div class="px-6 py-5 border-b border-gray-200 dark:border-gray-700">' +
                    '<div class="flex items-center justify-between">' +
                        '<div>' +
                            '<h2 class="text-xl font-bold text-gray-900 dark:text-white">Welcome to CertMate</h2>' +
                            '<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Let\'s get you set up in a few steps</p>' +
                        '</div>' +
                        '<div class="flex items-center gap-1.5" id="wizardSteps"></div>' +
                    '</div>' +
                '</div>' +
                '<div id="wizardBody" class="px-6 py-6"></div>' +
                '<div id="wizardFooter" class="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between"></div>' +
            '</div>';
        document.body.appendChild(overlay);
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
                    : 'w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-600 text-gray-500 dark:text-gray-400 flex items-center justify-center text-sm';
            html += '<div class="' + cls + '">' + (i < state.step ? '<i class="fas fa-check text-xs"></i>' : i) + '</div>';
            if (i < 3) html += '<div class="w-6 h-0.5 ' + (i < state.step ? 'bg-green-500' : 'bg-gray-200 dark:bg-gray-600') + '"></div>';
        }
        el.innerHTML = html;
    }

    function renderStep1() {
        var body = document.getElementById('wizardBody');
        body.innerHTML =
            '<div class="text-center mb-6">' +
                '<div class="w-16 h-16 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-envelope text-blue-600 dark:text-blue-400 text-2xl"></i>' +
                '</div>' +
                '<h3 class="text-lg font-semibold text-gray-900 dark:text-white">Contact Email</h3>' +
                '<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Required by certificate authorities for important notifications</p>' +
            '</div>' +
            '<div>' +
                '<label for="wizEmail" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Email Address</label>' +
                '<input type="email" id="wizEmail" value="' + escapeHtml(state.email) + '" placeholder="admin@example.com" ' +
                       'class="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary text-sm" required>' +
                '<p class="mt-2 text-xs text-gray-400"><i class="fas fa-info-circle mr-1"></i>Used by Let\'s Encrypt for expiry warnings and account recovery</p>' +
            '</div>';

        var footer = document.getElementById('wizardFooter');
        footer.innerHTML =
            '<button type="button" id="wizSkip" class="text-sm text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">Skip wizard</button>' +
            '<button type="button" id="wizNext1" class="px-6 py-2.5 bg-primary hover:bg-secondary text-white font-medium rounded-lg text-sm transition">Next <i class="fas fa-arrow-right ml-1"></i></button>';

        document.getElementById('wizNext1').addEventListener('click', function() {
            var email = document.getElementById('wizEmail').value.trim();
            if (!email || email.indexOf('@') === -1) {
                document.getElementById('wizEmail').classList.add('border-red-500');
                return;
            }
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
                '<div class="w-16 h-16 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-server text-green-600 dark:text-green-400 text-2xl"></i>' +
                '</div>' +
                '<h3 class="text-lg font-semibold text-gray-900 dark:text-white">DNS Provider</h3>' +
                '<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Select where your domains are managed</p>' +
            '</div>' +
            '<div class="grid grid-cols-2 sm:grid-cols-3 gap-2" id="providerGrid">';

        Object.keys(PROVIDERS).forEach(function(key) {
            var p = PROVIDERS[key];
            var selected = state.provider === key;
            html += '<button type="button" data-provider="' + key + '" class="wiz-provider flex flex-col items-center p-3 rounded-lg border-2 transition text-sm ' +
                (selected ? 'border-primary bg-primary/5 text-primary' : 'border-gray-200 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:border-gray-400') + '">' +
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
            '<button type="button" id="wizBack2" class="px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"><i class="fas fa-arrow-left mr-1"></i> Back</button>' +
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
        var html = '<div class="border-t border-gray-200 dark:border-gray-700 pt-4">' +
            '<h4 class="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3"><i class="fas fa-key mr-1.5 text-yellow-500"></i>' + escapeHtml(pDef.label) + ' Credentials</h4>';

        pDef.fields.forEach(function(f) {
            var savedVal = state.credentials[f.key] || '';
            if (f.type === 'textarea') {
                html += '<div><label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">' + escapeHtml(f.label) + '</label>' +
                    '<textarea id="wiz_' + f.key + '" rows="3" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary focus:border-primary" placeholder="' + escapeHtml(f.placeholder || '') + '">' + escapeHtml(savedVal) + '</textarea></div>';
            } else {
                html += '<div><label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">' + escapeHtml(f.label) + '</label>' +
                    '<input type="' + f.type + '" id="wiz_' + f.key + '" value="' + escapeHtml(savedVal) + '" placeholder="' + escapeHtml(f.placeholder || '') + '" ' +
                    'class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary focus:border-primary"></div>';
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
            auto_renew: true
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
                '<div class="w-20 h-20 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">' +
                    '<i class="fas fa-check-circle text-green-500 text-4xl"></i>' +
                '</div>' +
                '<h3 class="text-xl font-bold text-gray-900 dark:text-white mb-2">You\'re All Set!</h3>' +
                '<p class="text-sm text-gray-500 dark:text-gray-400 mb-4">CertMate is configured and ready to manage your certificates.</p>' +
                '<div class="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-left text-sm space-y-2">' +
                    '<div class="flex items-center"><i class="fas fa-check text-green-500 mr-2 w-4"></i><span class="text-gray-700 dark:text-gray-300">Email: <strong>' + escapeHtml(state.email) + '</strong></span></div>' +
                    '<div class="flex items-center"><i class="fas fa-check text-green-500 mr-2 w-4"></i><span class="text-gray-700 dark:text-gray-300">DNS Provider: <strong>' + escapeHtml(PROVIDERS[state.provider] ? PROVIDERS[state.provider].label : state.provider) + '</strong></span></div>' +
                    '<div class="flex items-center"><i class="fas fa-check text-green-500 mr-2 w-4"></i><span class="text-gray-700 dark:text-gray-300">Auto-renewal: <strong>Enabled</strong></span></div>' +
                '</div>' +
            '</div>';

        var footer = document.getElementById('wizardFooter');
        footer.innerHTML =
            '<a href="/settings" class="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">Advanced Settings</a>' +
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
