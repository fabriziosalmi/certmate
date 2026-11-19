(function () {
    'use strict';

    // Alpine.js components extracted to:
    //   - settings-notifications.js (notificationSettings)
    //   - settings-deploy.js        (deployManager)
    //   - settings-apikeys.js       (apiKeyManager)
    // They reach back into core via window.CmSettings (defined at end of IIFE).

    // API Configuration - session cookies are sent automatically
    var API_HEADERS = {
        'Content-Type': 'application/json'
    };

    // Global variables - properly initialized
    var currentSettings = {};
    var configuredCAProviders = [];
    // The server's last check of each CA account, by provider then account id.
    var caAccountChecks = {};
    var editingCAProvider = '';
    var editingCAAccount = '';
    var dnsProviders = {};
    var isLoading = false;

    var escapeHtml = CertMate.escapeHtml;

    // DOM Elements - initialized in DOMContentLoaded
    var form, saveBtn, statusMessage;

    // =============================================
    // Debug console functions
    // =============================================

    // Renamed from toggleDebugConsole / clearDebugConsole to avoid a
    // naming collision with the identically-named helpers in
    // dashboard.js — both files export to `window.*` and the two
    // pages don't load together so there's no runtime breakage today,
    // but a future bundle / a future page that includes both scripts
    // would silently overwrite the binding (4.1 fix).
    function toggleSettingsDebugConsole() {
        var consoleDiv = document.getElementById('settingsDebugConsole');
        if (consoleDiv.classList.contains('hidden')) {
            consoleDiv.classList.remove('hidden');
        } else {
            consoleDiv.classList.add('hidden');
        }
    }

    function clearSettingsDebugConsole() {
        document.getElementById('settingsDebugOutput').innerHTML = '<div class="text-gray-500">Debug console cleared. All settings actions will be logged here...</div>';
    }

    function toggleRoute53LegacyAuthMode() {
        var mode = document.getElementById('route53_auth_mode').value;
        document.querySelectorAll('.route53-legacy-key').forEach(function (field) {
            field.classList.toggle('hidden', mode === 'iam_role');
        });
    }

    function toggleRoute53ModalAuthMode(container) {
        var mode = container.querySelector('[name="auth_mode"]');
        if (!mode) return;
        function update() {
            ['access_key_id', 'secret_access_key'].forEach(function (name) {
                var field = container.querySelector('[name="' + name + '"]');
                field.required = mode.value !== 'iam_role';
                field.parentElement.classList.toggle('hidden', mode.value === 'iam_role');
            });
        }
        mode.addEventListener('change', update);
        update();
    }

    // =============================================
    // API Token helper functions
    // =============================================

    // The field, the eye icon and the button's name and pressed state say the same thing.
    function setTokenVisible(shown) {
        var tokenField = document.getElementById('api_bearer_token');
        var toggleIcon = document.getElementById('tokenToggleIcon');
        var toggleBtn = document.getElementById('tokenToggleBtn');
        tokenField.type = shown ? 'text' : 'password';
        toggleIcon.classList.toggle('fa-eye', !shown);
        toggleIcon.classList.toggle('fa-eye-slash', shown);
        if (toggleBtn) {
            toggleBtn.setAttribute('aria-pressed', shown ? 'true' : 'false');
            toggleBtn.setAttribute('aria-label', shown ? 'Hide token' : 'Show token');
        }
    }

    function toggleTokenVisibility() {
        setTokenVisible(document.getElementById('api_bearer_token').type === 'password');
    }

    // =============================================
    // Debug logging
    // =============================================

    function addDebugLog(message, type) {
        type = type || 'info';
        var output = document.getElementById('settingsDebugOutput');
        var color = type === 'error' ? 'text-red-400' : type === 'warn' ? 'text-yellow-400' : 'text-green-400';
        var time = CertMate.formatTime(new Date());
        var entry = document.createElement('div');
        entry.className = color;
        entry.textContent = '[' + time + '] ' + type.toUpperCase() + ': ' + message;
        output.appendChild(entry);
        output.scrollTop = output.scrollHeight;
    }

    // =============================================
    // Message display function
    // =============================================

    function showMessage(message, type, options) {
        type = type || 'info';
        addDebugLog(message, type);
        // options.errorContext (when supplied) triggers the "Report this
        // issue" button in the resulting toast — see report-issue.js.
        CertMate.toast(message, type, undefined, options);
    }

    // =============================================
    // DNS provider configuration functions
    // =============================================

    // Per-provider propagation wait (#974): the whole map as loaded, edited
    // one provider at a time through #dns_propagation_current.
    var propagationSeconds = {};

    function renderPropagationField(provider) {
        var section = document.getElementById('dns-propagation-section');
        var field = document.getElementById('dns_propagation_current');
        var label = document.getElementById('dns-propagation-provider');
        if (!section || !field) return;
        if (!provider || !(provider in propagationSeconds)) {
            section.classList.add('hidden');
            return;
        }
        field.dataset.provider = provider;
        field.value = propagationSeconds[provider];
        if (label) {
            var radio = document.querySelector('input[name="dns_provider"][value="' + provider + '"]');
            var name = radio && radio.parentElement ? radio.parentElement.querySelector('.text-xs.font-medium') : null;
            label.textContent = name ? name.textContent.trim() : provider;
        }
        section.classList.remove('hidden');
    }

    // reveal: scroll the section into view, for a provider the user has just
    // picked (UX audit P18). On a phone the tiles are two to a row, and the
    // section opened two screens below the tile with nothing moving.
    function showDNSConfig(provider, reveal) {
        renderPropagationField(provider);
        // Hide all DNS config sections
        document.querySelectorAll('.dns-config').forEach(function (config) {
            config.classList.add('hidden');
        });

        // Show the selected provider's config
        var configSection = document.getElementById(provider + '-config');
        if (configSection) {
            configSection.classList.remove('hidden');
            if (reveal) {
                var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
                configSection.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
            }
            addDebugLog('Showing DNS config for ' + provider, 'info');
        } else {
            addDebugLog('No config section found for ' + provider, 'warn');
        }
    }

    // =============================================
    // Save main settings function
    // =============================================

    function saveSettings() {
        if (isLoading) return;
        isLoading = true;

        if (saveBtn) {
            saveBtn.disabled = true;
            saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';
        }

        addDebugLog('Saving main settings...', 'info');

        // Set when the selected CA has no email but the save is allowed
        // through anyway (#491); surfaced after the save succeeds so it does
        // not read as a failure.
        var missingCaEmailWarning = null;

        try {
            var formData = new FormData(form);
            var caProviders = currentSettings.ca_providers || {};
            var defaultCA = formData.get('default_ca') || 'letsencrypt';
            var defaultConfig = caProviders[defaultCA] || {};
            var defaultAccounts = defaultConfig.accounts || {};
            var defaultAccountId = (currentSettings.default_ca_accounts || {})[defaultCA] ||
                (defaultAccounts.default ? 'default' : Object.keys(defaultAccounts)[0]);
            var accountEmail = (defaultAccounts[defaultAccountId] || defaultConfig).email || '';

            // Get email from the selected CA provider
            var email = '';
            if (defaultCA === 'letsencrypt' || defaultCA === 'letsencrypt_staging') {
                email = accountEmail || currentSettings.email || '';
            } else if (['zerossl', 'google', 'actalis', 'sslcom', 'digicert', 'sectigo', 'private_ca'].indexOf(defaultCA) !== -1) {
                email = accountEmail;
            }

            var domainsRaw = formData.get('domains');
            var domainsValue = domainsRaw ? domainsRaw.split('\n').map(function (d) { return d.trim(); }).filter(function (d) { return d; }) : undefined;

            // Default certificate-key shape selectors. RSA always carries
            // a key_size, ECDSA always a curve — the inactive branch is
            // omitted from the payload so save_settings doesn't trip the
            // mutual-exclusion validator.
            var defaultKeyType = formData.get('default_key_type') || 'rsa';
            var defaultKeySize = parseInt(formData.get('default_key_size'), 10);
            var defaultEllipticCurve = formData.get('default_elliptic_curve') || 'secp256r1';
            // Client certificates' key (#1421): one list, "rsa:3072" or "ecdsa:secp384r1".
            // Both fields are always sent; save_settings checks only the active one.
            var clientShape = (formData.get('client_cert_key_shape') || 'rsa:2048').split(':');

            var settings = {
                email: email.trim(),
                domains: domainsValue,
                auto_renew: formData.get('auto_renew') === 'on',
                renewal_threshold_days: parseInt(formData.get('renewal_threshold_days')) || 30,
                dns_provider: formData.get('dns_provider'),
                challenge_type: formData.get('challenge_type') || 'dns-01',
                cache_ttl: parseInt(formData.get('cache_ttl')) || 300,
                certificate_storage: collectStorageBackendSettings(),
                default_ca: defaultCA,
                default_key_type: defaultKeyType,
                default_key_size: defaultKeyType === 'rsa' ? (defaultKeySize || 2048) : 2048,
                default_elliptic_curve: defaultEllipticCurve,
                client_cert_key_type: clientShape[0],
                client_cert_key_size: clientShape[0] === 'rsa' ? parseInt(clientShape[1], 10) : 2048,
                client_cert_elliptic_curve: clientShape[0] === 'ecdsa' ? clientShape[1] : 'secp256r1'
            };

            // The whole propagation map (#974): a provider left out would
            // return to its default on the server.
            if (Object.keys(propagationSeconds).length) {
                settings.dns_propagation_seconds = Object.assign({}, propagationSeconds);
            }

            // PFX export password (#230). Secret field: only send when the
            // user typed a value — a blank field means "keep existing", which
            // the backend honours for secret-named keys. Sending the password
            // empty would be treated the same way, but omitting it keeps the
            // payload clean.
            var pfxPasswordField = document.getElementById('pfx_password');
            var pfxClear = document.getElementById('pfx_password_clear');
            if (pfxClear && pfxClear.checked) {
                // null, not '': a blank secret means "keep" on the server, so
                // the password could never be removed (UX audit, 2026-11-17).
                settings.pfx_password = null;
            } else if (pfxPasswordField && pfxPasswordField.value) {
                settings.pfx_password = pfxPasswordField.value;
            }

            // The email belongs to the selected CA provider. It is needed to
            // register an ACME account when a certificate is issued — NOT to
            // save settings: validate_settings_post never looks at it, so this
            // was a client-side block on a value the backend does not require.
            //
            // Blocking here made every unrelated change unsaveable — a DNS
            // provider, a storage backend — for
            // anyone whose selected CA had no email yet, including right after
            // switching the default CA. See issue #491.
            //
            // It is still enforced to finish initial setup. After
            // that it degrades to a warning shown once the save succeeds:
            // create_certificate still raises "Domain and email are required"
            // if it is genuinely missing at issuance time.
            if (!settings.email) {
                var caDisplayName = defaultCA === 'letsencrypt' ? "Let's Encrypt" :
                    defaultCA === 'letsencrypt_staging' ? "Let's Encrypt (Staging)" :
                    defaultCA === 'zerossl' ? 'ZeroSSL' :
                    defaultCA === 'google' ? 'Google Trust Services' :
                    defaultCA === 'actalis' ? 'Actalis' :
                    defaultCA === 'sslcom' ? 'SSL.com' :
                    defaultCA === 'digicert' ? 'DigiCert' :
                    defaultCA === 'sectigo' ? 'Sectigo' :
                    defaultCA === 'private_ca' ? 'Private CA' : defaultCA;
                if (!currentSettings.setup_completed) {
                    throw new Error('Email address is required in the ' + caDisplayName + ' configuration section');
                }
                missingCaEmailWarning = caDisplayName + ' has no email address, so issuing with it will fail until you add one';
            }

            if (settings.challenge_type !== 'http-01' && !settings.dns_provider) {
                throw new Error('DNS provider must be selected');
            }

            // The API Bearer Token is never part of this save (UX audit P04).
            // The endpoint refuses api_bearer_token: the token comes from
            // API_BEARER_TOKEN (or API_BEARER_TOKEN_FILE) at startup. Sent,
            // any value in the field answered 400 "Forbidden fields in
            // payload", and the field kept it, so every later Save failed too.
            // Left out, the stored token is kept as it is.

            // Add legacy DNS provider configurations from form fields
            var legacyConfig = {};

            // Get legacy fields for the selected provider
            var provider = settings.dns_provider;
            var legacyFields = getLegacyFieldsForProvider(provider);

            var legacyContainer = document.getElementById(provider + '-legacy-config');
            if (legacyContainer && legacyContainer.style.display === 'none') {
                legacyFields = []; // A provider with accounts is edited in its account modal.
            }
            legacyFields.forEach(function (fieldName) {
                var value = formData.get(fieldName);
                if ((value && value.trim()) ||
                        (provider === 'route53' && fieldName === 'route53_assume_role_arn')) {
                    var configKey = fieldName.replace(provider + '_', '');
                    legacyConfig[configKey] = (value || '').trim();
                }
            });

            // The single-account fields are the provider's "default" account.
            // Issuance reads accounts only: written flat beside them, a token
            // was saved, reported as saved, and never used (audit P05).
            // Route53's mode, region and role ARN are filled in by the form
            // itself, so on their own they would make an account with no
            // credential. The IAM-role mode needs no keys and counts.
            var accountSettings = ['auth_mode', 'region', 'assume_role_arn'];
            var holdsCredential = legacyConfig.auth_mode === 'iam_role' ||
                Object.keys(legacyConfig).some(function (key) {
                    return legacyConfig[key] && accountSettings.indexOf(key) === -1;
                });
            if (holdsCredential) {
                if (!settings.dns_providers) settings.dns_providers = {};
                settings.dns_providers[provider] = {accounts: {default: legacyConfig}};
            }

            addDebugLog('Saving settings: ' + Object.keys(settings).join(', '), 'info');

            fetch('/api/web/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            })
                .then(function (response) {
                    if (!response.ok) {
                        return response.text().then(function (errorData) {
                            // Parse JSON body when possible so the bug-report
                            // errorContext can carry the `code`/`hint` the
                            // backend returned.
                            var parsed = null;
                            try { parsed = errorData ? JSON.parse(errorData) : null; } catch (e) { /* not JSON */ }
                            var err = new Error('HTTP ' + response.status + ': ' + (parsed && parsed.error ? parsed.error : errorData));
                            err.responseStatus = response.status;
                            err.responseBody = parsed;
                            throw err;
                        });
                    }
                    return response.json();
                })
                .then(function (result) {
                    addDebugLog('Settings saved successfully', 'info');
                    showMessage('Settings saved successfully', 'success');
                    if (missingCaEmailWarning) {
                        showMessage(missingCaEmailWarning, 'warning');
                    }

                    // Reload settings to refresh the UI
                    return loadSettings();
                })
                .catch(function (error) {
                    addDebugLog('Error saving settings: ' + error.message, 'error');
                    showMessage('Error saving settings: ' + error.message, 'error', {
                        errorContext: {
                            endpoint: 'POST /api/web/settings',
                            status: error.responseStatus || 0,
                            code: error.responseBody && error.responseBody.code,
                            message: (error.responseBody && error.responseBody.error) || error.message,
                            hint: error.responseBody && error.responseBody.hint
                        }
                    });
                })
                .then(function () {
                    // finally block equivalent
                    isLoading = false;
                    if (saveBtn) {
                        saveBtn.disabled = false;
                        saveBtn.innerHTML = '<i class="fas fa-save mr-2"></i>Save DNS, General and Storage';
                    }
                });
        } catch (error) {
            addDebugLog('Error saving settings: ' + error.message, 'error');
            showMessage('Error saving settings: ' + error.message, 'error');
            isLoading = false;
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.innerHTML = '<i class="fas fa-save mr-2"></i>Save DNS, General and Storage';
            }
        }
    }

    // =============================================
    // Legacy field mappings
    // =============================================

    function getLegacyFieldsForProvider(provider) {
        var fieldMappings = {
            'cloudflare': ['cloudflare_api_token'],
            'route53': ['route53_access_key_id', 'route53_secret_access_key', 'route53_region',
                        'route53_auth_mode', 'route53_assume_role_arn'],
            'azure': ['azure_subscription_id', 'azure_resource_group', 'azure_tenant_id', 'azure_client_id', 'azure_client_secret'],
            'google': ['google_project_id', 'google_service_account_key'],
            'powerdns': ['powerdns_api_url', 'powerdns_api_key'],
            'digitalocean': ['digitalocean_api_token'],
            'linode': ['linode_api_key'],
            'edgedns': ['edgedns_client_token', 'edgedns_client_secret', 'edgedns_access_token', 'edgedns_host'],
            'gandi': ['gandi_api_token'],
            'ovh': ['ovh_endpoint', 'ovh_application_key', 'ovh_application_secret', 'ovh_consumer_key'],
            'namecheap': ['namecheap_username', 'namecheap_api_key'],
            'rfc2136': ['rfc2136_nameserver', 'rfc2136_tsig_key', 'rfc2136_tsig_secret', 'rfc2136_tsig_algorithm'],
            'hetzner': ['hetzner_api_token'],
            'porkbun': ['porkbun_api_key', 'porkbun_secret_key'],
            'godaddy': ['godaddy_api_key', 'godaddy_secret'],
            'he-ddns': ['he_ddns_username', 'he_ddns_password'],
            'dynudns': ['dynudns_token'],
            'duckdns': ['duckdns_api_token'],
            'dnsmadeeasy': ['dnsmadeeasy_api_key', 'dnsmadeeasy_secret_key'],
            'nsone': ['nsone_api_key'],
            'arvancloud': ['arvancloud_api_key'],
            'infomaniak': ['infomaniak_api_token'],
            'acme-dns': ['acme-dns_api_url', 'acme-dns_username', 'acme-dns_password', 'acme-dns_subdomain'],
            'hetzner-cloud': ['hetzner-cloud_api_token'],
            'desec': ['desec_api_token'],
            'scaleway': ['scaleway_application_token'],
            'solidserver': ['solidserver_host', 'solidserver_username', 'solidserver_password', 'solidserver_dns_name', 'solidserver_dnsview_name', 'solidserver_propagation_seconds'],
            'custom-script': ['custom-script_auth_hook', 'custom-script_cleanup_hook']
        };

        return fieldMappings[provider] || [];
    }

    // =============================================
    // Cache management functions
    // =============================================

    function refreshCacheStats() {
        addDebugLog('Refreshing cache stats...', 'info');

        return fetch('/api/web/cache/stats')
            .then(function (response) {
                if (response.ok) {
                    return response.json().then(function (stats) {
                        var entriesEl = document.getElementById('cache-entries');
                        var ttlEl = document.getElementById('cache-current-ttl');

                        if (entriesEl) entriesEl.textContent = stats.entries || 0;
                        if (ttlEl) ttlEl.textContent = (stats.current_ttl || 300) + 's';

                        addDebugLog('Cache stats refreshed: ' + stats.entries + ' entries, ' + stats.current_ttl + 's TTL', 'info');
                    });
                } else {
                    addDebugLog('Failed to refresh cache stats', 'warn');
                }
            })
            .catch(function (error) {
                addDebugLog('Error refreshing cache stats: ' + error.message, 'error');
            });
    }

    function clearDeploymentCache() {
        // Mirror the confirm pattern used by the dashboard's invalidateAllCache.
        // The clear itself is non-destructive (next dashboard load re-probes
        // each domain) but a misclick still wastes a round of probes and
        // momentarily flickers every cert's deployment badge — annoying enough
        // to warrant the same two-step interaction.
        return CertMate.confirm(
            'Clear all server-side deployment status cache? The next dashboard render will re-probe every cert.',
            'Clear Cache',
            { danger: false }
        ).then(function (confirmed) {
            if (!confirmed) return Promise.resolve();
            addDebugLog('Clearing deployment cache...', 'info');

            return fetch('/api/web/cache/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
                .then(function (response) {
                    if (response.ok) {
                        return response.json().then(function (result) {
                            addDebugLog('Cache cleared successfully', 'info');
                            showMessage('Cache cleared successfully', 'success');
                            return refreshCacheStats();
                        });
                    } else {
                        addDebugLog('Failed to clear cache', 'warn');
                        showMessage('Failed to clear cache', 'error');
                    }
                })
                .catch(function (error) {
                    addDebugLog('Error clearing cache: ' + error.message, 'error');
                    showMessage('Error clearing cache', 'error');
                });
        });
    }

    // =============================================
    // Load settings
    // =============================================

    function loadSettings(suppressErrorMessages) {
        suppressErrorMessages = suppressErrorMessages || false;
        addDebugLog('Loading settings from backend...', 'info');

        return fetch('/api/web/settings', {
            method: 'GET',
            headers: API_HEADERS
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(function (settings) {
                addDebugLog('Settings loaded: ' + Object.keys(settings).join(', '), 'info');

                currentSettings = settings;
                populateForm(settings);

                // Load DNS provider configurations and status
                return loadDNSProviders();
            })
            .then(function () {
                addDebugLog('Settings loaded and form populated successfully', 'info');
            })
            .catch(function (error) {
                addDebugLog('Failed to load settings: ' + error.message, 'error');
                console.error('Error loading settings:', error);
                if (!suppressErrorMessages) {
                    showMessage('Failed to load settings: ' + error.message, 'error');
                }
            });
    }

    // =============================================
    // Load DNS provider configurations
    // =============================================

    function loadDNSProviders() {
        try {
            addDebugLog('Loading DNS provider configurations...', 'info');
            dnsProviders = {};

            // Load provider configurations from current settings
            if (currentSettings && currentSettings.dns_providers) {
                Object.keys(currentSettings.dns_providers).forEach(function (provider) {
                    var config = currentSettings.dns_providers[provider];
                    try {
                        dnsProviders[provider] = {
                            configured: false,
                            accounts: []
                        };

                        if (config && typeof config === 'object') {
                            // Check for canonical multi-account format: { accounts: { id: {...}, ... } }
                            if (config.accounts && typeof config.accounts === 'object') {
                                Object.keys(config.accounts).forEach(function (accountId) {
                                    var accountConfig = config.accounts[accountId];
                                    if (typeof accountConfig === 'object') {
                                        dnsProviders[provider].accounts.push(Object.assign({}, accountConfig, {
                                            id: accountId,
                                            name: accountConfig.name || accountId,
                                            description: accountConfig.description || ''
                                        }));
                                    }
                                });
                                dnsProviders[provider].configured = dnsProviders[provider].accounts.length > 0;
                                // Check if this is flat multi-account format (values with 'name')
                            } else if (Object.values(config).some(function (val) { return typeof val === 'object' && 'name' in val; })) {
                                // Multi-account format
                                Object.keys(config).forEach(function (accountId) {
                                    var accountConfig = config[accountId];
                                    if (typeof accountConfig === 'object' && accountConfig.name) {
                                        dnsProviders[provider].accounts.push(Object.assign({}, accountConfig, {
                                            id: accountId,
                                            name: accountConfig.name,
                                            description: accountConfig.description || ''
                                        }));
                                    }
                                });
                                dnsProviders[provider].configured = dnsProviders[provider].accounts.length > 0;
                            } else {
                                // Legacy single-account format
                                var hasCredentials = Object.values(config).some(function (val) { return val && val.trim && val.trim().length > 0; });
                                dnsProviders[provider].configured = hasCredentials;

                                if (hasCredentials) {
                                    dnsProviders[provider].accounts.push(Object.assign({}, config, {
                                        id: 'default',
                                        name: 'Default Account',
                                        description: 'Legacy configuration'
                                    }));
                                }
                            }
                        }

                        addDebugLog(provider + ': ' + (dnsProviders[provider].configured ? 'configured' : 'not configured') + ' (' + dnsProviders[provider].accounts.length + ' accounts)', 'info');

                    } catch (error) {
                        addDebugLog('Error processing ' + provider + ': ' + error.message, 'warn');
                    }
                });
            }

        } catch (error) {
            addDebugLog('Failed to load DNS providers: ' + error.message, 'error');
            console.error('Error loading DNS providers:', error);
        }

        // Whether an account can issue is the server's call (#1469): it checks
        // the provider's own required fields, as issuance does. Counting the
        // accounts here called every provider of a fresh instance "Configured":
        // the first-run settings carry an empty "default" account for sixteen
        // of them.
        return fetch('/api/dns/accounts', { headers: API_HEADERS })
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(applyCredentialVerdict)
            .catch(function (error) {
                addDebugLog('Could not ask which DNS accounts have credentials: ' + error.message, 'error');
                Object.keys(dnsProviders).forEach(function (provider) {
                    dnsProviders[provider].configured = null;
                    dnsProviders[provider].accounts.forEach(function (account) {
                        account.lastCheck = { outcome: 'unknown' };
                    });
                });
            })
            .then(function () {
                updateProviderStatusIndicators();
                updateAccountLists();
                addDebugLog('DNS provider configurations loaded', 'info');
            });
    }

    // Each account gets `hasCredentials` from the server's list, and a provider
    // is configured when one of its accounts has them.
    function applyCredentialVerdict(list) {
        var verdict = {};
        var checks = {};
        (Array.isArray(list) ? list : []).forEach(function (account) {
            if (!account || !account.provider) return;
            (verdict[account.provider] = verdict[account.provider] || {})[account.account_id] = account.configured === true;
            (checks[account.provider] = checks[account.provider] || {})[account.account_id] = account.last_check || null;
        });
        Object.keys(dnsProviders).forEach(function (provider) {
            var known = verdict[provider] || {};
            dnsProviders[provider].accounts.forEach(function (account) {
                account.hasCredentials = known[account.id] === true;
                // The server's record of the last check (P39): only a check
                // it ran can say "passed".
                account.lastCheck = (checks[provider] || {})[account.id] || null;
            });
            dnsProviders[provider].configured = dnsProviders[provider].accounts.some(function (account) {
                return account.hasCredentials;
            });
        });
    }

    // =============================================
    // Update DNS provider status indicators in the UI
    // =============================================

    function updateProviderStatusIndicators() {
        var providers = [
            'cloudflare', 'route53', 'azure', 'google', 'powerdns',
            'digitalocean', 'linode', 'edgedns', 'gandi', 'ovh', 'namecheap',
            'vultr', 'solidserver', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner',
            'porkbun', 'godaddy', 'he-ddns', 'dynudns', 'duckdns',
            'arvancloud', 'infomaniak', 'acme-dns', 'hetzner-cloud',
            'desec', 'scaleway',
            'custom-script'
        ];

        providers.forEach(function (provider) {
            var statusEl = document.getElementById(provider + '-status');
            var accountsEl = document.getElementById(provider + '-accounts');
            var countEl = document.getElementById(provider + '-account-count');

            if (statusEl) {
                var providerData = dnsProviders[provider];
                if (providerData && providerData.configured) {
                    statusEl.textContent = 'Configured';
                    // Not green (P39): "Configured" says the credentials are
                    // there. Even a passed check proves only that they read
                    // zones, and the tile has no room to say so; the account
                    // card says it beside its green.
                    statusEl.className = 'text-xs text-label mt-1 whitespace-nowrap';

                    // The accounts that can issue, not every account on file.
                    if (accountsEl && countEl) {
                        var usable = providerData.accounts.filter(function (account) {
                            return account.hasCredentials;
                        }).length;
                        countEl.textContent = usable;
                        // The word after the number is in the template; it read
                        // "1 accounts" (UX audit, 2026-11-17).
                        var noun = countEl.nextSibling;
                        if (noun && noun.nodeType === Node.TEXT_NODE) {
                            noun.textContent = usable === 1 ? ' account' : ' accounts';
                        }
                        accountsEl.classList.remove('invisible');
                    }
                } else if (providerData && providerData.configured === null) {
                    // The server could not be asked: say so rather than guess.
                    statusEl.textContent = 'Status unknown';
                    statusEl.className = 'text-xs text-muted mt-1 whitespace-nowrap';
                    if (accountsEl) {
                        accountsEl.classList.add('invisible');
                    }
                } else {
                    statusEl.textContent = 'Not configured';
                    statusEl.className = 'text-xs text-muted mt-1 whitespace-nowrap';

                    // `invisible`, not `hidden`: the line keeps its height (settings_dns.html).
                    if (accountsEl) {
                        accountsEl.classList.add('invisible');
                    }
                }
            }
        });
    }

    // =============================================
    // The last check of a CA or DNS account (P39)
    // =============================================

    // The server keeps the last check of each account; only a check it ran
    // records "passed". An account is drawn green only from that record.
    function lastCheckOutcome(check) {
        return (check && check.outcome) || 'never';
    }

    function lastCheckText(check) {
        var outcome = lastCheckOutcome(check);
        var when = check && check.at ? ' ' + CertMate.formatDateTime(check.at) : '';
        // A pass says what it proved, on the card (review F6).
        if (outcome === 'passed') return 'Last check passed' + when + (check.reason ? ': ' + check.reason : '');
        if (outcome === 'failed') return 'Last check failed' + when + (check.reason ? ': ' + check.reason : '');
        // A CA's directory answered: that says nothing about the account (review F2).
        if (outcome === 'reachable') return 'Directory answered' + when + (check.reason ? '. ' + check.reason + '.' : '.');
        if (outcome === 'not_checkable') return 'Not checkable yet';
        // The record could not be read: not "never", which may be untrue.
        if (outcome === 'unknown') return 'Last check not known: CertMate could not be asked';
        return 'Never checked';
    }

    function lastCheckClass(check) {
        var outcome = lastCheckOutcome(check);
        if (outcome === 'passed') return 'text-success-fg';
        if (outcome === 'failed') return 'text-danger-fg';
        if (outcome === 'reachable') return 'text-label';
        return 'text-muted';
    }

    function lastCheckElement(check) {
        var line = document.createElement('p');
        line.className = 'text-xs mt-1 break-words ' + lastCheckClass(check);
        line.setAttribute('data-last-check', lastCheckOutcome(check));
        line.textContent = lastCheckText(check);
        return line;
    }

    function readJSON(response) {
        return response.json().catch(function () { return {}; }).then(function (body) {
            return { response: response, body: body || {} };
        });
    }

    // A save that checks first. A failed check asks in the page's own
    // dialog; Save anyway sends the save again with save_anyway, Cancel
    // sends nothing and resolves null. A check that could not run (no
    // answer, a refused connection) is a failed check on the server, so it
    // asks too.
    function saveWithCheck(url, init) {
        var joiner = url.indexOf('?') === -1 ? '?' : '&';
        return fetch(url + joiner + 'check=1', init).then(readJSON).then(function (first) {
            if (first.response.status !== 422 || first.body.code !== 'ACCOUNT_CHECK_FAILED') return first;
            var reason = String(((first.body.last_check || {}).reason) || 'no reason given').replace(/[.\s]+$/, '');
            return CertMate.confirm('The check failed: ' + reason + '. Save anyway?', 'Check failed',
                { confirmText: 'Save anyway' }).then(function (anyway) {
                if (!anyway) return null;
                return fetch(url + joiner + 'check=1&save_anyway=1', init).then(readJSON);
            });
        });
    }

    // What a save says about the check it ran.
    function savedWithCheckMessage(what, check) {
        var outcome = lastCheckOutcome(check);
        if (outcome === 'passed') return { text: what + ' saved; its check passed: ' + check.reason, type: 'success' };
        if (outcome === 'reachable') {
            return { text: what + ' saved; its directory answered. ' + check.reason + '.', type: 'info' };
        }
        if (outcome === 'failed') return { text: what + ' saved; its check failed: ' + check.reason, type: 'warning' };
        if (outcome === 'not_checkable') return { text: what + ' saved; it cannot be checked yet', type: 'success' };
        return { text: what + ' saved', type: 'success' };
    }

    // =============================================
    // Form validation function
    // =============================================

    function validateDNSProvider(provider) {
        var providerData = dnsProviders[provider];
        if (!providerData) return false;

        // Check if provider has at least one configured account
        return providerData.configured && providerData.accounts.length > 0;
    }

    // =============================================
    // Form population function
    // =============================================

    function populateForm(data) {
        try {
            addDebugLog('Populating form with settings data...', 'info');

            // Basic settings
            if (data.email) {
                var emailField = document.getElementById('email');
                if (emailField) {
                    emailField.value = data.email;
                    addDebugLog('Email field populated', 'info');
                }
            }

            if (data.domains && Array.isArray(data.domains)) {
                var domainsField = document.getElementById('domains');
                if (domainsField) {
                    // Handle both string and object formats
                    var domainStrings = data.domains.map(function (d) {
                        return typeof d === 'string' ? d : (d.domain || '');
                    }).filter(function (d) { return d; });
                    domainsField.value = domainStrings.join('\n');
                    addDebugLog('Domains field populated with ' + domainStrings.length + ' domains', 'info');
                }
            }

            {
                var autoRenewField = document.getElementById('auto_renew');
                if (autoRenewField) {
                    autoRenewField.checked = data.auto_renew !== false;
                    addDebugLog('Auto-renewal set to ' + autoRenewField.checked, 'info');
                }
            }

            // The update check has its own endpoint rather than riding in the
            // settings payload: it decides whether this instance reaches the
            // internet at all, it is admin-only for that reason, and it is
            // audited on change. Read here so the box shows the real state
            // instead of defaulting to unticked on every load.
            // The update check has its own endpoint rather than riding in the
            // settings payload: it decides whether this instance reaches the
            // internet at all, it is admin-only for that reason, and it is
            // audited on change.
            //
            // It also saves on CHANGE rather than with the form. Riding on
            // "Save Settings" coupled it to validation that has nothing to do
            // with it — measured in a browser: on an instance without an email
            // yet, saveSettings returns at "Email address is required" before
            // any request, so ticking the box and pressing Save did nothing
            // and said nothing about why.
            {
                var updateField = document.getElementById('update_check_enabled');
                if (updateField) {
                    fetch('/api/web/update-check', { credentials: 'same-origin' })
                        .then(function (r) { return r.ok ? r.json() : null; })
                        .then(function (d) { if (d) { updateField.checked = d.enabled === true; } })
                        .catch(function () { /* leave it unticked; the server is the source of truth */ });

                    if (!updateField.dataset.wired) {
                        updateField.dataset.wired = '1';
                        updateField.addEventListener('change', function () {
                            var wanted = updateField.checked;
                            fetch('/api/web/update-check', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                credentials: 'same-origin',
                                body: JSON.stringify({ enabled: wanted })
                            }).then(function (r) {
                                if (r.ok) {
                                    showMessage(wanted
                                        ? 'Update check enabled'
                                        : 'Update check disabled', 'success');
                                    return;
                                }
                                // Put the box back: a control that stays where
                                // it was clicked while the server disagrees is
                                // the worst of both.
                                updateField.checked = !wanted;
                                showMessage('Could not change the update check', 'error');
                            }).catch(function () {
                                updateField.checked = !wanted;
                                showMessage('Could not change the update check', 'error');
                            });
                        });
                    }
                }
            }

            if (data.dns_propagation_seconds && typeof data.dns_propagation_seconds === 'object') {
                propagationSeconds = Object.assign({}, data.dns_propagation_seconds);
                var checkedProvider = document.querySelector('input[name="dns_provider"]:checked');
                renderPropagationField(checkedProvider ? checkedProvider.value : data.dns_provider);
            }

            // A saved PFX password comes back masked: say whether there is one,
            // since the field itself is always shown empty.
            var pfxState = document.getElementById('pfx_password_state');
            if (pfxState) {
                pfxState.textContent = data.pfx_password
                    ? 'A password is saved: each certificate is also written as cert.pfx.'
                    : 'No password saved: no cert.pfx is written.';
            }
            var pfxClearBox = document.getElementById('pfx_password_clear');
            if (pfxClearBox) pfxClearBox.checked = false;

            if (data.renewal_threshold_days !== undefined) {
                var thresholdField = document.getElementById('renewal_threshold_days');
                if (thresholdField) {
                    thresholdField.value = data.renewal_threshold_days;
                    addDebugLog('Renewal threshold set to ' + data.renewal_threshold_days + ' days', 'info');
                }
            }

            // Default certificate-key shape — populate selectors from the
            // loaded settings so the form reflects the persisted defaults
            // (and the operator can edit them without losing the others).
            if (data.default_key_type) {
                var keyTypeField = document.getElementById('default_key_type');
                if (keyTypeField) {
                    keyTypeField.value = data.default_key_type;
                }
            }
            if (data.default_key_size) {
                var keySizeField = document.getElementById('default_key_size');
                if (keySizeField) {
                    keySizeField.value = String(data.default_key_size);
                }
            }
            if (data.default_elliptic_curve) {
                var curveField = document.getElementById('default_elliptic_curve');
                if (curveField) {
                    curveField.value = data.default_elliptic_curve;
                }
            }
            var clientShapeField = document.getElementById('client_cert_key_shape');
            if (clientShapeField && data.client_cert_key_type) {
                clientShapeField.value = data.client_cert_key_type === 'ecdsa'
                    ? 'ecdsa:' + (data.client_cert_elliptic_curve || 'secp256r1')
                    : 'rsa:' + (data.client_cert_key_size || 2048);
            }
            if (typeof toggleDefaultKeyOptions === 'function') {
                toggleDefaultKeyOptions();
            }

            if (data.api_bearer_token) {
                var populateTokenField = document.getElementById('api_bearer_token');
                if (populateTokenField) {
                    populateTokenField.value = data.api_bearer_token;
                    addDebugLog('API bearer token field populated', 'info');
                }
            } else if (data.api_bearer_token_hash) {
                var hashedTokenField = document.getElementById('api_bearer_token');
                if (hashedTokenField) {
                    hashedTokenField.placeholder = 'Set. Stored only as a hash, so it cannot be shown.';
                    addDebugLog('API bearer token already configured (hash present)', 'info');
                }
            }

            if (data.cache_ttl) {
                var cacheField = document.getElementById('cache_ttl');
                if (cacheField) {
                    cacheField.value = data.cache_ttl;
                    addDebugLog('Cache TTL set to ' + data.cache_ttl, 'info');
                }
            }

            // Challenge type selection
            if (data.challenge_type) {
                var challengeRadio = document.querySelector('input[name="challenge_type"][value="' + data.challenge_type + '"]');
                if (challengeRadio) {
                    challengeRadio.checked = true;
                    addDebugLog('Challenge type set to ' + data.challenge_type, 'info');
                }
            }
            // The DNS providers are not hidden under HTTP-01 (audit P21): a
            // certificate can choose DNS-01 whatever the default, a wildcard
            // has to, and the setup wizard sends an HTTP-01 user here to add a
            // provider. Hidden, there was no Add Account until the default
            // was changed.

            // DNS provider selection
            if (data.dns_provider) {
                var providerRadio = document.querySelector('input[name="dns_provider"][value="' + data.dns_provider + '"]');
                if (providerRadio) {
                    providerRadio.checked = true;
                    showDNSConfig(data.dns_provider);
                    addDebugLog('DNS provider set to ' + data.dns_provider, 'info');
                }
            }

            // DNS provider configurations (legacy fields)
            var localDnsProviders = data.dns_providers || {};
            Object.keys(localDnsProviders).forEach(function (provider) {
                var config = localDnsProviders[provider];
                if (typeof config === 'object' && config !== null) {
                    // Check if this is old single-account format
                    var route53Default = provider === 'route53' && config.accounts &&
                        Object.keys(config.accounts).length === 1 && config.accounts.default;
                    // A single-account (legacy) config holds the provider's own
                    // flat string values; a multi-account config holds account
                    // objects (each with a .name). Detect the legacy shape for
                    // ANY provider by looking for a non-object value under one of
                    // its legacy keys, instead of the old hard-coded list of four
                    // key names that missed every provider past the first nine.
                    var hasLegacyValues = getLegacyFieldsForProvider(provider).some(function (fieldName) {
                        var key = fieldName.replace(provider + '_', '');
                        return config[key] != null && config[key] !== '' && typeof config[key] !== 'object';
                    });
                    if (route53Default || hasLegacyValues) {
                        populateLegacyProviderFields(provider, route53Default || config);
                    }
                }
            });

            // Load storage backend settings
            loadStorageBackendSettings(data);
            addDebugLog('Storage backend settings loaded', 'info');

            // Load CA provider settings
            loadCAProviderSettings(data);
            addDebugLog('CA provider settings loaded', 'info');

            addDebugLog('Form populated successfully', 'info');
        } catch (error) {
            addDebugLog('Error populating form: ' + error.message, 'error');
            console.error('Error populating form:', error);
        }
    }

    // =============================================
    // Legacy provider field population
    // =============================================

    function populateLegacyProviderFields(provider, config) {
        try {
            addDebugLog('Populating legacy fields for ' + provider, 'info');
            config = config || {};

            // Mirror the save path exactly (see the getLegacyFieldsForProvider
            // loop in saveSettings): the config key is the field id with the
            // provider prefix stripped by the same String.replace, so every
            // provider round-trips - not only the nine that used to be listed
            // here by hand. (The prefix strip is a no-op where the field id and
            // provider id disagree on hyphen vs underscore, e.g. he-ddns; the
            // save path stored the key the same way, so both sides agree.)
            getLegacyFieldsForProvider(provider).forEach(function (fieldName) {
                var field = document.getElementById(fieldName);
                if (!field) return;
                var configKey = fieldName.replace(provider + '_', '');
                if (provider === 'route53' && configKey === 'assume_role_arn') {
                    // An empty saved ARN must clear the previous value in the form.
                    field.value = config.assume_role_arn || '';
                } else if (config[configKey]) {
                    field.value = config[configKey];
                    addDebugLog('Field ' + fieldName + ' populated', 'info');
                }
            });
            if (provider === 'route53') toggleRoute53LegacyAuthMode();
        } catch (error) {
            addDebugLog('Error populating legacy fields for ' + provider + ': ' + error.message, 'warn');
        }
    }

    // =============================================
    // Modal management functions
    // =============================================

    // Stores the element that triggered the add-account modal so we can
    // restore focus on close (B5 accessibility fix).
    var _addAccountTriggerEl = null;

    function showAddAccountModal(provider) {
        addDebugLog('Opening add account modal for ' + provider, 'info');

        // Remember trigger for focus restore on close
        _addAccountTriggerEl = document.activeElement;

        var modal = document.getElementById('addAccountModal');
        // R-2: macro emits `<h3 id="<modalId>-title">` for aria-labelledby
        // wiring; the dynamic per-provider title still lands in the same
        // <h3>, just renamed from the legacy "modal-title" id.
        var modalTitle = document.getElementById('addAccountModal-title');
        var providerFields = document.getElementById('modal-provider-fields');
        var accountNameField = document.getElementById('account-name');
        var accountDescField = document.getElementById('account-description');
        var setDefaultCheckbox = document.getElementById('set-as-default');

        if (!modal || !modalTitle || !providerFields) {
            addDebugLog('Modal elements not found', 'error');
            return;
        }

        // Set modal title
        var providerNames = {
            'cloudflare': 'Cloudflare',
            'route53': 'AWS Route53',
            'azure': 'Azure DNS',
            'google': 'Google Cloud DNS',
            'powerdns': 'PowerDNS',
            'digitalocean': 'DigitalOcean',
            'linode': 'Akamai Connected Cloud (Linode)',
            'edgedns': 'Akamai Edge DNS',
            'gandi': 'Gandi',
            'ovh': 'OVH',
            'namecheap': 'Namecheap',
            'rfc2136': 'RFC2136',
            'hetzner': 'Hetzner',
            'porkbun': 'Porkbun',
            'godaddy': 'GoDaddy',
            'he-ddns': 'Hurricane Electric',
            'dynudns': 'Dynu',
            'dnsmadeeasy': 'DNS Made Easy',
            'nsone': 'NS1',
            'duckdns': 'DuckDNS',
            'custom-script': 'Custom Script'
        };
        modalTitle.textContent = 'Add ' + (providerNames[provider] || provider) + ' Account';

        // Clear previous fields
        providerFields.innerHTML = '';
        if (accountNameField) accountNameField.value = '';
        if (accountDescField) accountDescField.value = '';
        if (setDefaultCheckbox) setDefaultCheckbox.checked = false;

        // Generate provider-specific fields
        var fields = getProviderFields(provider);
        providerFields.innerHTML = fields;
        if (provider === 'route53') toggleRoute53ModalAuthMode(providerFields);

        // Store current provider
        modal.dataset.provider = provider;

        // Show modal via the shared, ref-counted scroll lock (see
        // showEditAccountModal) rather than document.body.style.overflow.
        var wasHidden = modal.classList.contains('hidden');
        modal.classList.remove('hidden');
        if (wasHidden) CertMate.lockScroll();

        // Auto-focus the first input field
        setTimeout(function () {
            var firstInput = modal.querySelector('input, select, textarea');
            if (firstInput) firstInput.focus();
        }, 50);

        // Escape key listener to close
        modal._escHandler = function (e) {
            if (e.key === 'Escape') closeAddAccountModal();
        };
        document.addEventListener('keydown', modal._escHandler);
    }

    function closeAddAccountModal() {
        var modal = document.getElementById('addAccountModal');
        if (modal) {
            var wasOpen = !modal.classList.contains('hidden');
            modal.classList.add('hidden');
            if (wasOpen) CertMate.unlockScroll();

            // Remove Escape key listener
            if (modal._escHandler) {
                document.removeEventListener('keydown', modal._escHandler);
                modal._escHandler = null;
            }

            // Clear form
            document.getElementById('addAccountForm').reset();
            document.getElementById('modal-provider-fields').innerHTML = '';
        }

        // Restore focus to the element that triggered the modal
        if (_addAccountTriggerEl && _addAccountTriggerEl.focus) {
            _addAccountTriggerEl.focus();
            _addAccountTriggerEl = null;
        }
    }

    // Stores the element that triggered the edit-account modal so we can
    // restore focus on close (B5 accessibility fix).
    var _editAccountTriggerEl = null;

    function showEditAccountModal(provider, accountId) {
        addDebugLog('Opening edit account modal for ' + provider + ':' + accountId, 'info');

        // Remember trigger for focus restore on close
        _editAccountTriggerEl = document.activeElement;

        var modal = document.getElementById('editAccountModal');
        var editAccountIdField = document.getElementById('edit-account-id');
        var editProviderField = document.getElementById('edit-provider-name');
        var editProviderFields = document.getElementById('edit-modal-provider-fields');
        var editAccountNameField = document.getElementById('edit-account-name');
        var editAccountDescField = document.getElementById('edit-account-description');
        var editSetDefaultCheckbox = document.getElementById('edit-set-as-default');

        if (!modal || !editAccountIdField || !editProviderField) {
            addDebugLog('Edit modal elements not found', 'error');
            return;
        }

        // Set hidden fields
        editAccountIdField.value = accountId;
        editProviderField.value = provider;

        // Get account data
        var providerData = dnsProviders[provider];
        var account = (providerData && providerData.accounts) ? providerData.accounts.find(function (acc) { return acc.id === accountId; }) : null;

        if (!account) {
            addDebugLog('Account ' + accountId + ' not found for provider ' + provider, 'error');
            showMessage('Account not found', 'error');
            return;
        }

        // Populate basic fields
        if (editAccountNameField) editAccountNameField.value = account.name || '';
        if (editAccountDescField) editAccountDescField.value = account.description || '';
        if (editSetDefaultCheckbox) {
            editSetDefaultCheckbox.checked = (currentSettings.default_accounts && currentSettings.default_accounts[provider]) === accountId;
        }

        // Generate provider-specific fields with current values
        var fields = getProviderFields(provider, account);
        editProviderFields.innerHTML = fields;
        if (provider === 'route53') toggleRoute53ModalAuthMode(editProviderFields);

        // Show modal. Use the shared, ref-counted scroll lock (it locks the
        // real <html> scroller and survives stacked modals) instead of poking
        // document.body.style.overflow, which fought the shared counter and
        // left the page either stuck locked or unlocked too early.
        var wasHidden = modal.classList.contains('hidden');
        modal.classList.remove('hidden');
        if (wasHidden) CertMate.lockScroll();

        // Auto-focus the first input field
        setTimeout(function () {
            var firstInput = modal.querySelector('input, select, textarea');
            if (firstInput) firstInput.focus();
        }, 50);

        // Escape key listener to close
        modal._escHandler = function (e) {
            if (e.key === 'Escape') closeEditAccountModal();
        };
        document.addEventListener('keydown', modal._escHandler);
    }

    function closeEditAccountModal() {
        var modal = document.getElementById('editAccountModal');
        if (modal) {
            var wasOpen = !modal.classList.contains('hidden');
            modal.classList.add('hidden');
            if (wasOpen) CertMate.unlockScroll();

            // Remove Escape key listener
            if (modal._escHandler) {
                document.removeEventListener('keydown', modal._escHandler);
                modal._escHandler = null;
            }

            // Clear form
            document.getElementById('editAccountForm').reset();
            document.getElementById('edit-modal-provider-fields').innerHTML = '';
        }

        // Restore focus to the element that triggered the modal
        if (_editAccountTriggerEl && _editAccountTriggerEl.focus) {
            _editAccountTriggerEl.focus();
            _editAccountTriggerEl = null;
        }
    }

    // =============================================
    // Provider fields generation
    // =============================================

    function getProviderFields(provider, existingData) {
        existingData = existingData || {};

        var fieldMappings = {
            'cloudflare': [
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Enter your Cloudflare API token', required: true }
            ],
            'route53': [
                { name: 'auth_mode', label: 'Authentication', type: 'select', options: [
                    { value: 'access_keys', label: 'Access keys' },
                    { value: 'iam_role', label: 'AWS credentials / IAM role (no keys)' }
                ], defaultValue: 'access_keys', required: true },
                { name: 'access_key_id', label: 'Access Key ID', type: 'password', placeholder: 'AKIAIOSFODNN7EXAMPLE', required: true },
                { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', placeholder: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', required: true },
                { name: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1', defaultValue: 'us-east-1', required: false },
                { name: 'assume_role_arn', label: 'Assume role ARN (optional)', type: 'text', placeholder: 'arn:aws:iam::123456789012:role/CertMateRoute53', required: false }
            ],
            'azure': [
                { name: 'subscription_id', label: 'Subscription ID', type: 'text', placeholder: '12345678-1234-1234-1234-123456789012', required: true },
                { name: 'resource_group', label: 'Resource Group', type: 'text', placeholder: 'my-dns-resource-group', required: true },
                { name: 'tenant_id', label: 'Tenant ID', type: 'text', placeholder: '12345678-1234-1234-1234-123456789012', required: true },
                { name: 'client_id', label: 'Client ID', type: 'text', placeholder: '12345678-1234-1234-1234-123456789012', required: true },
                { name: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'Your Azure client secret', required: true }
            ],
            'google': [
                { name: 'project_id', label: 'Project ID', type: 'text', placeholder: 'my-gcp-project-123456', required: true },
                { name: 'service_account_key', label: 'Service Account JSON Key', type: 'textarea', placeholder: '{"type": "service_account", "project_id": "...", ...}', required: true }
            ],
            'powerdns': [
                { name: 'api_url', label: 'API URL', type: 'url', placeholder: 'https://powerdns.example.com:8081', required: true },
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your PowerDNS API key', required: true }
            ],
            'digitalocean': [
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Your DigitalOcean API token', required: true }
            ],
            'linode': [
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your Linode API key', required: true }
            ],
            'edgedns': [
                { name: 'client_token', label: 'Client Token', type: 'password', placeholder: 'akab-XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX', required: true },
                { name: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'Your Akamai client secret', required: true },
                { name: 'access_token', label: 'Access Token', type: 'password', placeholder: 'akab-XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX', required: true },
                { name: 'host', label: 'API Host', type: 'text', placeholder: 'akab-XXXX.luna.akamaiapis.net', required: true }
            ],
            'gandi': [
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Your Gandi LiveDNS API token', required: true }
            ],
            'ovh': [
                {
                    name: 'endpoint', label: 'Endpoint', type: 'select', options: [
                        { value: 'ovh-eu', label: 'ovh-eu (Europe)' },
                        { value: 'ovh-us', label: 'ovh-us (US)' },
                        { value: 'ovh-ca', label: 'ovh-ca (Canada)' },
                        { value: 'kimsufi-eu', label: 'kimsufi-eu' },
                        { value: 'kimsufi-ca', label: 'kimsufi-ca' },
                        { value: 'soyoustart-eu', label: 'soyoustart-eu' },
                        { value: 'soyoustart-ca', label: 'soyoustart-ca' }
                    ], required: true
                },
                { name: 'application_key', label: 'Application Key', type: 'password', placeholder: 'Your application key', required: true },
                { name: 'application_secret', label: 'Application Secret', type: 'password', placeholder: 'Your application secret', required: true },
                { name: 'consumer_key', label: 'Consumer Key', type: 'password', placeholder: 'Your consumer key', required: true }
            ],
            'namecheap': [
                { name: 'username', label: 'Username', type: 'text', placeholder: 'Your Namecheap username', required: true },
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your Namecheap API key', required: true }
            ],
            'rfc2136': [
                { name: 'nameserver', label: 'Nameserver', type: 'text', placeholder: 'ns.example.com', required: true },
                { name: 'tsig_key', label: 'TSIG Key Name', type: 'text', placeholder: 'mykey', required: true },
                { name: 'tsig_secret', label: 'TSIG Secret', type: 'password', placeholder: 'Base64-encoded secret', required: true },
                {
                    name: 'tsig_algorithm', label: 'TSIG Algorithm', type: 'select', options: [
                        { value: 'HMAC-MD5', label: 'HMAC-MD5' },
                        { value: 'HMAC-SHA1', label: 'HMAC-SHA1' },
                        { value: 'HMAC-SHA224', label: 'HMAC-SHA224' },
                        { value: 'HMAC-SHA256', label: 'HMAC-SHA256' },
                        { value: 'HMAC-SHA384', label: 'HMAC-SHA384' },
                        { value: 'HMAC-SHA512', label: 'HMAC-SHA512' }
                    ], defaultValue: 'HMAC-SHA256', required: false
                }
            ],
            'hetzner': [
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Your Hetzner DNS API token', required: true }
            ],
            'porkbun': [
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your Porkbun API key', required: true },
                { name: 'secret_key', label: 'Secret Key', type: 'password', placeholder: 'Your Porkbun secret key', required: true }
            ],
            'godaddy': [
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your GoDaddy API key', required: true },
                { name: 'secret', label: 'API Secret', type: 'password', placeholder: 'Your GoDaddy API secret', required: true }
            ],
            'he-ddns': [
                { name: 'username', label: 'Username', type: 'text', placeholder: 'Your Hurricane Electric username', required: true },
                { name: 'password', label: 'Password', type: 'password', placeholder: 'Your Hurricane Electric password', required: true }
            ],
            'dynudns': [
                { name: 'token', label: 'API Token', type: 'password', placeholder: 'Your Dynu API token', required: true }
            ],
            'dnsmadeeasy': [
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your DNS Made Easy API key', required: true },
                { name: 'secret_key', label: 'Secret Key', type: 'password', placeholder: 'Your DNS Made Easy secret key', required: true }
            ],
            'nsone': [
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your NS1 API key', required: true }
            ],
            'vultr': [
                { name: 'api_key', label: 'API Key', type: 'password', placeholder: 'Your Vultr API key', required: true }
            ],
            'solidserver': [
                { name: 'host', label: 'Host', type: 'text', placeholder: 'IP or hostname', required: true },
                { name: 'username', label: 'Username', type: 'text', placeholder: 'API user', required: true },
                { name: 'password', label: 'Password', type: 'password', placeholder: 'API password', required: true },
                { name: 'dns_name', label: 'DNS Server Name', type: 'text', placeholder: 'SOLIDserver smart architecture DNS name', required: true },
                { name: 'dnsview_name', label: 'DNS View Name', type: 'text', placeholder: 'External (optional)', required: false },
                { name: 'propagation_seconds', label: 'Propagation Delay (s)', type: 'number', placeholder: '120', required: false }
            ],
            'duckdns': [
                { name: 'api_token', label: 'Account Token', type: 'password', placeholder: 'UUID-format token from your DuckDNS account page', required: true }
            ],
            'custom-script': [
                { name: 'auth_hook', label: 'Auth Hook Script Path', type: 'text', placeholder: '/usr/local/bin/certmate-dns-auth.sh', required: true },
                { name: 'cleanup_hook', label: 'Cleanup Hook Script Path (optional)', type: 'text', placeholder: '/usr/local/bin/certmate-dns-cleanup.sh', required: false }
            ]
        };

        var fields = fieldMappings[provider] || [];
        var html = '';

        fields.forEach(function (field) {
            var value = escapeHtml(existingData[field.name] || field.defaultValue || '');
            var fieldId = 'modal-' + field.name;

            html += '<div class="mb-4">';
            html += '<label for="' + fieldId + '" class="block text-sm font-medium text-label mb-1">';
            html += field.label + (field.required ? ' *' : '');
            html += '</label>';

            if (field.type === 'select') {
                html += '<select id="' + fieldId + '" name="' + field.name + '" class="mt-1 block w-full border border-border bg-input text-foreground rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary" ' + (field.required ? 'required' : '') + '>';
                if (!field.required) {
                    html += '<option value="">Select ' + field.label.toLowerCase() + '</option>';
                }
                field.options.forEach(function (option) {
                    var selected = value === option.value ? 'selected' : '';
                    html += '<option value="' + option.value + '" ' + selected + '>' + option.label + '</option>';
                });
                html += '</select>';
            } else if (field.type === 'textarea') {
                html += '<textarea id="' + fieldId + '" name="' + field.name + '" rows="4" class="mt-1 block w-full border border-border bg-input text-foreground rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary" placeholder="' + field.placeholder + '" ' + (field.required ? 'required' : '') + '>' + value + '</textarea>';
            } else {
                html += '<input type="' + field.type + '" id="' + fieldId + '" name="' + field.name + '" class="mt-1 block w-full border border-border bg-input text-foreground rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary" placeholder="' + field.placeholder + '" value="' + value + '" ' + (field.required ? 'required' : '') + '>';
            }

            html += '</div>';
        });

        return html;
    }

    // =============================================
    // Save new account
    // =============================================

    function saveAccount() {
        addDebugLog('Saving new account...', 'info');

        var modal = document.getElementById('addAccountModal');
        var provider = modal.dataset.provider;
        var accountForm = document.getElementById('addAccountForm');
        var formData = new FormData(accountForm);

        if (!provider) {
            showMessage('Error saving account: Provider not specified', 'error');
            addDebugLog('Error saving account: Provider not specified', 'error');
            return;
        }

        // Generate a unique account ID
        var accountName = formData.get('name') || 'Untitled Account';
        var accountId = accountName.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'account_' + Date.now();

        // Build account configuration
        var accountConfig = {
            name: accountName,
            description: formData.get('description') || ''
        };

        // Add provider-specific fields
        var providerFieldsContainer = document.getElementById('modal-provider-fields');
        var providerFieldElements = providerFieldsContainer.querySelectorAll('input, select, textarea');

        providerFieldElements.forEach(function (field) {
            if (field.name && field.value) {
                accountConfig[field.name] = field.value;
            }
        });

        // Check if any required provider fields are empty
        var requiredFields = providerFieldsContainer.querySelectorAll('input[required], select[required], textarea[required]');
        var validationError = null;
        for (var i = 0; i < requiredFields.length; i++) {
            var field = requiredFields[i];
            if (!field.value || !field.value.trim()) {
                // The field's label, not its placeholder: that read "Enter your
                // Cloudflare API token is required" (UX audit, 2026-11-17).
                var fieldLabel = field.id && providerFieldsContainer.querySelector('label[for="' + field.id + '"]');
                var fieldName = fieldLabel ? fieldLabel.textContent.replace(/\*\s*$/, '').trim() : field.name;
                validationError = fieldName + ' is required';
                break;
            }
        }

        if (validationError) {
            addDebugLog('Error saving account: ' + validationError, 'error');
            showMessage('Error saving account: ' + validationError, 'error');
            return;
        }

        var payload = {
            account_id: accountId,
            config: accountConfig,
            set_as_default: formData.get('set_as_default') === 'on'
        };

        addDebugLog('Account payload: ' + JSON.stringify(payload, null, 2), 'info');

        // Send to backend, checking the credentials first (P39).
        saveWithCheck('/api/dns/' + encodeURIComponent(provider) + '/accounts', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        })
            .then(function (answer) {
                if (!answer) return; // Cancelled after a failed check: nothing saved, the form stays open.
                if (!answer.response.ok) {
                    // The server's own sentence when it sent one: a name
                    // already in use answers 409 and says what to do.
                    throw new Error(answer.body.error || ('HTTP ' + answer.response.status));
                }
                addDebugLog('Account created: ' + accountId, 'info');
                var said = savedWithCheckMessage('Account "' + accountName + '"', answer.body.last_check);
                showMessage(said.text, said.type);

                // Refresh settings and close modal
                return loadSettings().then(function () {
                    closeAddAccountModal();
                });
            })
            .catch(function (error) {
                addDebugLog('Error saving account: ' + error.message, 'error');
                showMessage('Error saving account: ' + error.message, 'error');
            });
    }

    // =============================================
    // Save edit account
    // =============================================

    function saveEditAccount() {
        addDebugLog('Saving account changes...', 'info');

        var editForm = document.getElementById('editAccountForm');
        var formData = new FormData(editForm);
        var provider = formData.get('edit-provider-name');
        var accountId = formData.get('edit-account-id');

        if (!provider || !accountId) {
            addDebugLog('Error updating account: Provider or account ID not specified', 'error');
            showMessage('Error updating account: Provider or account ID not specified', 'error');
            return;
        }

        // Build account data
        var accountData = {
            name: formData.get('name') || 'Untitled Account',
            description: formData.get('description') || '',
            set_as_default: formData.get('set_as_default') === 'on'
        };

        // Add provider-specific fields
        var providerFieldsContainer = document.getElementById('edit-modal-provider-fields');
        var providerFieldElements = providerFieldsContainer.querySelectorAll('input, select, textarea');

        providerFieldElements.forEach(function (field) {
            if (field.name && (field.value ||
                    (provider === 'route53' && field.name === 'assume_role_arn'))) {
                accountData[field.name] = field.value;
            }
        });

        addDebugLog('Updated account data: ' + JSON.stringify(accountData, null, 2), 'info');

        // Send to backend, checking the credentials first (P39).
        saveWithCheck('/api/dns/' + encodeURIComponent(provider) + '/accounts/' + encodeURIComponent(accountId), {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accountData)
        })
            .then(function (answer) {
                if (!answer) return; // Cancelled after a failed check: nothing saved, the form stays open.
                if (!answer.response.ok) {
                    throw new Error(answer.body.error || ('HTTP ' + answer.response.status));
                }
                addDebugLog('Account updated: ' + accountId, 'info');
                var said = savedWithCheckMessage('Account "' + accountData.name + '"', answer.body.last_check);
                showMessage(said.text, said.type);

                // Refresh settings and close modal
                return loadSettings().then(function () {
                    closeEditAccountModal();
                });
            })
            .catch(function (error) {
                addDebugLog('Error updating account: ' + error.message, 'error');
                showMessage('Error updating account: ' + error.message, 'error');
            });
    }

    // =============================================
    // Delete account
    // =============================================

    function deleteAccount(provider, accountId) {
        CertMate.confirm('Delete the ' + provider + ' account "' + accountId + '"? This cannot be undone. ' +
            'An account that certificates renew through is refused, and the refusal names them.', 'Delete Account').then(function (confirmed) {
            if (!confirmed) return;

            addDebugLog('Deleting account ' + provider + ':' + accountId, 'info');

            return fetch('/api/dns/' + provider + '/accounts/' + accountId, {
                method: 'DELETE',
                headers: {}
            })
                .then(function (response) {
                    if (!response.ok) {
                        return response.text().then(function (t) {
                            // The server's sentence when it sent one: an account
                            // in use answers 409 and names its certificates.
                            var said = null;
                            try { said = JSON.parse(t).error; } catch (_) { /* not JSON */ }
                            throw new Error(said || ('HTTP ' + response.status + ': ' + t));
                        });
                    }
                    addDebugLog('Account deleted: ' + accountId, 'info');
                    showMessage('Account deleted successfully', 'success');

                    // Refresh settings
                    return loadSettings();
                });
        })
            .catch(function (error) {
                addDebugLog('Error deleting account: ' + error.message, 'error');
                showMessage('Error deleting account: ' + error.message, 'error');
            });
    }

    // =============================================
    // Update account lists in the DNS config sections
    // =============================================

    function updateAccountLists() {
        var providers = Object.keys(dnsProviders);

        providers.forEach(function (provider) {
            var accountsListContainer = document.getElementById(provider + '-accounts-list');
            var legacyConfigContainer = document.getElementById(provider + '-legacy-config');

            if (!accountsListContainer) return;

            var providerData = dnsProviders[provider];

            if (providerData && providerData.accounts && providerData.accounts.length > 0) {
                // Show multi-account interface
                accountsListContainer.innerHTML = '';

                providerData.accounts.forEach(function (account) {
                    var isDefault = (currentSettings.default_accounts && currentSettings.default_accounts[provider]) === account.id;
                    var accountCard = createAccountCard(provider, account, isDefault);
                    accountsListContainer.appendChild(accountCard);
                });

                // One place per credential: once a provider has an account,
                // its card's Edit is where the credential changes.
                if (legacyConfigContainer) {
                    legacyConfigContainer.style.display = 'none';
                }
            } else {
                // Show legacy config for backward compatibility
                accountsListContainer.innerHTML = '<div class="text-sm text-muted">No accounts configured yet.</div>';
                if (legacyConfigContainer) {
                    legacyConfigContainer.style.display = 'block';
                }
            }
        });
    }

    // =============================================
    // Create account card element
    // =============================================

    // One action row for a DNS account and a CA account (#1511, P42): the
    // same small outlined buttons with the same icons. A DNS account's Edit
    // and Delete were white with a border and icons, a CA account's tinted
    // chips with neither. The small size: the row holds three to four
    // actions beside the account's name and its last check.
    var ACCOUNT_ACTION = 'btn btn-secondary btn-sm';
    var ACCOUNT_DELETE = ACCOUNT_ACTION + ' text-danger-fg';
    var ACCOUNT_ICONS = { check: 'fa-plug', edit: 'fa-pen', delete: 'fa-trash-alt' };

    function accountButtonHtml(action, label) {
        return '<i class="fas ' + ACCOUNT_ICONS[action] + ' mr-1" aria-hidden="true"></i>' + label;
    }

    function createAccountCard(provider, account, isDefault) {
        var card = document.createElement('div');
        card.className = 'bg-input border border-border rounded-lg p-4';

        var safeName = escapeHtml(account.name);
        var safeDesc = escapeHtml(account.description);
        var safeId = escapeHtml(account.id);
        var safeProvider = escapeHtml(provider);

        var descHtml = account.description ? '<p class="text-xs text-muted mt-1">' + safeDesc + '</p>' : '';
        var defaultBadge = isDefault ? '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-info-surface text-blue-800 dark:text-blue-400"><i class="fas fa-star mr-1"></i>Default</span>' : '';

        // An account the server says cannot issue (#1469): the empty "default"
        // a fresh instance carries, or one missing a required field.
        var noCredentialsBadge = account.hasCredentials === false
            ? '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-warning-surface text-warning-fg">No credentials</span>'
            : '';

        card.innerHTML =
            // Wraps: with Check credentials the three buttons squeezed the
            // name and the last check into a column a word wide on a phone.
            '<div class="flex flex-wrap items-center justify-between gap-3">' +
            '<div class="flex-1 min-w-40">' +
            // Wraps: with both badges the row was 3 px wider than a 360 px phone.
            '<div class="flex flex-wrap items-center gap-2">' +
            '<h5 class="text-sm font-medium text-foreground">' + safeName + '</h5>' +
            defaultBadge + noCredentialsBadge +
            '</div>' +
            descHtml +
            '<div class="text-xs text-muted mt-1">ID: ' + safeId + '</div>' +
            '<div data-last-check-slot></div>' +
            '</div>' +
            '<div class="flex flex-wrap items-center gap-2">' +
            '<button type="button" data-action="check" data-provider="' + safeProvider + '" data-account-id="' + safeId + '"' +
            ' class="' + ACCOUNT_ACTION + '">' + accountButtonHtml('check', 'Check credentials') + '</button>' +
            '<button type="button" data-action="edit" data-provider="' + safeProvider + '" data-account-id="' + safeId + '"' +
            ' class="' + ACCOUNT_ACTION + '">' + accountButtonHtml('edit', 'Edit') + '</button>' +
            '<button type="button" data-action="delete" data-provider="' + safeProvider + '" data-account-id="' + safeId + '"' +
            ' class="' + ACCOUNT_DELETE + '">' + accountButtonHtml('delete', 'Delete') + '</button>' +
            '</div>' +
            '</div>';

        card.querySelector('[data-last-check-slot]').replaceWith(lastCheckElement(account.lastCheck));

        // Attach event listeners safely (no inline onclick with string interpolation)
        card.querySelector('[data-action="check"]').addEventListener('click', function (event) {
            checkDNSAccount(provider, account, event.currentTarget);
        });
        card.querySelector('[data-action="edit"]').addEventListener('click', function () { showEditAccountModal(provider, account.id); });
        card.querySelector('[data-action="delete"]').addEventListener('click', function () { deleteAccount(provider, account.id); });
        return card;
    }

    // One read-only call to the provider, run by the server, which keeps the
    // result; the card and the provider tile follow it.
    function checkDNSAccount(provider, account, button) {
        if (button) button.disabled = true;
        return fetch('/api/dns/' + encodeURIComponent(provider) + '/accounts/' +
            encodeURIComponent(account.id) + '/check', { method: 'POST', headers: API_HEADERS })
            .then(readJSON)
            .then(function (answer) {
                if (!answer.response.ok || !answer.body.last_check) {
                    throw new Error(answer.body.error || ('HTTP ' + answer.response.status));
                }
                account.lastCheck = answer.body.last_check;
                var outcome = lastCheckOutcome(account.lastCheck);
                showMessage(account.name + ': ' + lastCheckText(account.lastCheck),
                    outcome === 'passed' ? 'success' : outcome === 'failed' ? 'error' : 'info');
                updateProviderStatusIndicators();
                updateAccountLists();
            })
            .catch(function (error) {
                showMessage('Could not check the account: ' + error.message, 'error');
            })
            .then(function () { if (button && button.isConnected) button.disabled = false; });
    }

    // =============================================
    // BACKUP MANAGEMENT FUNCTIONS
    // =============================================

    function createBackup(type, buttonElement) {
        var button = null;
        var originalText = '';

        addDebugLog('Creating ' + type + ' backup...', 'info');

        // Get button element - either passed directly or from event
        button = buttonElement || (window.event && window.event.target);
        originalText = button ? button.innerHTML : '';

        if (button) {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Creating...';
        }

        // Map legacy backup types to new unified format
        var backupType = type;
        if (type === 'full') {
            backupType = 'unified';
        }

        fetch('/api/backups/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: backupType,
                reason: 'manual_backup',
                // Offered only when backups are encrypted at rest (the box is
                // rendered then): a complete backup can restore the instance.
                include_secrets: !!(document.getElementById('backupIncludeSecrets') || {}).checked
            })
        })
            .then(function (response) {
                if (!response.ok) {
                    return response.text().then(function (errorData) {
                        var parsed = null;
                        try { parsed = errorData ? JSON.parse(errorData) : null; } catch (e) { /* not JSON */ }
                        var err = new Error('HTTP ' + response.status + ': ' + (parsed && parsed.error ? parsed.error : errorData));
                        err.responseStatus = response.status;
                        err.responseBody = parsed;
                        throw err;
                    });
                }
                return response.json();
            })
            .then(function (result) {
                if (result.message) {
                    addDebugLog('Backup created successfully: ' + result.backups.map(function (b) { return b.filename; }).join(', '), 'info');

                    var message = (type === 'unified' ? 'Unified' : type) + ' backup created successfully!';
                    if (result.recommendation) {
                        message += ' Note: ' + result.recommendation;
                    }
                    showMessage(message, 'success');

                    // Refresh backup list
                    return refreshBackupList();
                } else {
                    var err = new Error(result.error || 'Failed to create backup');
                    err.responseBody = result;
                    throw err;
                }
            })
            .catch(function (error) {
                addDebugLog('Error creating backup: ' + error.message, 'error');
                showMessage('Error creating backup: ' + error.message, 'error', {
                    errorContext: {
                        endpoint: 'POST /api/backups/create',
                        status: error.responseStatus || 0,
                        code: error.responseBody && error.responseBody.code,
                        message: (error.responseBody && error.responseBody.error) || error.message,
                        hint: error.responseBody && error.responseBody.hint
                    }
                });
            })
            .then(function () {
                // finally block equivalent - restore button state
                if (button && originalText) {
                    button.disabled = false;
                    button.innerHTML = originalText;
                }
            });
    }

    // =============================================
    // Refresh backup list
    // =============================================

    // Bring in an archive kept off this machine. Without it, recovering a lost
    // volume needed filesystem access to a filesystem that no longer existed:
    // restore only ever reads files already in backups/unified (#655).
    //
    // Uploading stores; it does not restore. That stays a separate, explicit
    // action, so an upload can never be destructive by itself.
    function uploadBackup(buttonElement) {
        var input = document.getElementById('backup-upload-input');
        var file = input && input.files && input.files[0];
        if (!file) {
            showMessage('Choose a backup file to upload first.', 'warning');
            return;
        }

        var button = buttonElement || (window.event && window.event.target);
        var originalText = button ? button.innerHTML : '';
        if (button) {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Uploading...';
        }

        var payload = new FormData();
        payload.append('file', file);

        // No Content-Type header on purpose: the browser sets it along with the
        // multipart boundary, and setting it by hand produces a body the server
        // cannot parse.
        fetch('/api/backups/upload', { method: 'POST', body: payload })
            .then(function (response) {
                return response.json().then(function (result) {
                    if (!response.ok) {
                        var err = new Error(result.error || ('HTTP ' + response.status));
                        err.responseStatus = response.status;
                        throw err;
                    }
                    return result;
                });
            })
            .then(function (result) {
                addDebugLog('Backup uploaded and stored as ' + result.filename, 'info');
                showMessage('Backup uploaded. It is stored, not restored — check it in the ' +
                    'list below, then restore it explicitly.', 'success');
                if (input) { input.value = ''; }
                return refreshBackupList();
            })
            .catch(function (error) {
                addDebugLog('Backup upload failed: ' + error.message, 'error');
                showMessage('Upload failed: ' + error.message, 'error');
            })
            .finally(function () {
                if (button) {
                    button.disabled = false;
                    button.innerHTML = originalText;
                }
            });
    }

    function refreshBackupList() {
        addDebugLog('Refreshing backup list...', 'info');

        return fetch('/api/backups', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(function (backups) {
                updateBackupList(backups);
                addDebugLog('Backup list refreshed: ' + backups.unified.length + ' backups', 'info');
            })
            .catch(function (error) {
                addDebugLog('Error refreshing backup list: ' + error.message, 'error');
                console.error('Error refreshing backup list:', error);

                // Show error in backup list container
                var backupList = document.getElementById('unified-backup-list');
                if (backupList) {
                    backupList.innerHTML =
                        '<div class="p-4 text-center text-red-500 dark:text-red-400">' +
                        '<i class="fas fa-exclamation-triangle mr-2"></i>' +
                        'Error loading backups: ' + CertMate.escapeHtml(error.message) +
                        '</div>';
                }
            });
    }

    // =============================================
    // Update backup list UI
    // =============================================

    function updateBackupList(backups) {
        var unifiedBackupList = document.getElementById('unified-backup-list');

        if (!unifiedBackupList) return;

        // Update Unified Backups (only show unified backups)
        if (backups.unified && backups.unified.length === 0) {
            unifiedBackupList.innerHTML =
                '<div class="p-4 text-center text-muted">' +
                '<i class="fas fa-archive mr-2"></i>' +
                'No backups yet' +
                '<div class="text-xs mt-1">Create your first backup above!</div>' +
                '</div>';
        } else if (backups.unified) {
            // Compact single-row layout on a neutral surface (the old per-row
            // green fill made the list hard to scan). The whole list grows the
            // page instead of scrolling inside a 256px box; a working "Show
            // more" reveals the rest in batches rather than the old dead-end
            // "N more backups available" label.
            var all = backups.unified;
            var visible = 8;

            function backupRow(backup) {
                var metadata = backup.metadata || {};
                var createdDate = CertMate.formatDateTime(metadata.created || metadata.timestamp);
                var size = CertMate.formatBytes(metadata.size);
                var reason = metadata.backup_reason || metadata.reason || 'manual';
                var domains = metadata.total_domains || (metadata.domains && metadata.domains.length) || 0;
                var safeFilename = escapeHtml(backup.filename);
                var safeReason = escapeHtml(reason);
                var iconBtn = 'p-1.5 rounded transition-colors';
                // Whether this archive can actually bring the instance back.
                // Automatic backups are taken with secrets masked and cannot:
                // the credentials are not in the archive. Offering an identical
                // Restore button on every row made the newest entry a decoy
                // restore point (#655). Treated as false unless the API
                // explicitly says true: an older server that does not send the
                // field must not be read as a promise that it can.
                //
                // It is not a claim that the endpoint rejects such archives,
                // which is what this comment used to say. The endpoint refuses a masked
                // archive over an instance that already holds certificates,
                // and accepts one onto an empty instance as a configuration
                // snapshot. `can_restore` answers "can this recover the
                // instance", not "would the endpoint take the file"; the
                // blocked reason below says what it can still do.
                var canRestore = backup.can_restore === true;
                var blockedReason = escapeHtml(backup.restore_blocked_reason ||
                    'this archive cannot restore the instance');
                // Archives written before v2.26.0 carry every private key while
                // their manifest claims to be share-safe, so this is read from
                // the archive rather than from that claim (#595). Only a
                // definite true warns: null means it could not be inspected,
                // and crying wolf on those would train people to ignore it.
                var carriesKeys = backup.contains_key_material === true;
                var keyCount = backup.key_file_count;
                var keyBadge = !carriesKeys ? '' :
                    '<span aria-hidden="true">·</span>' +
                    '<span class="px-1.5 py-0.5 rounded bg-danger-surface border border-danger-line text-danger-strong text-[11px]" ' +
                    'title="This archive contains ' + (keyCount || 'private') + ' private key file(s). If it was ever shared or copied off this host, treat those keys as exposed and reissue.">contains private keys</span>';
                var restoreBadge = canRestore ? '' :
                    '<span aria-hidden="true">·</span>' +
                    '<span class="px-1.5 py-0.5 rounded bg-warning-surface border border-warning-line text-warning-strong text-[11px]" title="' + blockedReason + '">cannot restore</span>';
                return '<div class="flex items-center gap-3 px-3 py-2 rounded-lg border border-border hover:bg-hover transition-colors">' +
                    '<i class="fas fa-file-zipper text-success-fg text-sm shrink-0" aria-hidden="true"></i>' +
                    '<div class="flex-1 min-w-0">' +
                        '<div class="text-sm font-medium text-foreground truncate">' + safeFilename + '</div>' +
                        '<div class="flex items-center flex-wrap gap-x-2 gap-y-0.5 text-xs text-muted mt-0.5">' +
                            '<span>' + escapeHtml(createdDate) + '</span>' +
                            '<span aria-hidden="true">·</span>' +
                            '<span>' + size + '</span>' +
                            '<span aria-hidden="true">·</span>' +
                            '<span>' + domains + ' domains</span>' +
                            '<span aria-hidden="true">·</span>' +
                            '<span class="px-1.5 py-0.5 rounded bg-surface-2 text-[11px]">' + safeReason + '</span>' +
                            restoreBadge +
                            keyBadge +
                        '</div>' +
                    '</div>' +
                    '<div class="flex items-center gap-0.5 shrink-0">' +
                        '<button data-action="download-backup" data-backup-type="unified" data-filename="' + safeFilename + '" class="' + iconBtn + ' text-info-fg hover:bg-blue-50 dark:hover:bg-blue-900/30" title="Download backup" aria-label="Download ' + safeFilename + '"><i class="fas fa-download text-sm"></i></button>' +
                        (canRestore
                            ? '<button data-action="restore-backup" data-backup-type="unified" data-filename="' + safeFilename + '" class="' + iconBtn + ' text-success-fg hover:bg-green-50 dark:hover:bg-green-900/30" title="Restore backup" aria-label="Restore ' + safeFilename + '"><i class="fas fa-rotate-left text-sm"></i></button>'
                            : '<button disabled data-backup-type="unified" data-filename="' + safeFilename + '" class="' + iconBtn + ' text-muted opacity-40 cursor-not-allowed" title="Cannot restore: ' + blockedReason + '" aria-label="Cannot restore ' + safeFilename + ': ' + blockedReason + '"><i class="fas fa-rotate-left text-sm"></i></button>') +
                        '<button data-action="delete-backup" data-backup-type="unified" data-filename="' + safeFilename + '" class="' + iconBtn + ' text-danger-fg hover:bg-red-50 dark:hover:bg-red-900/30" title="Delete backup" aria-label="Delete ' + safeFilename + '"><i class="fas fa-trash text-sm"></i></button>' +
                    '</div>' +
                '</div>';
            }

            function bindActions() {
                unifiedBackupList.querySelectorAll('button[data-action]').forEach(function (btn) {
                    btn.addEventListener('click', function () {
                        var bType = btn.dataset.backupType;
                        var filename = btn.dataset.filename;
                        switch (btn.dataset.action) {
                            case 'download-backup': downloadBackup(bType, filename); break;
                            case 'restore-backup': restoreBackup(bType, filename); break;
                            case 'delete-backup': deleteBackup(bType, filename); break;
                        }
                    });
                });
            }

            function renderUnified() {
                var html = all.slice(0, visible).map(backupRow).join('');
                var remaining = all.length - visible;
                if (remaining > 0) {
                    html += '<button type="button" id="backup-show-more" class="w-full mt-1 px-3 py-2 text-xs font-medium text-info-fg border border-border rounded-lg hover:bg-hover transition-colors">' +
                        '<i class="fas fa-chevron-down mr-1.5"></i>Show ' + Math.min(8, remaining) + ' more (' + remaining + ' hidden)' +
                    '</button>';
                }
                unifiedBackupList.innerHTML = html;
                bindActions();
                var more = document.getElementById('backup-show-more');
                if (more) more.addEventListener('click', function () { visible += 8; renderUnified(); });
            }

            renderUnified();
        }
    }

    // =============================================
    // Download backup
    // =============================================

    function downloadBackup(type, filename) {
        // Only support unified backups
        if (type !== 'unified') {
            showMessage('Only unified backup download is supported.', 'error');
            return;
        }

        addDebugLog('Downloading backup: ' + filename, 'info');

        fetch('/api/backups/download/unified/' + filename, {
            method: 'GET',
            headers: {}
        })
            .then(function (response) {
                if (!response.ok) {
                    return response.text().then(function (errorText) {
                        throw new Error('HTTP ' + response.status + ': ' + errorText);
                    });
                }
                return response.blob();
            })
            .then(function (blob) {
                // Create download link
                var url = window.URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);

                addDebugLog('Backup downloaded: ' + filename, 'info');
                showMessage('Backup downloaded: ' + filename, 'success');
            })
            .catch(function (error) {
                addDebugLog('Error downloading backup: ' + error.message, 'error');
                showMessage('Error downloading backup: ' + error.message, 'error');
            });
    }

    // =============================================
    // Restore backup
    // =============================================

    function restoreBackup(type, filename) {
        // Only support unified backups
        if (type !== 'unified') {
            showMessage('Only unified backup restore is supported.', 'error');
            return;
        }

        CertMate.confirm('Are you sure you want to restore from "' + filename + '"? This will atomically restore both settings and certificates, creating a backup of your current configuration first.', 'Restore Backup').then(function (confirmed) {
            if (!confirmed) return;

            addDebugLog('Restoring from backup: ' + filename, 'info');

            return fetch('/api/backups/restore/unified', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filename: filename,
                    create_backup_before_restore: true
                })
            })
                .then(function (response) {
                    if (!response.ok) {
                        return response.text().then(function (errorData) {
                            var parsed = null;
                            try { parsed = errorData ? JSON.parse(errorData) : null; } catch (e) { /* not JSON */ }
                            var err = new Error('HTTP ' + response.status + ': ' + (parsed && parsed.error ? parsed.error : errorData));
                            err.responseStatus = response.status;
                            err.responseBody = parsed;
                            throw err;
                        });
                    }
                    return response.json();
                })
                .then(function (result) {
                    addDebugLog('Backup restored successfully from: ' + filename, 'info');

                    var successMessage = result.message || 'Backup restored successfully!';
                    if (result.pre_restore_backup) {
                        successMessage += '\n\nA backup of the previous state was created: ' + result.pre_restore_backup;
                    }

                    // Show immediate success message
                    showMessage(successMessage, 'success');

                    // Try to reload the settings data and refresh the UI
                    return loadSettings(true)
                        .then(function () {
                            return refreshBackupList();
                        })
                        .then(function () {
                            addDebugLog('Settings reloaded successfully after restore', 'info');
                            showMessage('Backup restored and configuration reloaded successfully!', 'success');
                        })
                        .catch(function (reloadError) {
                            addDebugLog('Settings reload failed after successful restore: ' + reloadError.message, 'warn');
                            showMessage('Backup restored successfully! Please refresh the page to see all changes.', 'success');

                            // Fallback to page reload after a delay
                            setTimeout(function () {
                                addDebugLog('Auto-refreshing page after restore...', 'info');
                                window.location.reload();
                            }, 3000);
                        });
                });
        })
            .catch(function (error) {
                addDebugLog('Error during backup restore: ' + error.message, 'error');
                showMessage('Error restoring backup: ' + error.message, 'error', {
                    errorContext: {
                        endpoint: 'POST /api/backups/restore/unified',
                        status: error.responseStatus || 0,
                        code: error.responseBody && error.responseBody.code,
                        message: (error.responseBody && error.responseBody.error) || error.message,
                        hint: error.responseBody && error.responseBody.hint
                    }
                });
            });
    }

    // =============================================
    // Delete backup
    // =============================================

    function deleteBackup(type, filename) {
        // Only support unified backups
        if (type !== 'unified') {
            showMessage('Only unified backup deletion is supported.', 'error');
            return;
        }

        CertMate.confirm('Are you sure you want to delete the backup "' + filename + '"? This action cannot be undone.', 'Delete Backup').then(function (confirmed) {
            if (!confirmed) return;

            addDebugLog('Deleting backup: ' + filename, 'info');

            return fetch('/api/backups/delete/unified/' + filename, {
                method: 'DELETE',
                headers: {}
            })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP error! status: ' + response.status);
                    }
                    return response.json();
                })
                .then(function (result) {
                    if (result.message) {
                        addDebugLog('Backup deleted successfully: ' + filename, 'info');
                        showMessage('Backup "' + filename + '" deleted successfully!', 'success');

                        // Refresh backup list
                        return refreshBackupList();
                    } else {
                        throw new Error(result.error || 'Failed to delete backup');
                    }
                });
        })
            .catch(function (error) {
                addDebugLog('Error deleting backup: ' + error.message, 'error');
                showMessage('Error deleting backup: ' + error.message, 'error');
            });
    }

    // =============================================
    // CA PROVIDER MANAGEMENT FUNCTIONS
    // =============================================

    // Public ACME CAs usable through the generic Private CA entry.
    // Adding a new one (e.g. another European CA exposing ACME) is a
    // single entry here plus an <option> in settings_ca.html.
    var PRIVATE_CA_PRESETS = {
        'actalis': {
            acme_url: 'https://acme-api.actalis.com/acme/directory',
            hint: 'Actalis enforces External Account Binding: fill in the EAB Key ID and HMAC Key from your Actalis customer area (Manage with ACME). Leave the CA Certificate empty - Actalis roots are publicly trusted. Tip: Actalis also has a dedicated entry in the CA dropdown above.'
        }
    };

    function applyPrivateCaPreset() {
        var select = document.getElementById('private-ca-preset');
        if (!select) return;
        var preset = PRIVATE_CA_PRESETS[select.value];
        var urlField = document.getElementById('private-ca-acme-url');
        if (preset && urlField) {
            urlField.value = preset.acme_url;
        }
        var hintElement = document.getElementById('private-ca-preset-hint');
        if (hintElement) {
            hintElement.textContent = preset ? preset.hint : '';
        }
    }

    // Reflect a saved directory URL back onto the preset select so the
    // form reopens showing "Actalis" instead of a bare URL.
    function syncPrivateCaPresetFromUrl(acmeUrl) {
        var select = document.getElementById('private-ca-preset');
        if (!select) return;
        var matched = '';
        Object.keys(PRIVATE_CA_PRESETS).forEach(function (key) {
            if (PRIVATE_CA_PRESETS[key].acme_url === acmeUrl) {
                matched = key;
            }
        });
        select.value = matched;
        var hintElement = document.getElementById('private-ca-preset-hint');
        if (hintElement) {
            hintElement.textContent = matched ? PRIVATE_CA_PRESETS[matched].hint : '';
        }
    }

    function toggleCAProviderConfig() {
        var caProvider = editingCAProvider;

        // Map CA provider values to config IDs
        var caProviderToConfigId = {
            'letsencrypt': 'letsencrypt-config',
            'letsencrypt_staging': 'letsencrypt-staging-config',
            'zerossl': 'zerossl-config',
            // The DNS tab already owns id="google-config" for the Google DNS
            // provider; the CA panel uses a distinct id so getElementById does
            // not collide and leave the CA panel hidden (issue #226).
            'google': 'google-ca-config',
            'actalis': 'actalis-config',
            'digicert': 'digicert-config',
            'sectigo': 'sectigo-config',
            'sslcom': 'sslcom-config',
            'private_ca': 'private-ca-config'
        };

        // Hide all CA configuration panels and disable their required fields
        var caConfigs = ['letsencrypt-config', 'letsencrypt-staging-config', 'zerossl-config', 'google-ca-config', 'actalis-config', 'digicert-config', 'sectigo-config', 'sslcom-config', 'private-ca-config'];
        caConfigs.forEach(function (configId) {
            var element = document.getElementById(configId);
            if (element) {
                element.style.display = 'none';
                // Disable required validation for hidden fields
                var requiredFields = element.querySelectorAll('[required]');
                requiredFields.forEach(function (field) {
                    field.removeAttribute('required');
                    field.dataset.wasRequired = 'true';
                });
            }
        });

        // Show the selected CA configuration panel and re-enable required fields
        var selectedConfigId = caProviderToConfigId[caProvider] || caProvider + '-config';
        var selectedConfig = document.getElementById(selectedConfigId);
        if (selectedConfig) {
            selectedConfig.style.display = 'block';
            // Re-enable required validation for visible fields
            var requiredFields = selectedConfig.querySelectorAll('[data-was-required="true"]');
            requiredFields.forEach(function (field) {
                field.setAttribute('required', '');
            });
        }

        // A result belongs to the account it was checked for.
        showCATestResult(null);

        // Update hint text based on selected CA
        var hintElement = document.getElementById('ca-test-hint');
        if (hintElement) {
            switch (caProvider) {
                case 'letsencrypt':
                    hintElement.textContent = 'Enter your email address and test Let\'s Encrypt connection';
                    break;
                case 'letsencrypt_staging':
                    hintElement.textContent = 'Staging issues untrusted test certificates. Email falls back to the Let\'s Encrypt one when left empty';
                    break;
                case 'zerossl':
                    hintElement.textContent = 'Enter EAB credentials and email, then test ZeroSSL connection';
                    break;
                case 'google':
                    hintElement.textContent = 'Enter EAB credentials and email, then test Google Trust Services connection';
                    break;
                case 'actalis':
                    hintElement.textContent = 'Enter EAB credentials and email, then test Actalis connection';
                    break;
                case 'digicert':
                    hintElement.textContent = 'Enter ACME URL, EAB credentials, and email, then test DigiCert connection';
                    break;
                case 'sectigo':
                    hintElement.textContent = 'Copy the ACME directory URL and EAB credentials from your Sectigo SCM ACME account';
                    break;
                case 'sslcom':
                    hintElement.textContent = 'Enter EAB credentials and email, then test SSL.com connection';
                    break;
                case 'private_ca':
                    hintElement.textContent = 'Enter your ACME directory URL and email, then test Private CA connection';
                    break;
                default:
                    hintElement.textContent = 'Select a CA provider and fill in required fields, then test the connection';
            }
        }
    }

    function renderConfiguredCAProviders() {
        var list = document.getElementById('configured-ca-list');
        var types = document.getElementById('add-ca-type');
        list.replaceChildren();
        var allUsable = true;
        configuredCAProviders.forEach(function (provider) {
            var config = ((currentSettings.ca_providers || {})[provider]) || {};
            var accounts = config.accounts || {default: config};
            Object.keys(accounts).forEach(function (accountId) {
                var account = accounts[accountId] || {};
                var row = document.createElement('div');
                row.className = 'flex flex-wrap items-center gap-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg px-4 py-3 border border-border';
                var option = Array.from(types.options).find(function (item) { return item.value === provider; });
                var name = document.createElement('span');
                name.className = 'flex-1 text-sm font-medium text-foreground min-w-40';
                name.textContent = (option ? option.textContent : provider) + ' - ' +
                    (account.name || (accountId === 'default' ? 'Default account' : accountId));
                row.appendChild(name);
                // Listed is not usable: an account the create form would
                // refuse says what it lacks, and opens to add it.
                var missing = CertMate.caAccountMissing(provider, account, currentSettings);
                var check = caAccountChecks === null ? { outcome: 'unknown' }
                    : ((caAccountChecks[provider] || {})[accountId] || null);
                var checkLine = lastCheckElement(check);
                checkLine.classList.remove('mt-1');
                checkLine.classList.add('w-full', 'order-last');
                row.appendChild(checkLine);
                if (missing.length) {
                    allUsable = false;
                    var lacks = document.createElement('span');
                    lacks.className = 'text-xs font-medium text-warning-fg';
                    lacks.textContent = 'No ' + CertMate.caAccountMissingText(missing, 'noun', 'or') +
                        ': cannot issue';
                    row.appendChild(lacks);
                    var complete = document.createElement('button');
                    complete.type = 'button';
                    complete.textContent = missing.length === 1 && missing[0] === 'email' ? 'Add email' : 'Complete account';
                    complete.className = 'btn btn-sm bg-warning-surface text-warning-fg hover:bg-hover';
                    complete.addEventListener('click', function () { openCAAccountModal(provider, accountId); });
                    row.appendChild(complete);
                }
                var selectedAccount = ((currentSettings.default_ca_accounts || {})[provider]) ||
                    (accounts.default ? 'default' : Object.keys(accounts)[0]);
                var perCA = selectedAccount === accountId;
                var globalDefault = document.getElementById('default-ca').value === provider && perCA;
                var label = document.createElement('label');
                label.className = 'flex items-center gap-1 text-xs text-muted cursor-pointer';
                var radio = document.createElement('input');
                radio.type = 'radio';
                radio.name = 'ca-default-' + provider;
                radio.checked = perCA;
                radio.addEventListener('change', function () {
                    setDefaultCAAccount(provider, accountId, account, false);
                });
                label.appendChild(radio);
                label.appendChild(document.createTextNode('Default for this CA'));
                row.appendChild(label);
                var global = document.createElement('button');
                global.type = 'button';
                global.textContent = globalDefault ? 'Global default' : 'Make global default';
                // The global default is a state, not an unavailable action:
                // tinted and not dimmed, though it cannot be pressed.
                global.className = globalDefault
                    ? 'btn btn-sm bg-info-surface text-info-fg disabled:opacity-100 disabled:cursor-default'
                    : ACCOUNT_ACTION;
                global.disabled = globalDefault;
                global.addEventListener('click', function () {
                    setDefaultCAAccount(provider, accountId, account, true);
                });
                row.appendChild(global);
                var checkButton = document.createElement('button');
                checkButton.type = 'button';
                checkButton.innerHTML = accountButtonHtml('check', 'Check credentials');
                checkButton.className = ACCOUNT_ACTION;
                checkButton.addEventListener('click', function () {
                    checkCAAccount(provider, accountId, checkButton);
                });
                row.appendChild(checkButton);
                var edit = document.createElement('button');
                edit.type = 'button';
                edit.innerHTML = accountButtonHtml('edit', 'Edit');
                edit.className = ACCOUNT_ACTION;
                edit.addEventListener('click', function () { openCAAccountModal(provider, accountId); });
                row.appendChild(edit);
                var remove = document.createElement('button');
                remove.type = 'button';
                remove.innerHTML = accountButtonHtml('delete', 'Delete');
                // .btn dims a disabled button and shows it cannot be pressed.
                remove.className = ACCOUNT_DELETE;
                remove.disabled = globalDefault;
                remove.title = globalDefault ? 'Choose another global default CA account before deleting this one' : '';
                remove.addEventListener('click', function () { deleteCAAccount(provider, accountId); });
                row.appendChild(remove);
                list.appendChild(row);
            });
        });
        // The heading is never green (P39): a CA check proves that the
        // directory answers, not that an account works. A warning when an
        // account cannot issue or its last check failed; otherwise no colour.
        var anyFailed = configuredCAProviders.some(function (provider) {
            return Object.keys((caAccountChecks || {})[provider] || {}).some(function (id) {
                return lastCheckOutcome(caAccountChecks[provider][id]) === 'failed';
            });
        });
        var status = document.querySelector('[data-ca-accounts-status]');
        if (status) {
            status.className = (!allUsable || anyFailed)
                ? 'fas fa-fw fa-exclamation-triangle mr-2 text-warning-fg'
                : 'fas fa-fw fa-info-circle mr-2 text-muted';
        }
    }

    // The last checks of the CA accounts, from the server. Never rejects: a
    // failed read draws every account's last check as not known, not green.
    function loadCAAccountChecks() {
        return fetch('/api/web/settings/ca-account-checks', { headers: API_HEADERS })
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(function (list) {
                caAccountChecks = {};
                (Array.isArray(list) ? list : []).forEach(function (entry) {
                    if (!entry || !entry.provider) return;
                    (caAccountChecks[entry.provider] = caAccountChecks[entry.provider] || {})[entry.account_id] =
                        entry.last_check || null;
                });
            })
            .catch(function (error) {
                caAccountChecks = null;
                addDebugLog('Could not read the CA account checks: ' + error.message, 'error');
            })
            .then(function () { renderConfiguredCAProviders(); });
    }

    function checkCAAccount(provider, accountId, button) {
        if (button) button.disabled = true;
        return fetch('/api/web/settings/ca-providers/' + encodeURIComponent(provider) + '/accounts/' +
            encodeURIComponent(accountId) + '/check', { method: 'POST', headers: API_HEADERS })
            .then(readJSON)
            .then(function (answer) {
                if (!answer.response.ok || !answer.body.last_check) {
                    throw new Error(answer.body.error || ('HTTP ' + answer.response.status));
                }
                var outcome = lastCheckOutcome(answer.body.last_check);
                showMessage(accountId + ': ' + lastCheckText(answer.body.last_check),
                    outcome === 'passed' ? 'success' : outcome === 'failed' ? 'error' : 'info');
                // After a failed read the other accounts' checks are not known
                // here: read them all again rather than draw them as never checked.
                if (caAccountChecks === null) return loadCAAccountChecks();
                (caAccountChecks[provider] = caAccountChecks[provider] || {})[accountId] = answer.body.last_check;
                renderConfiguredCAProviders();
            })
            .catch(function (error) {
                showMessage('Could not check the CA account: ' + error.message, 'error');
            })
            .then(function () { if (button && button.isConnected) button.disabled = false; });
    }

    function currentCAAccountConfig() {
        var config = ((currentSettings.ca_providers || {})[editingCAProvider]) || {};
        return (config.accounts || {})[editingCAAccount] ||
            (editingCAAccount === 'default' ? config : {});
    }

    function fillCAAccountFields(provider, config) {
        var fields = {
            letsencrypt: {email: 'letsencrypt-email'},
            letsencrypt_staging: {email: 'letsencrypt-staging-email'},
            zerossl: {email: 'zerossl-email', eab_kid: 'zerossl-eab-kid', eab_hmac: 'zerossl-eab-hmac'},
            google: {email: 'google-email', eab_kid: 'google-eab-kid', eab_hmac: 'google-eab-hmac'},
            actalis: {email: 'actalis-email', eab_kid: 'actalis-eab-kid', eab_hmac: 'actalis-eab-hmac'},
            digicert: {email: 'digicert-email', acme_url: 'digicert-acme-url', eab_kid: 'digicert-eab-kid', eab_hmac: 'digicert-eab-hmac'},
            sectigo: {email: 'sectigo-email', acme_url: 'sectigo-acme-url', eab_kid: 'sectigo-eab-kid', eab_hmac: 'sectigo-eab-hmac'},
            sslcom: {email: 'sslcom-email', eab_kid: 'sslcom-eab-kid', eab_hmac: 'sslcom-eab-hmac'},
            private_ca: {email: 'private-ca-email', acme_url: 'private-ca-acme-url', ca_cert: 'private-ca-cert', eab_kid: 'private-ca-eab-kid', eab_hmac: 'private-ca-eab-hmac'}
        };
        Object.keys(fields[provider] || {}).forEach(function (key) {
            var value = config[key] || (key === 'eab_kid' ? config.eab_key_id : '');
            document.getElementById(fields[provider][key]).value = key === 'eab_hmac' ? '' : (value || '');
        });
    }

    function openCAAccountModal(provider, accountId) {
        editingCAProvider = provider || '';
        editingCAAccount = accountId || '';
        var type = document.getElementById('add-ca-type');
        type.value = editingCAProvider;
        type.disabled = Boolean(accountId);
        var nameField = document.getElementById('ca-account-name');
        nameField.value = editingCAAccount;
        nameField.disabled = Boolean(accountId);
        nameField.classList.toggle('opacity-60', Boolean(accountId));
        nameField.classList.toggle('cursor-not-allowed', Boolean(accountId));
        nameField.classList.toggle('bg-surface-2', Boolean(accountId));
        if (editingCAProvider) {
            var saved = currentCAAccountConfig();
            if (editingCAProvider === 'letsencrypt' && editingCAAccount === 'default' && !saved.email) {
                saved = {email: currentSettings.email};
            }
            fillCAAccountFields(editingCAProvider, saved);
        }
        var profileField = document.getElementById('ca-account-acme-profile');
        if (profileField) profileField.value = (editingCAProvider && currentCAAccountConfig().acme_profile) || '';
        toggleCAProviderConfig();
        document.getElementById('caAccountModal').classList.remove('hidden');
    }

    function selectCAAccountType() {
        editingCAProvider = document.getElementById('add-ca-type').value;
        fillCAAccountFields(editingCAProvider, {});
        toggleCAProviderConfig();
    }

    function saveCAAccount() {
        var provider = document.getElementById('add-ca-type').value;
        var name = document.getElementById('ca-account-name').value.trim();
        if (!provider || !name) { showMessage('Choose a CA and enter an account name', 'error'); return; }
        if (!editingCAAccount && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
            showMessage('Account name: use letters, digits, dots, dashes and underscores', 'error');
            return;
        }
        editingCAProvider = provider;
        var config = collectCAProviderSettings()[provider];
        config.name = name;
        // The account's default ACME profile (#395); '' clears it.
        var profileField = document.getElementById('ca-account-acme-profile');
        if (profileField) config.acme_profile = profileField.value;
        // The save checks the account first (P39): a failed check asks
        // before anything is saved.
        saveWithCheck('/api/web/settings/ca-providers/' + encodeURIComponent(provider) +
            '/accounts/' + encodeURIComponent(name) + (editingCAAccount ? '' : '?create=1'), {
            method: 'POST', headers: API_HEADERS, body: JSON.stringify(config)
        }).then(function (answer) {
            if (!answer) return; // Cancelled after a failed check: nothing saved, the dialog stays open.
            if (!answer.response.ok) throw new Error(answer.body.error || 'Unable to save CA account');
            document.getElementById('caAccountModal').classList.add('hidden');
            var said = savedWithCheckMessage('CA account', answer.body.last_check);
            showMessage(said.text, said.type);
            return loadSettings();
        }).catch(function (error) { showMessage(error.message, 'error'); });
    }

    function setDefaultCAAccount(provider, accountId, account, globalDefault) {
        var defaults = Object.assign({}, currentSettings.default_ca_accounts || {});
        defaults[provider] = accountId;
        var changes = {default_ca_accounts: defaults};
        if (globalDefault) changes.default_ca = provider;
        if (globalDefault || document.getElementById('default-ca').value === provider) {
            changes.email = account.email || currentSettings.email || '';
        }
        fetch('/api/web/settings', {method: 'POST', headers: API_HEADERS,
            body: JSON.stringify(changes)
        }).then(function (response) {
            if (!response.ok) throw new Error('Unable to change the default CA account');
            return loadSettings();
        }).catch(function (error) { showMessage(error.message, 'error'); });
    }

    function deleteCAAccount(provider, accountId) {
        CertMate.confirm('Delete the ' + provider + ' account ' + accountId + '?', 'Delete CA Account',
            { confirmText: 'Delete' }).then(function (confirmed) {
            if (!confirmed) return;
            return fetch('/api/web/settings/ca-providers/' + encodeURIComponent(provider) +
                '/accounts/' + encodeURIComponent(accountId), {
                method: 'DELETE', headers: API_HEADERS
            }).then(function (response) {
                return response.json().then(function (body) {
                    if (!response.ok) throw new Error(body.error || 'Unable to delete CA account');
                    return loadSettings();
                });
            }).catch(function (error) { showMessage(error.message, 'error'); });
        });
    }

    // =============================================
    // Test CA Provider
    // =============================================

    // The result of "Check configuration", written in the dialog as well as
    // in a toast: it was only a toast, and once that went the dialog said
    // nothing about the check (P34). `ok` null clears it.
    function showCATestResult(ok, text) {
        var el = document.getElementById('ca-test-result');
        if (!el) return;
        el.classList.remove('text-success-fg', 'text-danger-fg');
        if (ok === null) {
            el.textContent = '';
            el.classList.add('hidden');
            return;
        }
        el.textContent = text;
        el.classList.add(ok ? 'text-success-fg' : 'text-danger-fg');
        el.classList.remove('hidden');
    }

    function testCAProvider() {
        var caProvider = editingCAProvider;
        var config = {};
        var missingFields = [];

        if (caProvider === 'letsencrypt') {
            var leEmail = document.getElementById('letsencrypt-email').value;
            if (!leEmail.trim()) {
                missingFields.push('Email');
            }
            config = {
                email: leEmail
            };
        } else if (caProvider === 'letsencrypt_staging') {
            // Mirror the backend aliasing: staging falls back to the
            // Let's Encrypt account email when its own field is empty.
            var lsEmail = document.getElementById('letsencrypt-staging-email').value ||
                document.getElementById('letsencrypt-email').value;
            if (!lsEmail.trim()) {
                missingFields.push('Email');
            }
            config = {
                email: lsEmail
            };
        } else if (caProvider === 'zerossl') {
            var zsEabKid = document.getElementById('zerossl-eab-kid').value;
            var zsEabHmac = document.getElementById('zerossl-eab-hmac').value;
            var zsEmail = document.getElementById('zerossl-email').value;
            if (!zsEabKid.trim()) missingFields.push('EAB Key ID');
            if (!zsEabHmac.trim()) missingFields.push('EAB HMAC Key');
            if (!zsEmail.trim()) missingFields.push('Email');
            config = { eab_key_id: zsEabKid, eab_hmac_key: zsEabHmac, email: zsEmail };
        } else if (caProvider === 'google') {
            var gEabKid = document.getElementById('google-eab-kid').value;
            var gEabHmac = document.getElementById('google-eab-hmac').value;
            var gEmail = document.getElementById('google-email').value;
            if (!gEabKid.trim()) missingFields.push('EAB Key ID');
            if (!gEabHmac.trim()) missingFields.push('EAB HMAC Key');
            if (!gEmail.trim()) missingFields.push('Email');
            config = { eab_key_id: gEabKid, eab_hmac_key: gEabHmac, email: gEmail };
        } else if (caProvider === 'actalis') {
            var acEabKid = document.getElementById('actalis-eab-kid').value;
            var acEabHmac = document.getElementById('actalis-eab-hmac').value;
            var acEmail = document.getElementById('actalis-email').value;
            if (!acEabKid.trim()) missingFields.push('EAB Key ID');
            if (!acEabHmac.trim()) missingFields.push('EAB HMAC Key');
            if (!acEmail.trim()) missingFields.push('Email');
            config = { eab_kid: acEabKid, eab_hmac: acEabHmac, email: acEmail };
        } else if (caProvider === 'sslcom') {
            var sEabKid = document.getElementById('sslcom-eab-kid').value;
            var sEabHmac = document.getElementById('sslcom-eab-hmac').value;
            var sEmail = document.getElementById('sslcom-email').value;
            if (!sEabKid.trim()) missingFields.push('EAB Key ID');
            if (!sEabHmac.trim()) missingFields.push('EAB HMAC Key');
            if (!sEmail.trim()) missingFields.push('Email');
            config = { eab_key_id: sEabKid, eab_hmac_key: sEabHmac, email: sEmail };
        } else if (caProvider === 'digicert') {
            var dcAcmeUrl = document.getElementById('digicert-acme-url').value;
            var dcEabKid = document.getElementById('digicert-eab-kid').value;
            var dcEabHmac = document.getElementById('digicert-eab-hmac').value;
            var dcEmail = document.getElementById('digicert-email').value;

            if (!dcAcmeUrl.trim()) missingFields.push('ACME URL');
            if (!dcEabKid.trim()) missingFields.push('EAB Key ID');
            if (!dcEabHmac.trim()) missingFields.push('EAB HMAC Key');
            if (!dcEmail.trim()) missingFields.push('Email');

            config = {
                acme_url: dcAcmeUrl,
                eab_kid: dcEabKid,
                eab_hmac: dcEabHmac,
                email: dcEmail
            };
        } else if (caProvider === 'sectigo') {
            config = {
                acme_url: document.getElementById('sectigo-acme-url').value,
                eab_kid: document.getElementById('sectigo-eab-kid').value,
                eab_hmac: document.getElementById('sectigo-eab-hmac').value,
                email: document.getElementById('sectigo-email').value
            };
            if (!config.acme_url.trim()) missingFields.push('ACME Directory URL');
            if (!config.eab_kid.trim()) missingFields.push('EAB Key ID');
            if (!config.eab_hmac.trim()) config.eab_hmac = currentCAAccountConfig().eab_hmac || '';
            if (!config.eab_hmac.trim()) missingFields.push('EAB HMAC Key');
            if (!config.email.trim()) missingFields.push('Email');
        } else if (caProvider === 'private_ca') {
            var pcAcmeUrl = document.getElementById('private-ca-acme-url').value;
            var pcEmail = document.getElementById('private-ca-email').value;

            if (!pcAcmeUrl.trim()) missingFields.push('ACME URL');
            if (!pcEmail.trim()) missingFields.push('Email');

            config = {
                acme_url: pcAcmeUrl,
                ca_cert: document.getElementById('private-ca-cert').value,
                eab_kid: document.getElementById('private-ca-eab-kid').value,
                eab_hmac: document.getElementById('private-ca-eab-hmac').value,
                email: pcEmail
            };
        }

        // Validate required fields
        if (missingFields.length > 0) {
            showMessage('Please fill in the following required fields: ' + missingFields.join(', '), 'error');
            return;
        }

        // Show loading state
        var testButton = document.querySelector('button[data-click="testCAProvider"]');
        if (!testButton) return;
        var originalText = testButton.innerHTML;
        testButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Testing...';
        testButton.disabled = true;
        showCATestResult(null);

        fetch('/api/settings/test-ca-provider', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ca_provider: caProvider,
                config: config
            })
        })
            .then(function (response) {
                return response.json().then(function (result) {
                    if (response.ok && result.success) {
                        showMessage('CA connection test successful! ' + result.message, 'success');
                        showCATestResult(true, 'Check passed: ' + result.message);
                    } else {
                        var errorMsg = result.message || result.error || 'Unknown error occurred';
                        showMessage('CA connection test failed: ' + errorMsg, 'error');
                        showCATestResult(false, 'Check failed: ' + errorMsg);
                    }
                });
            })
            .catch(function (error) {
                console.error('Error testing CA provider:', error);
                showMessage('Error testing CA provider connection. Please check your network connection.', 'error');
                showCATestResult(false, 'Check failed: the request did not reach CertMate. Please check your network connection.');
            })
            .then(function () {
                // finally block equivalent - restore button state
                testButton.innerHTML = originalText;
                testButton.disabled = false;
            });
    }

    // =============================================
    // STORAGE BACKEND MANAGEMENT FUNCTIONS
    // =============================================

    // Mirror the cert-form behaviour for Settings → Default Certificate Key:
    // show the RSA key-size picker only when the operator picked RSA, the
    // ECDSA curve picker only when they picked ECDSA. Keeping both visible
    // would let the form post a contradictory pair (e.g. type=rsa with a
    // curve set), which save_settings would reject.
    function toggleDefaultKeyOptions() {
        var keyType = (document.getElementById('default_key_type') || {}).value;
        var sizeEl = document.getElementById('default_key_size_container');
        var curveEl = document.getElementById('default_elliptic_curve_container');
        if (sizeEl) sizeEl.style.display = (keyType === 'ecdsa') ? 'none' : '';
        if (curveEl) curveEl.style.display = (keyType === 'ecdsa') ? '' : 'none';
    }

    function toggleStorageBackendConfig() {
        var backend = document.getElementById('storage-backend').value;
        var configs = document.querySelectorAll('.storage-config');

        // Hide all configuration panels
        configs.forEach(function (config) {
            config.style.display = 'none';
        });

        // Map backend names to their corresponding config div IDs
        var backendToConfigId = {
            'local_filesystem': 'storage-local-config',
            'azure_keyvault': 'storage-azure-config',
            'aws_secrets_manager': 'storage-aws-config',
            'hashicorp_vault': 'storage-vault-config',
            'infisical': 'storage-infisical-config',
            's3_compatible': 'storage-s3-config'
        };

        // Show the selected configuration panel
        var configId = backendToConfigId[backend];
        if (configId) {
            var selectedConfig = document.getElementById(configId);
            if (selectedConfig) {
                selectedConfig.style.display = 'block';
            }
        }

        if (typeof toggleAzureBackfillRow === 'function') {
            toggleAzureBackfillRow();
        }
        toggleAWSAuthMode();
        toggleS3AuthMode();
    }

    function toggleAWSAuthMode() {
        var keys = document.getElementById('aws-key-fields');
        var mode = document.getElementById('aws-auth-mode');
        if (keys && mode) keys.style.display = mode.value === 'iam_role' ? 'none' : '';
    }

    function toggleS3AuthMode() {
        var keys = document.getElementById('s3-key-fields');
        var mode = document.getElementById('s3-auth-mode');
        if (keys && mode) keys.style.display = mode.value === 'iam_role' ? 'none' : '';
    }

    function testStorageBackend() {
        var backend = document.getElementById('storage-backend').value;
        var config = getStorageBackendConfig(backend);

        if (!validateStorageConfig(backend, config)) {
            showMessage('Please fill in all required fields for the selected storage backend.', 'error');
            return;
        }

        showMessage('Testing storage backend connection...', 'info');

        var requestData = {
            backend: backend,
            config: config
        };

        fetch('/api/storage/test', {
            method: 'POST',
            headers: API_HEADERS,
            body: JSON.stringify(requestData)
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }

                return response.json();
            })
            .then(function (data) {
                if (data.success) {
                    showMessage(data.message, 'success');
                } else if (data.message) {
                    showMessage(data.message, 'error');
                } else if (data.error) {
                    showMessage(data.error, 'error');
                } else {
                    showMessage('Unknown error occurred', 'error');
                }
            })
            .catch(function (error) {
                console.error('Storage backend test error:', error);
                showMessage('Failed to test storage backend connection: ' + error.message, 'error');
            });
    }

    function toggleAzureBackfillRow() {
        var modeSelect = document.getElementById('azure-storage-mode');
        var row = document.getElementById('azure-backfill-row');
        var backendSelect = document.getElementById('storage-backend');
        if (!row || !modeSelect) {
            return;
        }
        // Backend rejects backfill outside 'both' mode (in 'certificate'
        // mode list_certificates() never sees the legacy Secrets and the
        // walk would silently no-op). Hide the button rather than letting
        // the user click into a 400.
        var visible = backendSelect && backendSelect.value === 'azure_keyvault'
            && modeSelect.value === 'both';
        row.style.display = visible ? '' : 'none';
    }

    function backfillAzureCertificateObjects() {
        var btn = document.getElementById('azure-backfill-btn');
        var output = document.getElementById('azure-backfill-output');
        if (btn) {
            btn.disabled = true;
        }
        if (output) {
            output.classList.remove('hidden');
            output.textContent = 'Running backfill...';
        }
        showMessage('Backfilling Certificate objects...', 'info');

        fetch('/api/storage/azure-keyvault/backfill-certificates', {
            method: 'POST',
            headers: API_HEADERS
        })
            .then(function (response) { return response.json().then(function (data) { return { ok: response.ok, data: data }; }); })
            .then(function (payload) {
                var data = payload.data || {};
                if (output) {
                    var lines = [];
                    lines.push((data.message || (payload.ok ? 'Backfill finished' : 'Backfill failed')));
                    if (data.results) {
                        Object.keys(data.results).sort().forEach(function (domain) {
                            lines.push(domain + ': ' + data.results[domain]);
                        });
                    } else if (data.error) {
                        lines.push('Error: ' + data.error);
                    }
                    output.textContent = lines.join('\n');
                }
                if (data.success) {
                    showMessage(data.message || 'Backfill complete', 'success');
                } else if (data.message) {
                    showMessage(data.message, payload.ok ? 'warning' : 'error');
                } else if (data.error) {
                    showMessage(data.error, 'error');
                } else {
                    showMessage('Backfill failed', 'error');
                }
            })
            .catch(function (error) {
                console.error('Azure Key Vault backfill error:', error);
                if (output) {
                    output.textContent = 'Backfill failed: ' + error.message;
                }
                showMessage('Backfill request failed: ' + error.message, 'error');
            })
            .finally(function () {
                if (btn) {
                    btn.disabled = false;
                }
            });
    }

    function getStorageBackendConfig(backend) {
        var config = {};

        switch (backend) {
            case 'local_filesystem':
                config.cert_dir = document.getElementById('storage-cert-dir').value || 'certificates';
                break;

            case 'azure_keyvault':
                config.vault_url = document.getElementById('azure-vault-url').value;
                config.tenant_id = document.getElementById('azure-tenant-id').value;
                config.client_id = document.getElementById('azure-client-id').value;
                config.client_secret = document.getElementById('azure-client-secret').value;
                var storageModeEl = document.getElementById('azure-storage-mode');
                config.storage_mode = (storageModeEl && storageModeEl.value) || 'secrets';
                break;

            case 'aws_secrets_manager':
                config.region = document.getElementById('aws-region').value || 'us-east-1';
                config.auth_mode = document.getElementById('aws-auth-mode').value;
                config.access_key_id = config.auth_mode === 'iam_role' ? '' : document.getElementById('aws-access-key-id').value;
                config.secret_access_key = config.auth_mode === 'iam_role' ? '' : document.getElementById('aws-secret-access-key').value;
                config.assume_role_arn = document.getElementById('aws-assume-role-arn').value;
                break;

            case 'hashicorp_vault':
                config.vault_url = document.getElementById('vault-url').value;
                config.vault_token = document.getElementById('vault-token').value;
                config.mount_point = document.getElementById('vault-mount-point').value || 'secret';
                config.engine_version = document.getElementById('vault-engine-version').value;
                break;

            case 'infisical':
                config.site_url = document.getElementById('infisical-site-url').value || 'https://app.infisical.com';
                config.client_id = document.getElementById('infisical-client-id').value;
                config.client_secret = document.getElementById('infisical-client-secret').value;
                config.project_id = document.getElementById('infisical-project-id').value;
                config.environment = document.getElementById('infisical-environment').value || 'prod';
                break;

            case 's3_compatible':
                config.endpoint_url = document.getElementById('s3-endpoint-url').value;
                config.bucket = document.getElementById('s3-bucket').value;
                config.auth_mode = document.getElementById('s3-auth-mode').value;
                config.access_key_id = config.auth_mode === 'iam_role' ? '' : document.getElementById('s3-access-key-id').value;
                config.secret_access_key = config.auth_mode === 'iam_role' ? '' : document.getElementById('s3-secret-access-key').value;
                config.assume_role_arn = document.getElementById('s3-assume-role-arn').value;
                config.region = document.getElementById('s3-region').value || 'us-east-1';
                config.prefix = document.getElementById('s3-prefix').value || 'certmate/certificates';
                break;
        }

        return config;
    }

    // What the settings answer said about storage when the page loaded, secrets masked. A
    // secret field the page left empty is still configured when this has it for the same
    // backend (#1424): the page never fills a saved secret back in, and Test, Migrate and
    // Save all read an empty secret as "use the stored one".
    var savedStorageConfig = {};

    function savedSecret(backend, key) {
        var block = (savedStorageConfig[backend] && typeof savedStorageConfig[backend] === 'object')
            ? savedStorageConfig[backend]
            : (savedStorageConfig.backend === backend ? savedStorageConfig : {});
        return !!(block[key] || block[key + '_file'] || block[key + '_env']);
    }

    function hasSecret(backend, config, key) {
        return !!config[key] || savedSecret(backend, key);
    }

    function validateStorageConfig(backend, config) {
        switch (backend) {
            case 'local_filesystem':
                return config.cert_dir && config.cert_dir.trim() !== '';

            case 'azure_keyvault':
                return config.vault_url && config.tenant_id && config.client_id && hasSecret(backend, config, 'client_secret');

            case 'aws_secrets_manager':
                return config.auth_mode === 'iam_role' || (hasSecret(backend, config, 'access_key_id') && hasSecret(backend, config, 'secret_access_key'));

            case 'hashicorp_vault':
                return config.vault_url && hasSecret(backend, config, 'vault_token');

            case 'infisical':
                return config.client_id && hasSecret(backend, config, 'client_secret') && config.project_id;

            case 's3_compatible':
                if (!config.bucket || (config.assume_role_arn && config.endpoint_url)) return false;
                if (config.auth_mode === 'iam_role') return !config.endpoint_url;
                return hasSecret(backend, config, 'access_key_id') && hasSecret(backend, config, 'secret_access_key');

            default:
                return false;
        }
    }

    // =============================================
    // CA Provider settings load/collect
    // =============================================

    function loadCAProviderSettings(settings) {
        document.getElementById('default-ca').value = settings.default_ca || 'letsencrypt';
        configuredCAProviders = CertMate.configuredCAProviders(settings);
        // Drawn once, with the last checks: drawn first without them, each
        // row would grow by its check's line when the answer came.
        loadCAAccountChecks();
        editingCAProvider = '';
        editingCAAccount = '';
        toggleCAProviderConfig();
    }

    function loadStorageBackendSettings(settings) {
        var storageConfig = settings.certificate_storage || {};
        savedStorageConfig = storageConfig;
        var backend = storageConfig.backend || 'local_filesystem';

        // Set backend selection
        document.getElementById('storage-backend').value = backend;
        toggleStorageBackendConfig();

        // Load backend-specific configuration
        switch (backend) {
            case 'local_filesystem':
                if (storageConfig.cert_dir) {
                    document.getElementById('storage-cert-dir').value = storageConfig.cert_dir;
                }
                break;

            case 'azure_keyvault':
                // Support both nested ({azure_keyvault:{...}}) and legacy flat format
                var azureConfig = storageConfig.azure_keyvault || storageConfig;
                document.getElementById('azure-vault-url').value = azureConfig.vault_url || '';
                document.getElementById('azure-tenant-id').value = azureConfig.tenant_id || '';
                document.getElementById('azure-client-id').value = azureConfig.client_id || '';
                var storageModeSelect = document.getElementById('azure-storage-mode');
                if (storageModeSelect) {
                    storageModeSelect.value = azureConfig.storage_mode || 'secrets';
                }
                if (typeof toggleAzureBackfillRow === 'function') {
                    toggleAzureBackfillRow();
                }
                // Don't populate client_secret for security
                break;

            case 'aws_secrets_manager':
                // Support both nested ({aws_secrets_manager:{...}}) and legacy flat format
                var awsConfig = storageConfig.aws_secrets_manager || storageConfig;
                document.getElementById('aws-auth-mode').value = awsConfig.auth_mode || 'access_keys';
                document.getElementById('aws-region').value = awsConfig.region || 'us-east-1';
                document.getElementById('aws-access-key-id').value = awsConfig.access_key_id || '';
                document.getElementById('aws-assume-role-arn').value = awsConfig.assume_role_arn || '';
                toggleAWSAuthMode();
                // Don't populate secret_access_key for security
                break;

            case 'hashicorp_vault':
                // Support both nested ({hashicorp_vault:{...}}) and legacy flat format
                var vaultConfig = storageConfig.hashicorp_vault || storageConfig;
                document.getElementById('vault-url').value = vaultConfig.vault_url || '';
                document.getElementById('vault-mount-point').value = vaultConfig.mount_point || 'secret';
                document.getElementById('vault-engine-version').value = vaultConfig.engine_version || 'v2';
                // Don't populate vault_token for security
                break;

            case 'infisical':
                // Support both nested ({infisical:{...}}) and legacy flat format
                var infisicalConfig = storageConfig.infisical || storageConfig;
                document.getElementById('infisical-site-url').value = infisicalConfig.site_url || 'https://app.infisical.com';
                // The client ID is not a secret, and the settings answer sends it. Left empty, the
                // next Save of any setting wrote '' over the stored one, because only
                // secret-named fields are read as "keep" (#1424): Infisical then failed at start
                // and storage fell back to the local disk.
                document.getElementById('infisical-client-id').value = infisicalConfig.client_id || '';
                document.getElementById('infisical-project-id').value = infisicalConfig.project_id || '';
                document.getElementById('infisical-environment').value = infisicalConfig.environment || 'prod';
                // Don't populate the client secret for security
                break;

            case 's3_compatible':
                var s3Config = storageConfig.s3_compatible || storageConfig;
                document.getElementById('s3-auth-mode').value = s3Config.auth_mode || 'access_keys';
                document.getElementById('s3-endpoint-url').value = s3Config.endpoint_url || '';
                document.getElementById('s3-bucket').value = s3Config.bucket || '';
                document.getElementById('s3-region').value = s3Config.region || 'us-east-1';
                document.getElementById('s3-prefix').value = s3Config.prefix || 'certmate/certificates';
                document.getElementById('s3-assume-role-arn').value = s3Config.assume_role_arn || '';
                toggleS3AuthMode();
                // Don't populate access keys for security
                break;
        }
    }

    function collectCAProviderSettings() {
        var caProviders = {};

        // Let's Encrypt configuration. The legacy 'environment' field is
        // gone (#279): staging is the letsencrypt_staging CA entry.
        caProviders.letsencrypt = {
            email: document.getElementById('letsencrypt-email').value || ''
        };

        // Let's Encrypt (Staging) configuration
        caProviders.letsencrypt_staging = {
            email: document.getElementById('letsencrypt-staging-email').value || ''
        };

        // ZeroSSL configuration
        caProviders.zerossl = {
            eab_kid: document.getElementById('zerossl-eab-kid').value || '',
            eab_hmac: document.getElementById('zerossl-eab-hmac').value || '',
            email: document.getElementById('zerossl-email').value || ''
        };

        // Google Trust Services configuration
        caProviders.google = {
            eab_kid: document.getElementById('google-eab-kid').value || '',
            eab_hmac: document.getElementById('google-eab-hmac').value || '',
            email: document.getElementById('google-email').value || ''
        };

        // Actalis configuration
        caProviders.actalis = {
            eab_kid: document.getElementById('actalis-eab-kid').value || '',
            eab_hmac: document.getElementById('actalis-eab-hmac').value || '',
            email: document.getElementById('actalis-email').value || ''
        };

        // DigiCert configuration
        caProviders.digicert = {
            acme_url: document.getElementById('digicert-acme-url').value || 'https://one.digicert.com/mpki/api/v1/acme/v2/directory',
            eab_kid: document.getElementById('digicert-eab-kid').value || '',
            eab_hmac: document.getElementById('digicert-eab-hmac').value || '',
            email: document.getElementById('digicert-email').value || ''
        };

        caProviders.sectigo = {
            acme_url: document.getElementById('sectigo-acme-url').value || '',
            eab_kid: document.getElementById('sectigo-eab-kid').value || '',
            eab_hmac: document.getElementById('sectigo-eab-hmac').value || '',
            email: document.getElementById('sectigo-email').value || ''
        };

        // SSL.com configuration
        caProviders.sslcom = {
            eab_kid: document.getElementById('sslcom-eab-kid').value || '',
            eab_hmac: document.getElementById('sslcom-eab-hmac').value || '',
            email: document.getElementById('sslcom-email').value || ''
        };

        // Private CA configuration
        caProviders.private_ca = {
            acme_url: document.getElementById('private-ca-acme-url').value || '',
            ca_cert: document.getElementById('private-ca-cert').value || '',
            eab_kid: document.getElementById('private-ca-eab-kid').value || '',
            eab_hmac: document.getElementById('private-ca-eab-hmac').value || '',
            email: document.getElementById('private-ca-email').value || ''
        };

        return caProviders;
    }

    function collectStorageBackendSettings() {
        var backend = document.getElementById('storage-backend').value;
        var config = getStorageBackendConfig(backend);

        // Nest backend-specific config under its own key so loadStorageBackendSettings
        // can reliably read it back (e.g. storageConfig.hashicorp_vault.vault_url).
        var result = { backend: backend };
        switch (backend) {
            case 'local_filesystem':
                result.cert_dir = config.cert_dir;
                break;
            case 'azure_keyvault':
                result.azure_keyvault = config;
                break;
            case 'aws_secrets_manager':
                result.aws_secrets_manager = config;
                break;
            case 'hashicorp_vault':
                result.hashicorp_vault = config;
                break;
            case 'infisical':
                result.infisical = config;
                break;
            case 's3_compatible':
                result.s3_compatible = config;
                break;
        }
        return result;
    }

    // =============================================
    // Storage migration
    // =============================================

    // What the migration writes into the target the Settings form shows,
    // from that backend's store_certificate (modules/core/storage_backends.py):
    // the local filesystem, Infisical and Azure Key Vault secrets write each
    // file sent and leave the others; AWS Secrets Manager, HashiCorp Vault and
    // S3 write one secret or object; Azure's certificate object is imported as
    // a new version and needs a private key, and in "both" the secrets are
    // written before that import (#1511 review).
    var MIGRATION_EFFECT = {
        local_filesystem: 'Copies each certificate in the source into the local directory shown in Settings: ' +
            'its files are written over those of a certificate with the same name there, and a file the source does not have stays as it was.',
        aws_secrets_manager: 'Copies each certificate in the source into AWS Secrets Manager shown in Settings, ' +
            'as one secret, replacing a certificate with the same name there whole.',
        hashicorp_vault: 'Copies each certificate in the source into the HashiCorp Vault shown in Settings, ' +
            'as one secret, replacing a certificate with the same name there whole.',
        s3_compatible: 'Copies each certificate in the source into the S3-compatible bucket shown in Settings, ' +
            'as one object, replacing a certificate with the same name there whole.',
        infisical: 'Copies each certificate in the source into the Infisical project shown in Settings: ' +
            'each file is written as its own secret over one with the same name, and a file the source does not have stays as it was.',
        'azure_keyvault:secrets': 'Copies each certificate in the source into Azure Key Vault (secrets only) shown in Settings: ' +
            'each file is written as its own secret over one with the same name, and a file the source does not have stays as it was.',
        'azure_keyvault:certificate': 'Copies each certificate in the source into Azure Key Vault (certificate object only) shown in Settings, ' +
            'as a new version of the certificate object with the same name, built only from the certificate, chain and key the source has. ' +
            'A certificate without a private key cannot be imported: it is counted as failed and nothing is written for it.',
        'azure_keyvault:both': 'Copies each certificate in the source into Azure Key Vault (secrets and certificate object) shown in Settings: ' +
            'each file is written as its own secret over one with the same name, and a file the source does not have stays as it was; ' +
            'then a new version of the certificate object is imported. A certificate without a private key cannot be imported, and ' +
            'its secrets are written first, so it is counted as failed after being partly copied.'
    };

    function migrationEffect() {
        var backend = document.getElementById('storage-backend').value;
        if (backend === 'azure_keyvault') {
            var mode = document.getElementById('azure-storage-mode');
            backend += ':' + ((mode && mode.value) || 'secrets');
        }
        return MIGRATION_EFFECT[backend] || 'Copies each certificate in the source into the backend shown in Settings.';
    }

    function showStorageMigrationModal() {
        // Create migration modal dynamically
        var modal = document.createElement('div');
        modal.id = 'storageMigrationModal';
        modal.className = 'fixed inset-0 bg-black/50 overflow-y-auto h-full w-full z-50';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'storageMigrationModal-title');
        modal.innerHTML =
            '<div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-surface">' +
            '<div class="mt-3">' +
            '<div class="flex items-center justify-between mb-4">' +
            '<h3 id="storageMigrationModal-title" class="text-lg font-medium text-foreground">' +
            '<i class="fas fa-exchange-alt mr-2"></i>Certificate Storage Migration' +
            '</h3>' +
            '<button type="button" id="storageMigCloseBtn" class="text-muted hover:text-gray-600 dark:hover:text-gray-300">' +
            '<i class="fas fa-times"></i>' +
            '</button>' +
            '</div>' +
            '<div class="mb-4">' +
            '<p class="text-sm text-muted">' +
            'Copy certificates from the source you choose into the storage backend shown in Settings. ' +
            'Select the saved backend even when changing only its bucket or other settings.' +
            '</p>' +
            '<label for="storageMigSource" class="block text-sm text-label mt-3 mb-1">Source backend</label>' +
            '<select id="storageMigSource" class="w-full px-3 py-2 text-sm border border-border rounded bg-input text-foreground">' +
            '<option value="">Choose source backend...</option>' +
            '<option value="local_filesystem">Local filesystem</option>' +
            '</select>' +
            '<p id="storageMigSame" class="hidden mt-2 text-sm text-label" role="status">' +
            'If this source is the same location as the backend in use, there is nothing to copy: ' +
            'each certificate would be written onto itself and counted as migrated.' +
            '</p>' +
            // What POST /api/storage/migrate does: migrate_certificates reads
            // each certificate the source lists and gives it to the target's
            // store_certificate, going on after a failure and counting it. The
            // source is only read; nothing is saved. What the target writes
            // depends on it, and the dialog says it for the one the form shows.
            '<div class="mt-3 p-3 bg-warning-surface border border-warning-line rounded-md">' +
            '<div class="flex">' +
            '<i class="fas fa-exclamation-triangle text-warning-fg mt-0.5 mr-2" aria-hidden="true"></i>' +
            '<div class="text-sm text-warning-strong">' +
            migrationEffect() + ' ' +
            'A certificate that cannot be copied is counted as failed in the result, and the migration goes on with the others. ' +
            'The source keeps its copies until you remove them. ' +
            'Nothing in Settings changes: CertMate keeps using the saved storage settings until you save them.' +
            '</div>' +
            '</div>' +
            '</div>' +
            '</div>' +
            '<div class="flex justify-end space-x-3">' +
            '<button type="button" id="storageMigCancelBtn" class="btn btn-secondary">' +
            'Cancel' +
            '</button>' +
            // Amber, like the button that opened this: it is the risky step.
            '<button type="button" id="storageMigStartBtn" class="btn btn-warning">' +
            '<i class="fas fa-play mr-1"></i>Start Migration' +
            '</button>' +
            '</div>' +
            '</div>' +
            '</div>';
        document.body.appendChild(modal);

        // A saved target and an unsaved edit to the same backend type are
        // indistinguishable by type alone. Never guess the source.
        var stored = currentSettings.certificate_storage || {};
        var sourceSelect = document.getElementById('storageMigSource');
        Array.prototype.forEach.call(document.getElementById('storage-backend').options, function (option) {
            if (option.value !== 'local_filesystem' && stored[option.value]) {
                sourceSelect.add(new Option(option.text, option.value));
            }
        });

        // Wire up event listeners instead of inline onclick
        document.getElementById('storageMigCloseBtn').addEventListener('click', closeStorageMigrationModal);
        document.getElementById('storageMigCancelBtn').addEventListener('click', closeStorageMigrationModal);
        document.getElementById('storageMigStartBtn').addEventListener('click', performStorageMigration);
        // A source of the type in use may be the very location the form
        // shows: the server does not refuse that, it writes each certificate
        // onto itself and counts it migrated. The page cannot always tell (a
        // retyped secret, a directory written another way), so it says so.
        sourceSelect.addEventListener('change', function () {
            var inUse = savedStorageConfig.backend || 'local_filesystem';
            document.getElementById('storageMigSame').classList.toggle('hidden', sourceSelect.value !== inUse);
        });

        // Escape key handler
        modal._escHandler = function (e) {
            if (e.key === 'Escape') closeStorageMigrationModal();
        };
        document.addEventListener('keydown', modal._escHandler);

        // Backdrop click handler — close when clicking the overlay itself
        modal.addEventListener('click', function (e) {
            if (e.target === modal) closeStorageMigrationModal();
        });
    }

    function closeStorageMigrationModal() {
        var modal = document.getElementById('storageMigrationModal');
        if (modal) {
            if (modal._escHandler) {
                document.removeEventListener('keydown', modal._escHandler);
                modal._escHandler = null;
            }
            modal.remove();
        }
    }

    function performStorageMigration() {
        var newConfig = collectStorageBackendSettings();
        var sourceBackend = document.getElementById('storageMigSource').value;
        if (!sourceBackend) {
            showMessage('Select the source backend before migrating certificates.', 'error');
            return;
        }
        // Pull the per-backend sub-config out of the envelope produced by
        // collectStorageBackendSettings (which nests under the backend key,
        // e.g. { backend: 'azure_keyvault', azure_keyvault: {...} }). The
        // server validator runs against the sub-config, not the envelope.
        var targetSubConfig = (newConfig.backend === 'local_filesystem')
            ? { cert_dir: newConfig.cert_dir }
            : (newConfig[newConfig.backend] || {});

        if (!validateStorageConfig(newConfig.backend, targetSubConfig)) {
            showMessage('Please configure and test the new storage backend before migrating.', 'error');
            return;
        }

        showMessage('Starting certificate migration...', 'info');
        closeStorageMigrationModal();

        // Send the selected source explicitly; the server resolves its stored
        // configuration (or the default local certificate directory). This
        // still works after the target backend has already been saved.
        fetch('/api/storage/migrate', {
            method: 'POST',
            headers: API_HEADERS,
            body: JSON.stringify({
                source_backend: sourceBackend,
                target_backend: newConfig.backend,
                target_config: newConfig
            })
        })
            .then(function (response) {
                return response.json().then(function (body) {
                    return { ok: response.ok, body: body };
                });
            })
            .then(function (result) {
                var data = result.body || {};
                if (result.ok && data.success) {
                    var migrated = (data.migrated_count != null) ? data.migrated_count : 0;
                    var failed = (data.failed_count != null) ? data.failed_count : 0;
                    if (data.total === 0) {
                        showMessage('No certificates found in the selected source backend. Check the source and its certificate directory.', 'warning');
                        return;
                    }
                    var msg = 'Migration completed. ' + migrated + ' certificates migrated';
                    if (failed > 0) {
                        msg += ', ' + failed + ' failed (see server logs)';
                    }
                    msg += '.';
                    showMessage(msg, failed > 0 ? 'warning' : 'success');
                } else {
                    showMessage('Migration failed: ' + (data.message || data.error || 'Unknown error'), 'error');
                }
            })
            .catch(function (error) {
                console.error('Migration error:', error);
                showMessage('Failed to perform storage migration.', 'error');
            });
    }

    // =============================================
    // USER MANAGEMENT FUNCTIONS
    // =============================================

    function loadAuthConfig() {
        return fetch('/api/auth/config', {
            headers: {}
        })
            .then(function (response) {
                if (response.ok) {
                    return response.json().then(function (data) {
                        document.getElementById('localAuthToggle').checked = data.local_auth_enabled;
                        var banner = document.getElementById('authSecurityBanner');
                        if (banner) banner.style.display = data.local_auth_enabled ? 'none' : 'block';
                        return data;
                    });
                }
                return null;
            })
            .catch(function (error) {
                console.error('Error loading auth config:', error);
                return null;
            });
    }

    function toggleLocalAuth(confirmUnauthenticated) {
        var toggle = document.getElementById('localAuthToggle');
        var enabled = toggle.checked;
        var body = { local_auth_enabled: enabled };
        if (confirmUnauthenticated) body.confirm_unauthenticated = true;

        fetch('/api/auth/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (response.ok) {
                        showMessage(data.message, 'success');
                        var banner = document.getElementById('authSecurityBanner');
                        if (banner) banner.style.display = enabled ? 'none' : 'block';
                    } else if (response.status === 409 && data.confirm_unauthenticated_required && !confirmUnauthenticated) {
                        // The one-way-door guard (#581): this is the last
                        // credential. Running without authentication is a
                        // deliberate, audited choice — ask, then repeat with
                        // the flag (#587).
                        toggle.checked = !enabled; // hold the toggle until confirmed
                        CertMate.confirm(
                            'Local authentication is the only credential configured. ' +
                            'Turning it off puts this instance in setup mode: every endpoint, ' +
                            'including private-key download, answers any caller on the network as admin. ' +
                            'Only do this if something in front of CertMate authenticates for you. ' +
                            'The choice is recorded in the audit log with your name.',
                            'Run without authentication?'
                        ).then(function (confirmed) {
                            if (!confirmed) return;
                            toggle.checked = enabled;
                            toggleLocalAuth(true);
                        });
                    } else {
                        showMessage(data.error || 'Failed to update auth config', 'error');
                        toggle.checked = !enabled; // Revert toggle
                    }
                });
            })
            .catch(function (error) {
                console.error('Error toggling local auth:', error);
                showMessage('Failed to update authentication settings', 'error');
                toggle.checked = !enabled; // Revert toggle
            });
    }

    function createUser() {
        var username = document.getElementById('newUserUsername').value.trim();
        var password = document.getElementById('newUserPassword').value;
        var email = document.getElementById('newUserEmail').value.trim();
        var role = document.getElementById('newUserRole').value;

        if (!username || !password) {
            showMessage('Username and password are required', 'error');
            return;
        }

        // Client-side password policy check (mirrors backend)
        if (password.length < 12 || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
            showMessage('Password must be at least 12 characters and include a digit and a symbol', 'error');
            var pwField = document.getElementById('newUserPassword');
            if (pwField) {
                pwField.classList.add('border-red-500', 'input-shake');
                pwField.focus();
                setTimeout(function() { pwField.classList.remove('border-red-500', 'input-shake'); }, 3000);
            }
            return;
        }

        fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: username, password: password, email: email || null, role: role })
        })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (response.ok) {
                        showMessage('User \'' + username + '\' created successfully', 'success');
                        // Clear form
                        document.getElementById('newUserUsername').value = '';
                        document.getElementById('newUserPassword').value = '';
                        document.getElementById('newUserEmail').value = '';
                        document.getElementById('newUserRole').value = 'operator';
                        // Refresh user list
                        refreshUserList();
                    } else {
                        showMessage(data.error || 'Failed to create user', 'error');
                    }
                });
            })
            .catch(function (error) {
                console.error('Error creating user:', error);
                showMessage('Failed to create user: ' + error.message, 'error');
            });
    }

    function refreshUserList() {
        var userListDiv = document.getElementById('userList');
        userListDiv.innerHTML = '<div class="text-center py-4 text-muted text-sm"><i class="fas fa-spinner fa-spin mr-2"></i> Loading users...</div>';

        // Timeout after 15 seconds to prevent infinite loading
        var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var timeoutId = controller ? setTimeout(function() { controller.abort(); }, 15000) : null;

        fetch('/api/users', {
            headers: {},
            signal: controller ? controller.signal : undefined
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('Failed to fetch users');
                }
                return response.json();
            })
            .then(function (data) {
                if (timeoutId) clearTimeout(timeoutId);
                var users = data.users || {};

                if (Object.keys(users).length === 0) {
                    userListDiv.innerHTML = '<div class="text-center py-4 text-muted text-sm"><i class="fas fa-users mr-2"></i> No users configured. Add a user above to enable local authentication.</div>';
                    return;
                }

                // The sole remaining admin must stay reachable: the backend
                // refuses to delete or disable it, so we also hide those
                // actions in the UI to avoid offering a button that can only
                // fail (mirrors issue #229).
                var adminCount = Object.keys(users).filter(function (u) {
                    return users[u].role === 'admin';
                }).length;

                var html = '';
                Object.keys(users).forEach(function (username) {
                    var userInfo = users[username];
                    var roleColor = userInfo.role === 'admin' ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300' : userInfo.role === 'operator' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' : 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300';
                    var statusColor = userInfo.enabled !== false ? 'text-green-500' : 'text-red-500';
                    var lastLogin = userInfo.last_login ? CertMate.formatDateTime(userInfo.last_login) : 'Never';

                    var isSso = userInfo.sso === true;
                    var isSoleAdmin = userInfo.role === 'admin' && adminCount === 1;

                    // Role control. The sole admin renders a static badge — the
                    // backend refuses to demote them (lockout guard), so we don't
                    // offer a select that can only fail. Everyone else gets an
                    // inline dropdown that PUTs the new role (issue #255).
                    var roleControl;
                    if (isSoleAdmin) {
                        roleControl = '<span class="text-xs px-2 py-0.5 rounded-full ' + roleColor + '">' + escapeHtml(userInfo.role || '') + '</span>';
                    } else {
                        var roleOptions = ['admin', 'operator', 'viewer'].map(function (r) {
                            return '<option value="' + r + '"' + (userInfo.role === r ? ' selected' : '') + '>' + r + '</option>';
                        }).join('');
                        roleControl =
                            '<select data-action="change-role" data-username="' + escapeHtml(username) + '" data-current="' + escapeHtml(userInfo.role || '') + '"' +
                            ' class="text-xs px-2 py-0.5 rounded-full border-0 cursor-pointer ' + roleColor + ' focus:ring-2 focus:ring-blue-500 outline-none"' +
                            ' title="Change role" aria-label="Role of ' + escapeHtml(username) + '">' + roleOptions + '</select>';
                    }

                    var emailHtml = userInfo.email ? '<span class="mr-3"><i class="fas fa-envelope mr-1"></i>' + escapeHtml(userInfo.email) + '</span>' : '';

                    // SSO accounts are managed by the external IdP — badge them
                    // so admins can tell them apart from local credentials.
                    var ssoBadge = isSso
                        ? '<span class="text-xs px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300"' +
                          ' title="Single sign-on account' + (userInfo.oidc_issuer ? ' (' + escapeHtml(userInfo.oidc_issuer) + ')' : '') + '">' +
                          '<i class="fas fa-id-badge mr-1"></i>SSO</span>'
                        : '';

                    // Each button is named for what it does and to whom: the
                    // glyph alone was its name, and every row had the same four
                    // (P16). The title stays for the pointer.
                    var who = escapeHtml(username);
                    var rowButton = 'type="button" class="p-2 inline-flex items-center justify-center min-w-11 min-h-11 sm:min-w-9 sm:min-h-9 rounded ';

                    // Disable/enable toggle — hidden for the sole admin (cannot
                    // be locked out).
                    var toggleBtn = isSoleAdmin ? '' :
                        '<button ' + rowButton + 'text-muted hover:text-gray-700 dark:hover:text-gray-200" data-action="toggle-user" data-username="' + who + '" data-enable="' + (userInfo.enabled === false) + '"' +
                        ' title="' + (userInfo.enabled !== false ? 'Disable user' : 'Enable user') + '"' +
                        ' aria-label="' + (userInfo.enabled !== false ? 'Disable ' : 'Enable ') + who + '">' +
                        '<i class="fas fa-' + (userInfo.enabled !== false ? 'ban' : 'check') + '" aria-hidden="true"></i>' +
                        '</button>';

                    // Password reset — not applicable to SSO accounts (no local
                    // password to set).
                    var resetBtn = isSso ? '' :
                        '<button ' + rowButton + 'text-muted hover:text-gray-700 dark:hover:text-gray-200" data-action="reset-password" data-username="' + who + '"' +
                        ' title="Reset password" aria-label="Reset password of ' + who + '">' +
                        '<i class="fas fa-key" aria-hidden="true"></i>' +
                        '</button>';

                    // Email — what an SSO login links an existing account by.
                    var emailBtn =
                        '<button ' + rowButton + 'text-muted hover:text-gray-700 dark:hover:text-gray-200" data-action="edit-email" data-username="' + who + '"' +
                        ' data-email="' + escapeHtml(userInfo.email || '') + '"' +
                        ' title="' + (userInfo.email ? 'Change email' : 'Set email') + '"' +
                        ' aria-label="' + (userInfo.email ? 'Change email of ' : 'Set email of ') + who + '">' +
                        '<i class="fas fa-envelope" aria-hidden="true"></i>' +
                        '</button>';

                    // Delete — hidden for the sole admin.
                    var deleteBtn = isSoleAdmin ? '' :
                        '<button ' + rowButton + 'text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300" data-action="delete-user" data-username="' + who + '"' +
                        ' title="Delete user" aria-label="Delete ' + who + '">' +
                        '<i class="fas fa-trash" aria-hidden="true"></i>' +
                        '</button>';

                    // The row wraps: on a phone the actions take a line of
                    // their own under the user instead of running past the
                    // edge of the list (P12).
                    html +=
                        '<div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">' +
                        '<div class="flex items-center space-x-3 min-w-0">' +
                        '<i class="fas fa-user-circle text-2xl text-gray-400 dark:text-gray-500" aria-hidden="true"></i>' +
                        '<div class="min-w-0">' +
                        '<div class="flex flex-wrap items-center gap-2">' +
                        '<span class="font-medium text-foreground min-w-0 [overflow-wrap:anywhere]">' + escapeHtml(username) + '</span>' +
                        roleControl +
                        ssoBadge +
                        '<i class="fas fa-circle text-xs ' + statusColor + '" title="' + (userInfo.enabled !== false ? 'Active' : 'Disabled') + '" aria-hidden="true"></i>' +
                        '<span class="sr-only">' + (userInfo.enabled !== false ? 'Active' : 'Disabled') + '</span>' +
                        '</div>' +
                        '<div class="text-xs text-muted break-words">' +
                        emailHtml +
                        '<span><i class="fas fa-clock mr-1" aria-hidden="true"></i>Last login: ' + escapeHtml(lastLogin) + '</span>' +
                        '</div>' +
                        '</div>' +
                        '</div>' +
                        '<div class="flex items-center justify-end gap-1 w-full sm:w-auto">' +
                        toggleBtn +
                        emailBtn +
                        resetBtn +
                        deleteBtn +
                        '</div>' +
                        '</div>';
                });

                userListDiv.innerHTML = html;

                // Bind user action buttons via event delegation
                userListDiv.querySelectorAll('button[data-action]').forEach(function (btn) {
                    btn.addEventListener('click', function () {
                        var user = btn.dataset.username;
                        switch (btn.dataset.action) {
                            case 'toggle-user': toggleUserStatus(user, btn.dataset.enable === 'true'); break;
                            case 'reset-password': resetUserPassword(user); break;
                            case 'edit-email': editUserEmail(user, btn.dataset.email); break;
                            case 'delete-user': deleteUser(user); break;
                        }
                    });
                });

                // Role dropdowns fire 'change', not 'click', so they bind
                // separately from the icon buttons above.
                userListDiv.querySelectorAll('select[data-action="change-role"]').forEach(function (sel) {
                    sel.addEventListener('change', function () {
                        changeUserRole(sel.dataset.username, sel.value, sel.dataset.current, sel);
                    });
                });
            })
            .catch(function (error) {
                if (timeoutId) clearTimeout(timeoutId);
                console.error('Error loading users:', error);
                var msg = error.name === 'AbortError'
                    ? 'User list request timed out. Click Refresh to retry.'
                    : 'Failed to load users. Click Refresh to retry.';
                userListDiv.innerHTML = '<div class="text-center py-4 text-red-500 text-sm"><i class="fas fa-exclamation-triangle mr-2"></i> ' + msg + '</div>';
            });
    }

    function changeUserRole(username, newRole, currentRole, selectEl) {
        if (newRole === currentRole) return;

        CertMate.confirm(
            'Change role of \'' + username + '\' from ' + currentRole + ' to ' + newRole + '?',
            'Change Role',
            { danger: false, confirmText: 'Change Role' }
        ).then(function (confirmed) {
            if (!confirmed) {
                if (selectEl) selectEl.value = currentRole; // revert the dropdown
                return;
            }

            fetch('/api/users/' + username, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: newRole })
            })
                .then(function (response) {
                    return response.json().then(function (data) {
                        if (response.ok) {
                            showMessage('Role for \'' + username + '\' changed to ' + newRole, 'success');
                            refreshUserList();
                        } else {
                            showMessage(data.error || 'Failed to change role', 'error');
                            if (selectEl) selectEl.value = currentRole;
                        }
                    });
                })
                .catch(function (error) {
                    console.error('Error changing user role:', error);
                    showMessage('Failed to change role', 'error');
                    if (selectEl) selectEl.value = currentRole;
                });
        });
    }

    function toggleUserStatus(username, enable) {
        fetch('/api/users/' + username, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled: enable })
        })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (response.ok) {
                        showMessage('User \'' + username + '\' ' + (enable ? 'enabled' : 'disabled'), 'success');
                        refreshUserList();
                    } else {
                        showMessage(data.error || 'Failed to update user', 'error');
                    }
                });
            })
            .catch(function (error) {
                console.error('Error toggling user status:', error);
                showMessage('Failed to update user status', 'error');
            });
    }

    function editUserEmail(username, current) {
        CertMate.prompt('Email for \'' + username + '\':', 'Edit Email', current || '').then(function (email) {
            email = (email || '').trim();
            if (!email || email === current) return;

            fetch('/api/users/' + encodeURIComponent(username), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            })
                .then(function (response) {
                    return response.json().then(function (data) {
                        if (response.ok) {
                            showMessage('Email saved for \'' + username + '\'', 'success');
                            refreshUserList();
                        } else {
                            showMessage(data.error || 'Failed to save email', 'error');
                        }
                    });
                })
                .catch(function (error) {
                    console.error('Error saving email:', error);
                    showMessage('Failed to save email', 'error');
                });
        });
    }

    function resetUserPassword(username) {
        CertMate.prompt('Enter new password for \'' + username + '\':', 'Reset Password', '', { inputType: 'password' }).then(function (newPassword) {
            if (!newPassword) return;

            fetch('/api/users/' + username, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: newPassword })
            })
                .then(function (response) {
                    return response.json().then(function (data) {
                        if (response.ok) {
                            showMessage('Password reset for \'' + username + '\'', 'success');
                        } else {
                            showMessage(data.error || 'Failed to reset password', 'error');
                        }
                    });
                })
                .catch(function (error) {
                    console.error('Error resetting password:', error);
                    showMessage('Failed to reset password', 'error');
                });
        });
    }

    function deleteUser(username) {
        CertMate.confirm('Are you sure you want to delete user \'' + username + '\'? This action cannot be undone.', 'Delete User').then(function (confirmed) {
            if (!confirmed) return;

            fetch('/api/users/' + username, {
                method: 'DELETE',
                headers: {}
            })
                .then(function (response) {
                    return response.json().then(function (data) {
                        if (response.ok) {
                            showMessage('User \'' + username + '\' deleted', 'success');
                            refreshUserList();
                        } else {
                            showMessage(data.error || 'Failed to delete user', 'error');
                        }
                    });
                })
                .catch(function (error) {
                    console.error('Error deleting user:', error);
                    showMessage('Failed to delete user', 'error');
                });
        });
    }

    // =============================================
    // DOMContentLoaded - consolidated
    // =============================================

    document.addEventListener('DOMContentLoaded', function () {
        form = document.getElementById('settingsForm');
        saveBtn = document.getElementById('saveBtn');
        statusMessage = document.getElementById('statusMessage');

        // R-2: route every dismiss path (Esc, backdrop, the macro's
        // close button, the form's Cancel button with [data-modal-close])
        // through the existing cleanup. The programmatic path —
        // saveAccount() / saveEditAccount() calling closeXxxModal() on
        // success — still runs the same body, so cleanup is uniform.
        var addModalEl = document.getElementById('addAccountModal');
        if (addModalEl) addModalEl.addEventListener('modal:close', closeAddAccountModal);
        var editModalEl = document.getElementById('editAccountModal');
        if (editModalEl) editModalEl.addEventListener('modal:close', closeEditAccountModal);
        // The Enter-to-not-submit workaround is gone: the CA modal now lives
        // outside #settingsForm (settings.html), so Enter in it no longer
        // submits the page form.

        addDebugLog('DOM loaded, initializing settings page', 'info');

        // Add challenge type radio listeners
        document.querySelectorAll('input[name="challenge_type"]').forEach(function (radio) {
            radio.addEventListener('change', function () {
                addDebugLog('Challenge type changed to: ' + this.value, 'info');
            });
        });

        var propagationField = document.getElementById('dns_propagation_current');
        if (propagationField) {
            propagationField.addEventListener('input', function () {
                var provider = this.dataset.provider;
                var seconds = parseInt(this.value, 10);
                if (provider && seconds > 0) {
                    propagationSeconds[provider] = seconds;
                }
            });
        }

        // Add radio button listeners. A tile picked with the pointer brings
        // its section into view; arrow keys moving through the group do not,
        // or each step would scroll the group away from the keyboard.
        var dnsPickedByKey = false;
        document.querySelectorAll('input[name="dns_provider"]').forEach(function (radio) {
            radio.addEventListener('keydown', function (e) { dnsPickedByKey = e.key.indexOf('Arrow') === 0; });
            radio.addEventListener('change', function () {
                var reveal = !dnsPickedByKey;
                dnsPickedByKey = false;
                if (this.checked) {
                    showDNSConfig(this.value, reveal);
                    addDebugLog('DNS provider changed to: ' + this.value, 'info');
                }
            });
        });

        // Load settings on page load (critical, runs first)
        loadSettings();

        // Initialize CA provider configuration visibility
        toggleCAProviderConfig();

        // Refresh cache stats (delayed to avoid thread starvation)
        setTimeout(function () { refreshCacheStats(); }, 1500);

        // Form submit handler
        if (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                addDebugLog('Settings form submitted', 'info');
                saveSettings();
            });
            // One form holds the DNS, CA, General and Storage tabs. A field
            // out of its limits on a tab that is not showing blocked the save
            // with no word: the browser cannot show its message on a hidden
            // field, so there was no request and no toast. The first invalid
            // field of a press of Save is brought into view and named.
            form.addEventListener('invalid', onSettingsFieldInvalid, true);
        }

        // Users and backups load when their panel is first shown. They waited
        // a fixed 4 and 3 seconds after the page, to spread the startup
        // requests, so the Users tab showed local authentication as off and
        // "Loading users..." for four seconds when /api/users answers in
        // milliseconds (UX audit, 2026-11-17). Opening the tab is spread
        // enough. Read from the panel itself (Alpine shows it), not from the
        // URL, so the page opening on a tab and a click on one are the same.
        loadWhenShown('settings-panel-users', function () {
            loadAuthConfig();
            refreshUserList();
        });
        loadWhenShown('settings-panel-backup', refreshBackupList);
    });

    // Run *load* once, the first time the panel *id* is on screen.
    function loadWhenShown(id, load) {
        var panel = document.getElementById(id);
        if (!panel) return;
        var observer = new MutationObserver(check);
        function check() {
            if (panel.offsetParent === null) return;
            observer.disconnect();
            load();
        }
        observer.observe(panel, { attributes: true, attributeFilter: ['style', 'class', 'x-cloak'] });
        check();
    }

    // =============================================
    // Cross-module bridge for extracted Alpine components
    // =============================================
    // Helpers consumed by settings-deploy.js (addDebugLog) and
    // settings-apikeys.js (showMessage). Keep this surface tiny.
    window.CmSettings = {
        addDebugLog: addDebugLog,
        showMessage: showMessage
    };

    // =============================================
    // Window exposures needed by HTML onclick/onchange/x-data
    // =============================================

    window.showAddAccountModal = showAddAccountModal;
    window.closeAddAccountModal = closeAddAccountModal;
    window.saveAccount = saveAccount;
    window.showEditAccountModal = showEditAccountModal;
    window.closeEditAccountModal = closeEditAccountModal;
    window.saveEditAccount = saveEditAccount;
    window.deleteAccount = deleteAccount;
    window.toggleCAProviderConfig = toggleCAProviderConfig;
    window.openCAAccountModal = openCAAccountModal;
    window.selectCAAccountType = selectCAAccountType;
    window.saveCAAccount = saveCAAccount;
    window.applyPrivateCaPreset = applyPrivateCaPreset;
    window.testCAProvider = testCAProvider;
    window.toggleTokenVisibility = toggleTokenVisibility;
    window.toggleStorageBackendConfig = toggleStorageBackendConfig;
    window.toggleAWSAuthMode = toggleAWSAuthMode;
    window.toggleS3AuthMode = toggleS3AuthMode;
    window.toggleDefaultKeyOptions = toggleDefaultKeyOptions;
    window.testStorageBackend = testStorageBackend;
    window.toggleAzureBackfillRow = toggleAzureBackfillRow;
    window.backfillAzureCertificateObjects = backfillAzureCertificateObjects;
    window.showStorageMigrationModal = showStorageMigrationModal;
    window.closeStorageMigrationModal = closeStorageMigrationModal;
    window.performStorageMigration = performStorageMigration;
    window.toggleLocalAuth = toggleLocalAuth;
    window.createUser = createUser;
    window.refreshUserList = refreshUserList;
    window.createBackup = createBackup;
    window.uploadBackup = uploadBackup;
    window.refreshBackupList = refreshBackupList;
    window.downloadBackup = downloadBackup;
    window.restoreBackup = restoreBackup;
    window.deleteBackup = deleteBackup;
    window.clearSettingsDebugConsole = clearSettingsDebugConsole;
    window.toggleSettingsDebugConsole = toggleSettingsDebugConsole;
    window.toggleRoute53LegacyAuthMode = toggleRoute53LegacyAuthMode;
    window.toggleUserStatus = toggleUserStatus;
    window.resetUserPassword = resetUserPassword;
    window.editUserEmail = editUserEmail;
    window.deleteUser = deleteUser;
    window.clearDeploymentCache = clearDeploymentCache;
    window.refreshCacheStats = refreshCacheStats;

    // The form's `invalid` event, in the capture phase: the browser fires it
    // once for each invalid field when Save is pressed, and the first one of
    // that press is the one shown, in a toast naming the field and its tab.
    // Whether the browser can show its own message is decided by the field,
    // not its panel: a field on the showing tab can still be hidden, inside
    // a provider block that is not selected. A field that can be shown keeps
    // the browser's bubble. A hidden one gets preventDefault (otherwise the
    // browser only logs that it cannot focus it); if its tab is hidden, the
    // tab is opened the way the side menu opens one (the URL fragment, read
    // by settingsTabs) and the field is focused once it shows.
    var settingsInvalidShown = false;
    function settingsFieldHidden(el) {
        return el.offsetParent === null || el.getClientRects().length === 0;
    }
    function onSettingsFieldInvalid(event) {
        var field = event.target;
        if (settingsInvalidShown) {
            event.preventDefault();
            return;
        }
        settingsInvalidShown = true;
        setTimeout(function () { settingsInvalidShown = false; }, 0);

        var panel = field.closest('[id^="settings-panel-"]');
        var tabId = panel ? panel.id.replace('settings-panel-', '') : '';
        var tabButton = tabId ? document.getElementById('settings-tab-' + tabId) : null;
        var tabLabel = (tabButton && tabButton.getAttribute('aria-label')) || tabId;
        var label = field.id ? document.querySelector('label[for="' + field.id + '"]') : null;
        var name = (label && label.textContent.trim()) || field.name || field.id;
        // The limits are the reason only when the value is outside them; a
        // step mismatch (7.5 in a whole-days field) keeps the browser's text.
        var why = field.validationMessage;
        if ((field.validity.rangeUnderflow || field.validity.rangeOverflow)
                && field.min !== '' && field.max !== '') {
            why = 'It must be between ' + field.min + ' and ' + field.max + '.';
        }
        var where = tabLabel ? tabLabel + ' tab, ' : '';
        showMessage(where + name + ': ' + why + ' Nothing was saved.', 'error');

        if (!settingsFieldHidden(field)) return;
        event.preventDefault();
        if (panel && settingsFieldHidden(panel)) {
            location.hash = tabId;
            var tries = 0;
            (function focusWhenShown() {
                if (!settingsFieldHidden(field)) {
                    field.focus();
                } else if (tries++ < 40) {
                    setTimeout(focusWhenShown, 25);
                }
            })();
        }
    }

    // WAI-ARIA tabs: Left/Right/Home/End move between the settings tabs and
    // activate the focused one (automatic activation). Wired from settings.html
    // via @keydown on the [role=tablist]. Clicking the target button triggers
    // Alpine's `tab = t.id`, which also updates the roving tabindex reactively.
    function onSettingsTabKeydown(event) {
        var keys = ['ArrowDown', 'ArrowUp', 'ArrowRight', 'ArrowLeft', 'Home', 'End'];
        if (keys.indexOf(event.key) === -1) return;
        // Every tab of the side menu, across its three tablists (#1423): only the selected
        // tab is in the Tab order, so the arrows are how the other groups are reached.
        var scope = event.currentTarget.closest('[data-settings-sections]') || event.currentTarget;
        var tabs = Array.prototype.slice.call(scope.querySelectorAll('[role="tab"]'));
        if (!tabs.length) return;
        var current = tabs.indexOf(document.activeElement);
        if (current === -1) current = 0;
        var next = current;
        if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = (current + 1) % tabs.length;
        else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = (current - 1 + tabs.length) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        event.preventDefault();
        tabs[next].focus();
        tabs[next].click();
    }
    window.onSettingsTabKeydown = onSettingsTabKeydown;

    // What the page's controls may ask for by name (`data-click`, `data-change`,
    // `data-input`): see CertMate.actions in certmate.js.
    CertMate.globalActions([
        'applyPrivateCaPreset', 'backfillAzureCertificateObjects', 'clearSettingsDebugConsole',
        'createBackup', 'createUser', 'openCAAccountModal',
        'refreshBackupList', 'refreshUserList', 'saveAccount', 'saveCAAccount',
        'saveEditAccount', 'selectCAAccountType', 'showAddAccountModal',
        'showStorageMigrationModal', 'testCAProvider', 'testStorageBackend',
        'toggleAWSAuthMode', 'toggleAzureBackfillRow', 'toggleDefaultKeyOptions',
        'toggleLocalAuth', 'toggleRoute53LegacyAuthMode', 'toggleS3AuthMode',
        'toggleSettingsDebugConsole', 'toggleStorageBackendConfig', 'toggleTokenVisibility',
        'uploadBackup'
    ]);

})();
