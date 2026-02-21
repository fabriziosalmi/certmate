(function() {
    'use strict';

    // =============================================
    // BLOCK 1: Alpine.js Notification Component
    // =============================================

    function notificationSettings() {
        return {
            config: {
                enabled: false,
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
            set smtpToStr(v) { this.config.channels.smtp.to_addresses = v.split(',').map(function(s) { return s.trim(); }).filter(Boolean); },
            toggleEvent: function(evt) {
                var idx = this.config.events.indexOf(evt);
                if (idx === -1) this.config.events.push(evt);
                else this.config.events.splice(idx, 1);
            },
            loadConfig: function() {
                var self = this;
                fetch('/api/notifications/config', { credentials: 'same-origin' })
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        if (data && typeof data === 'object' && !data.error) {
                            self.config.enabled = data.enabled || false;
                            self.config.events = data.events || [];
                            if (data.channels) {
                                if (data.channels.smtp) Object.assign(self.config.channels.smtp, data.channels.smtp);
                                if (data.channels.webhooks) self.config.channels.webhooks = data.channels.webhooks;
                            }
                        }
                    })
                    .catch(function() {});
            },
            saveConfig: function() {
                var self = this;
                fetch('/api/notifications/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify(self.config)
                })
                .then(function(r) { return r.json(); })
                .then(function() { CertMate.toast('Notification settings saved', 'success'); })
                .catch(function() { CertMate.toast('Failed to save', 'error'); });
            },
            testSmtp: function() {
                var self = this;
                fetch('/api/notifications/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ channel_type: 'smtp', config: self.config.channels.smtp })
                })
                .then(function(r) { return r.json(); })
                .then(function(d) { CertMate.toast(d.success ? 'Test email sent!' : ('Email failed: ' + (d.error || 'unknown')), d.success ? 'success' : 'error'); })
                .catch(function() { CertMate.toast('Test failed', 'error'); });
            },
            testWebhook: function(wh) {
                fetch('/api/notifications/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ channel_type: 'webhook', config: wh })
                })
                .then(function(r) { return r.json(); })
                .then(function(d) { CertMate.toast(d.success ? 'Webhook test sent!' : ('Webhook failed: ' + (d.error || 'unknown')), d.success ? 'success' : 'error'); })
                .catch(function() { CertMate.toast('Test failed', 'error'); });
            },
            toggleWebhookEvent: function(wh, evt) {
                if (!wh.events) wh.events = [];
                var idx = wh.events.indexOf(evt);
                if (idx === -1) wh.events.push(evt);
                else wh.events.splice(idx, 1);
            },
            loadDeliveries: function() {
                var self = this;
                fetch('/api/webhooks/deliveries?limit=50', { credentials: 'same-origin' })
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        if (Array.isArray(data)) self.deliveries = data;
                    })
                    .catch(function() {});
            }
        };
    }

    // =============================================
    // BLOCK 2: Main Settings JavaScript
    // =============================================

    // API Configuration - session cookies are sent automatically
    var API_HEADERS = {
        'Content-Type': 'application/json'
    };

    // Global variables - properly initialized
    var currentSettings = {};
    var dnsProviders = {};
    var isLoading = false;

    var escapeHtml = CertMate.escapeHtml;

    // DOM Elements - initialized in DOMContentLoaded
    var form, saveBtn, statusMessage;

    // =============================================
    // Debug console functions
    // =============================================

    function toggleDebugConsole() {
        var consoleDiv = document.getElementById('settingsDebugConsole');
        if (consoleDiv.classList.contains('hidden')) {
            consoleDiv.classList.remove('hidden');
        } else {
            consoleDiv.classList.add('hidden');
        }
    }

    function clearDebugConsole() {
        document.getElementById('settingsDebugOutput').innerHTML = '<div class="text-gray-500">Debug console cleared. All settings actions will be logged here...</div>';
    }

    // =============================================
    // Challenge type toggle
    // =============================================

    function toggleChallengeType() {
        var selected = document.querySelector('input[name="challenge_type"]:checked');
        var dnsSection = document.getElementById('dns-provider-section');
        if (!dnsSection) return;
        if (selected && selected.value === 'http-01') {
            dnsSection.style.display = 'none';
        } else {
            dnsSection.style.display = '';
        }
    }

    // =============================================
    // API Token helper functions
    // =============================================

    function toggleTokenVisibility() {
        var tokenField = document.getElementById('api_bearer_token');
        var toggleIcon = document.getElementById('tokenToggleIcon');
        if (tokenField.type === 'password') {
            tokenField.type = 'text';
            toggleIcon.classList.remove('fa-eye');
            toggleIcon.classList.add('fa-eye-slash');
        } else {
            tokenField.type = 'password';
            toggleIcon.classList.remove('fa-eye-slash');
            toggleIcon.classList.add('fa-eye');
        }
    }

    function generateRandomToken() {
        var array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, function(byte) { return byte.toString(16).padStart(2, '0'); }).join('');
    }

    function generateToken() {
        var tokenField = document.getElementById('api_bearer_token');
        var newToken = generateRandomToken();
        tokenField.value = newToken;
        tokenField.type = 'text'; // Show the generated token
        var toggleIcon = document.getElementById('tokenToggleIcon');
        toggleIcon.classList.remove('fa-eye');
        toggleIcon.classList.add('fa-eye-slash');
        addDebugLog('Generated new API Bearer Token', 'info');
        showMessage('New API token generated. Remember to save your settings!', 'success');
    }

    // =============================================
    // Debug logging
    // =============================================

    function addDebugLog(message, type) {
        type = type || 'info';
        var output = document.getElementById('settingsDebugOutput');
        var color = type === 'error' ? 'text-red-400' : type === 'warn' ? 'text-yellow-400' : 'text-green-400';
        var time = new Date().toLocaleTimeString();
        var entry = document.createElement('div');
        entry.className = color;
        entry.textContent = '[' + time + '] ' + type.toUpperCase() + ': ' + message;
        output.appendChild(entry);
        output.scrollTop = output.scrollHeight;
    }

    // =============================================
    // Message display function
    // =============================================

    function showMessage(message, type) {
        type = type || 'info';
        addDebugLog(message, type);

        if (statusMessage) {
            statusMessage.textContent = message;
            var cls = 'mt-4 p-3 rounded-md text-sm ';
            if (type === 'success') {
                cls += 'bg-green-100 text-green-700 border border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-600';
            } else if (type === 'error') {
                cls += 'bg-red-100 text-red-700 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-600';
            } else if (type === 'warning') {
                cls += 'bg-yellow-100 text-yellow-700 border border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-400 dark:border-yellow-600';
            } else {
                cls += 'bg-blue-100 text-blue-700 border border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-600';
            }
            statusMessage.className = cls;
            statusMessage.classList.remove('hidden');

            // Auto-hide success messages after 5 seconds
            if (type === 'success') {
                setTimeout(function() {
                    if (statusMessage) {
                        statusMessage.classList.add('hidden');
                    }
                }, 5000);
            }
        }
    }

    // =============================================
    // DNS provider configuration functions
    // =============================================

    function showDNSConfig(provider) {
        // Hide all DNS config sections
        document.querySelectorAll('.dns-config').forEach(function(config) {
            config.classList.add('hidden');
        });

        // Show the selected provider's config
        var configSection = document.getElementById(provider + '-config');
        if (configSection) {
            configSection.classList.remove('hidden');
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

        try {
            var formData = new FormData(form);
            var caProviders = collectCAProviderSettings();
            var defaultCA = formData.get('default_ca') || 'letsencrypt';

            // Get email from the selected CA provider
            var email = '';
            if (defaultCA === 'letsencrypt') {
                email = (caProviders.letsencrypt && caProviders.letsencrypt.email) || '';
            } else if (defaultCA === 'digicert') {
                email = (caProviders.digicert && caProviders.digicert.email) || '';
            } else if (defaultCA === 'private_ca') {
                email = (caProviders.private_ca && caProviders.private_ca.email) || '';
            }

            var domainsRaw = formData.get('domains');
            var domainsValue = domainsRaw ? domainsRaw.split('\n').map(function(d) { return d.trim(); }).filter(function(d) { return d; }) : undefined;

            var tokenRaw = formData.get('api_bearer_token');
            var tokenValue = tokenRaw ? tokenRaw.trim() : undefined;

            var settings = {
                email: email.trim(),
                domains: domainsValue,
                auto_renew: formData.get('auto_renew') === 'on',
                renewal_threshold_days: parseInt(formData.get('renewal_threshold_days')) || 30,
                dns_provider: formData.get('dns_provider'),
                challenge_type: formData.get('challenge_type') || 'dns-01',
                api_bearer_token: tokenValue,
                cache_ttl: parseInt(formData.get('cache_ttl')) || 300,
                storage_backend: formData.get('storage_backend'),
                certificate_storage: collectStorageBackendSettings(),
                default_ca: defaultCA,
                ca_providers: caProviders
            };

            // Validate required fields - email comes from the selected CA provider
            if (!settings.email) {
                var caDisplayName = defaultCA === 'letsencrypt' ? "Let's Encrypt" :
                                    defaultCA === 'digicert' ? 'DigiCert' : 'Private CA';
                throw new Error('Email address is required in the ' + caDisplayName + ' configuration section');
            }

            if (settings.challenge_type !== 'http-01' && !settings.dns_provider) {
                throw new Error('DNS provider must be selected');
            }

            // API Bearer Token is only required after initial setup
            if (!settings.api_bearer_token && currentSettings.setup_completed) {
                throw new Error('API Bearer Token is required');
            }

            // Auto-generate token for initial setup if not provided
            if (!settings.api_bearer_token && !currentSettings.setup_completed) {
                settings.api_bearer_token = generateRandomToken();
                var tokenField = document.getElementById('api_bearer_token');
                if (tokenField) {
                    tokenField.value = settings.api_bearer_token;
                }
                addDebugLog('Auto-generated API Bearer Token for initial setup', 'info');
            }

            // Add legacy DNS provider configurations from form fields
            var legacyConfig = {};

            // Get legacy fields for the selected provider
            var provider = settings.dns_provider;
            var legacyFields = getLegacyFieldsForProvider(provider);

            legacyFields.forEach(function(fieldName) {
                var value = formData.get(fieldName);
                if (value && value.trim()) {
                    var configKey = fieldName.replace(provider + '_', '');
                    legacyConfig[configKey] = value.trim();
                }
            });

            // Only include legacy config if we have some values and no multi-account data
            if (Object.keys(legacyConfig).length > 0) {
                if (!settings.dns_providers) settings.dns_providers = {};
                if (!settings.dns_providers[provider]) settings.dns_providers[provider] = {};

                // Check if we already have multi-account data
                var hasMultiAccount = Object.values(settings.dns_providers[provider]).some(function(val) {
                    return typeof val === 'object' && val.name;
                });

                if (!hasMultiAccount) {
                    Object.assign(settings.dns_providers[provider], legacyConfig);
                }
            }

            addDebugLog('Settings to save: ' + JSON.stringify(settings, null, 2), 'info');

            fetch('/api/web/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            })
            .then(function(response) {
                if (!response.ok) {
                    return response.text().then(function(errorData) {
                        throw new Error('HTTP ' + response.status + ': ' + errorData);
                    });
                }
                return response.json();
            })
            .then(function(result) {
                addDebugLog('Settings saved successfully', 'info');
                showMessage('Settings saved successfully', 'success');

                // Reload settings to refresh the UI
                return loadSettings();
            })
            .catch(function(error) {
                addDebugLog('Error saving settings: ' + error.message, 'error');
                showMessage('Error saving settings: ' + error.message, 'error');
            })
            .then(function() {
                // finally block equivalent
                isLoading = false;
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.innerHTML = '<i class="fas fa-save mr-2"></i>Save Settings';
                }
            });
        } catch (error) {
            addDebugLog('Error saving settings: ' + error.message, 'error');
            showMessage('Error saving settings: ' + error.message, 'error');
            isLoading = false;
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.innerHTML = '<i class="fas fa-save mr-2"></i>Save Settings';
            }
        }
    }

    // =============================================
    // Legacy field mappings
    // =============================================

    function getLegacyFieldsForProvider(provider) {
        var fieldMappings = {
            'cloudflare': ['cloudflare_api_token'],
            'route53': ['route53_access_key_id', 'route53_secret_access_key', 'route53_region'],
            'azure': ['azure_subscription_id', 'azure_resource_group', 'azure_tenant_id', 'azure_client_id', 'azure_client_secret'],
            'google': ['google_project_id', 'google_service_account_key'],
            'powerdns': ['powerdns_api_url', 'powerdns_api_key'],
            'digitalocean': ['digitalocean_api_token'],
            'linode': ['linode_api_key'],
            'gandi': ['gandi_api_token'],
            'ovh': ['ovh_endpoint', 'ovh_application_key', 'ovh_application_secret', 'ovh_consumer_key'],
            'namecheap': ['namecheap_username', 'namecheap_api_key'],
            'rfc2136': ['rfc2136_nameserver', 'rfc2136_tsig_key', 'rfc2136_tsig_secret', 'rfc2136_tsig_algorithm'],
            'hetzner': ['hetzner_api_token'],
            'porkbun': ['porkbun_api_key', 'porkbun_secret_key'],
            'godaddy': ['godaddy_api_key', 'godaddy_secret'],
            'he-ddns': ['he_ddns_username', 'he_ddns_password'],
            'dynudns': ['dynudns_token'],
            'dnsmadeeasy': ['dnsmadeeasy_api_key', 'dnsmadeeasy_secret_key'],
            'nsone': ['nsone_api_key']
        };

        return fieldMappings[provider] || [];
    }

    // =============================================
    // Cache management functions
    // =============================================

    function refreshCacheStats() {
        addDebugLog('Refreshing cache stats...', 'info');

        return fetch('/api/web/cache/stats')
            .then(function(response) {
                if (response.ok) {
                    return response.json().then(function(stats) {
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
            .catch(function(error) {
                addDebugLog('Error refreshing cache stats: ' + error.message, 'error');
            });
    }

    function clearDeploymentCache() {
        addDebugLog('Clearing deployment cache...', 'info');

        return fetch('/api/web/cache/clear', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(function(response) {
            if (response.ok) {
                return response.json().then(function(result) {
                    addDebugLog('Cache cleared successfully', 'info');
                    showMessage('Cache cleared successfully', 'success');
                    return refreshCacheStats();
                });
            } else {
                addDebugLog('Failed to clear cache', 'warn');
                showMessage('Failed to clear cache', 'error');
            }
        })
        .catch(function(error) {
            addDebugLog('Error clearing cache: ' + error.message, 'error');
            showMessage('Error clearing cache', 'error');
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
        .then(function(response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }
            return response.json();
        })
        .then(function(settings) {
            addDebugLog('Settings loaded: ' + Object.keys(settings).join(', '), 'info');

            currentSettings = settings;
            populateForm(settings);

            // Load DNS provider configurations and status
            return loadDNSProviders();
        })
        .then(function() {
            addDebugLog('Settings loaded and form populated successfully', 'info');
        })
        .catch(function(error) {
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
                Object.keys(currentSettings.dns_providers).forEach(function(provider) {
                    var config = currentSettings.dns_providers[provider];
                    try {
                        dnsProviders[provider] = {
                            configured: false,
                            accounts: []
                        };

                        if (config && typeof config === 'object') {
                            // Check for canonical multi-account format: { accounts: { id: {...}, ... } }
                            if (config.accounts && typeof config.accounts === 'object') {
                                Object.keys(config.accounts).forEach(function(accountId) {
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
                            } else if (Object.values(config).some(function(val) { return typeof val === 'object' && 'name' in val; })) {
                                // Multi-account format
                                Object.keys(config).forEach(function(accountId) {
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
                                var hasCredentials = Object.values(config).some(function(val) { return val && val.trim && val.trim().length > 0; });
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

            // Update provider status indicators
            updateProviderStatusIndicators();

            // Update account lists in DNS config sections
            updateAccountLists();

            addDebugLog('DNS provider configurations loaded', 'info');

        } catch (error) {
            addDebugLog('Failed to load DNS providers: ' + error.message, 'error');
            console.error('Error loading DNS providers:', error);
        }
    }

    // =============================================
    // Update DNS provider status indicators in the UI
    // =============================================

    function updateProviderStatusIndicators() {
        var providers = [
            'cloudflare', 'route53', 'azure', 'google', 'powerdns',
            'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap',
            'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner',
            'porkbun', 'godaddy', 'he-ddns', 'dynudns'
        ];

        providers.forEach(function(provider) {
            var statusEl = document.getElementById(provider + '-status');
            var accountsEl = document.getElementById(provider + '-accounts');
            var countEl = document.getElementById(provider + '-account-count');

            if (statusEl) {
                var providerData = dnsProviders[provider];
                if (providerData && providerData.configured) {
                    statusEl.textContent = 'Configured';
                    statusEl.className = 'text-xs text-green-600 dark:text-green-400 mt-1';

                    if (accountsEl && countEl) {
                        countEl.textContent = providerData.accounts.length;
                        accountsEl.classList.remove('hidden');
                    }
                } else {
                    statusEl.textContent = 'Not configured';
                    statusEl.className = 'text-xs text-gray-500 dark:text-gray-400 mt-1';

                    if (accountsEl) {
                        accountsEl.classList.add('hidden');
                    }
                }
            }
        });
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
                    var domainStrings = data.domains.map(function(d) {
                        return typeof d === 'string' ? d : (d.domain || '');
                    }).filter(function(d) { return d; });
                    domainsField.value = domainStrings.join('\n');
                    addDebugLog('Domains field populated with ' + domainStrings.length + ' domains', 'info');
                }
            }

            if (data.auto_renew !== undefined) {
                var autoRenewField = document.getElementById('auto_renew');
                if (autoRenewField) {
                    autoRenewField.checked = data.auto_renew;
                    addDebugLog('Auto-renewal set to ' + data.auto_renew, 'info');
                }
            }

            if (data.renewal_threshold_days !== undefined) {
                var thresholdField = document.getElementById('renewal_threshold_days');
                if (thresholdField) {
                    thresholdField.value = data.renewal_threshold_days;
                    addDebugLog('Renewal threshold set to ' + data.renewal_threshold_days + ' days', 'info');
                }
            }

            if (data.api_bearer_token) {
                var populateTokenField = document.getElementById('api_bearer_token');
                if (populateTokenField) {
                    populateTokenField.value = data.api_bearer_token;
                    addDebugLog('API bearer token field populated', 'info');
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
            toggleChallengeType();

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
            Object.keys(localDnsProviders).forEach(function(provider) {
                var config = localDnsProviders[provider];
                if (typeof config === 'object' && config !== null) {
                    // Check if this is old single-account format
                    if (config.api_token || config.access_key_id || config.api_key) {
                        populateLegacyProviderFields(provider, config);
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

            var fieldMappings = {
                'cloudflare': [
                    { field: 'cloudflare_api_token', config: 'api_token' }
                ],
                'route53': [
                    { field: 'route53_access_key_id', config: 'access_key_id' },
                    { field: 'route53_secret_access_key', config: 'secret_access_key' },
                    { field: 'route53_region', config: 'region' }
                ],
                'digitalocean': [
                    { field: 'digitalocean_api_token', config: 'api_token' }
                ],
                'azure': [
                    { field: 'azure_subscription_id', config: 'subscription_id' },
                    { field: 'azure_resource_group', config: 'resource_group' },
                    { field: 'azure_tenant_id', config: 'tenant_id' },
                    { field: 'azure_client_id', config: 'client_id' },
                    { field: 'azure_client_secret', config: 'client_secret' }
                ],
                'google': [
                    { field: 'google_project_id', config: 'project_id' },
                    { field: 'google_service_account_key', config: 'service_account_key' }
                ],
                'powerdns': [
                    { field: 'powerdns_api_url', config: 'api_url' },
                    { field: 'powerdns_api_key', config: 'api_key' }
                ]
            };

            var mappings = fieldMappings[provider] || [];
            mappings.forEach(function(mapping) {
                var field = document.getElementById(mapping.field);
                if (field && config[mapping.config]) {
                    field.value = config[mapping.config];
                    addDebugLog('Field ' + mapping.field + ' populated', 'info');
                }
            });
        } catch (error) {
            addDebugLog('Error populating legacy fields for ' + provider + ': ' + error.message, 'warn');
        }
    }

    // =============================================
    // Modal management functions
    // =============================================

    function showAddAccountModal(provider) {
        addDebugLog('Opening add account modal for ' + provider, 'info');

        var modal = document.getElementById('addAccountModal');
        var modalTitle = document.getElementById('modal-title');
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
            'linode': 'Linode',
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
            'nsone': 'NS1'
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

        // Store current provider
        modal.dataset.provider = provider;

        // Show modal
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function closeAddAccountModal() {
        var modal = document.getElementById('addAccountModal');
        if (modal) {
            modal.classList.add('hidden');
            document.body.style.overflow = '';

            // Clear form
            document.getElementById('addAccountForm').reset();
            document.getElementById('modal-provider-fields').innerHTML = '';
        }
    }

    function showEditAccountModal(provider, accountId) {
        addDebugLog('Opening edit account modal for ' + provider + ':' + accountId, 'info');

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
        var account = (providerData && providerData.accounts) ? providerData.accounts.find(function(acc) { return acc.id === accountId; }) : null;

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

        // Show modal
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function closeEditAccountModal() {
        var modal = document.getElementById('editAccountModal');
        if (modal) {
            modal.classList.add('hidden');
            document.body.style.overflow = '';

            // Clear form
            document.getElementById('editAccountForm').reset();
            document.getElementById('edit-modal-provider-fields').innerHTML = '';
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
                { name: 'access_key_id', label: 'Access Key ID', type: 'password', placeholder: 'AKIAIOSFODNN7EXAMPLE', required: true },
                { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', placeholder: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', required: true },
                { name: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1', defaultValue: 'us-east-1', required: false }
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
            'gandi': [
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Your Gandi LiveDNS API token', required: true }
            ],
            'ovh': [
                { name: 'endpoint', label: 'Endpoint', type: 'select', options: [
                    { value: 'ovh-eu', label: 'ovh-eu (Europe)' },
                    { value: 'ovh-us', label: 'ovh-us (US)' },
                    { value: 'ovh-ca', label: 'ovh-ca (Canada)' },
                    { value: 'kimsufi-eu', label: 'kimsufi-eu' },
                    { value: 'kimsufi-ca', label: 'kimsufi-ca' },
                    { value: 'soyoustart-eu', label: 'soyoustart-eu' },
                    { value: 'soyoustart-ca', label: 'soyoustart-ca' }
                ], required: true },
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
                { name: 'tsig_algorithm', label: 'TSIG Algorithm', type: 'select', options: [
                    { value: 'HMAC-MD5', label: 'HMAC-MD5' },
                    { value: 'HMAC-SHA1', label: 'HMAC-SHA1' },
                    { value: 'HMAC-SHA224', label: 'HMAC-SHA224' },
                    { value: 'HMAC-SHA256', label: 'HMAC-SHA256' },
                    { value: 'HMAC-SHA384', label: 'HMAC-SHA384' },
                    { value: 'HMAC-SHA512', label: 'HMAC-SHA512' }
                ], defaultValue: 'HMAC-SHA256', required: false }
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
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Your DNS Made Easy API token', required: true }
            ],
            'nsone': [
                { name: 'api_token', label: 'API Token', type: 'password', placeholder: 'Your NS1 API token', required: true }
            ]
        };

        var fields = fieldMappings[provider] || [];
        var html = '';

        fields.forEach(function(field) {
            var value = escapeHtml(existingData[field.name] || field.defaultValue || '');
            var fieldId = 'modal-' + field.name;

            html += '<div class="mb-4">';
            html += '<label for="' + fieldId + '" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">';
            html += field.label + (field.required ? ' *' : '');
            html += '</label>';

            if (field.type === 'select') {
                html += '<select id="' + fieldId + '" name="' + field.name + '" class="mt-1 block w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary" ' + (field.required ? 'required' : '') + '>';
                if (!field.required) {
                    html += '<option value="">Select ' + field.label.toLowerCase() + '</option>';
                }
                field.options.forEach(function(option) {
                    var selected = value === option.value ? 'selected' : '';
                    html += '<option value="' + option.value + '" ' + selected + '>' + option.label + '</option>';
                });
                html += '</select>';
            } else if (field.type === 'textarea') {
                html += '<textarea id="' + fieldId + '" name="' + field.name + '" rows="4" class="mt-1 block w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary" placeholder="' + field.placeholder + '" ' + (field.required ? 'required' : '') + '>' + value + '</textarea>';
            } else {
                html += '<input type="' + field.type + '" id="' + fieldId + '" name="' + field.name + '" class="mt-1 block w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary focus:border-primary" placeholder="' + field.placeholder + '" value="' + value + '" ' + (field.required ? 'required' : '') + '>';
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

        providerFieldElements.forEach(function(field) {
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
                validationError = (field.placeholder || field.name) + ' is required';
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

        // Send to backend
        fetch('/api/dns/' + provider + '/accounts', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        })
        .then(function(response) {
            if (!response.ok) {
                return response.text().then(function(errorData) {
                    throw new Error('HTTP ' + response.status + ': ' + errorData);
                });
            }
            return response.json();
        })
        .then(function(result) {
            addDebugLog('Account created: ' + result.account_id, 'info');
            showMessage('Account "' + accountName + '" created successfully', 'success');

            // Refresh settings and close modal
            return loadSettings().then(function() {
                closeAddAccountModal();
            });
        })
        .catch(function(error) {
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

        providerFieldElements.forEach(function(field) {
            if (field.name && field.value) {
                accountData[field.name] = field.value;
            }
        });

        addDebugLog('Updated account data: ' + JSON.stringify(accountData, null, 2), 'info');

        // Send to backend
        fetch('/api/dns/' + provider + '/accounts/' + accountId, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accountData)
        })
        .then(function(response) {
            if (!response.ok) {
                return response.text().then(function(errorData) {
                    throw new Error('HTTP ' + response.status + ': ' + errorData);
                });
            }
            return response.json();
        })
        .then(function(result) {
            addDebugLog('Account updated: ' + accountId, 'info');
            showMessage('Account "' + accountData.name + '" updated successfully', 'success');

            // Refresh settings and close modal
            return loadSettings().then(function() {
                closeEditAccountModal();
            });
        })
        .catch(function(error) {
            addDebugLog('Error updating account: ' + error.message, 'error');
            showMessage('Error updating account: ' + error.message, 'error');
        });
    }

    // =============================================
    // Delete account
    // =============================================

    function deleteAccount(provider, accountId) {
        CertMate.confirm('Are you sure you want to delete this account? This action cannot be undone.', 'Delete Account').then(function(confirmed) {
            if (!confirmed) return;

            addDebugLog('Deleting account ' + provider + ':' + accountId, 'info');

            return fetch('/api/dns/' + provider + '/accounts/' + accountId, {
                method: 'DELETE',
                headers: {}
            })
            .then(function(response) {
                if (!response.ok) {
                    return response.text().then(function(t) {
                        throw new Error('HTTP ' + response.status + ': ' + t);
                    });
                }
                addDebugLog('Account deleted: ' + accountId, 'info');
                showMessage('Account deleted successfully', 'success');

                // Refresh settings
                return loadSettings();
            });
        })
        .catch(function(error) {
            addDebugLog('Error deleting account: ' + error.message, 'error');
            showMessage('Error deleting account: ' + error.message, 'error');
        });
    }

    // =============================================
    // Update account lists in the DNS config sections
    // =============================================

    function updateAccountLists() {
        var providers = Object.keys(dnsProviders);

        providers.forEach(function(provider) {
            var accountsListContainer = document.getElementById(provider + '-accounts-list');
            var legacyConfigContainer = document.getElementById(provider + '-legacy-config');

            if (!accountsListContainer) return;

            var providerData = dnsProviders[provider];

            if (providerData && providerData.accounts && providerData.accounts.length > 0) {
                // Show multi-account interface
                accountsListContainer.innerHTML = '';

                providerData.accounts.forEach(function(account) {
                    var isDefault = (currentSettings.default_accounts && currentSettings.default_accounts[provider]) === account.id;
                    var accountCard = createAccountCard(provider, account, isDefault);
                    accountsListContainer.appendChild(accountCard);
                });

                // Hide legacy config if we have multi-account data
                if (legacyConfigContainer && providerData.accounts.some(function(acc) { return acc.id !== 'default'; })) {
                    legacyConfigContainer.style.display = 'none';
                }
            } else {
                // Show legacy config for backward compatibility
                accountsListContainer.innerHTML = '<div class="text-sm text-gray-500 dark:text-gray-400">No accounts configured yet.</div>';
                if (legacyConfigContainer) {
                    legacyConfigContainer.style.display = 'block';
                }
            }
        });
    }

    // =============================================
    // Create account card element
    // =============================================

    function createAccountCard(provider, account, isDefault) {
        var card = document.createElement('div');
        card.className = 'bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg p-4';

        var safeName = escapeHtml(account.name);
        var safeDesc = escapeHtml(account.description);
        var safeId = escapeHtml(account.id);
        var safeProvider = escapeHtml(provider);

        var descHtml = account.description ? '<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">' + safeDesc + '</p>' : '';
        var defaultBadge = isDefault ? '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400"><i class="fas fa-star mr-1"></i>Default</span>' : '';

        card.innerHTML =
            '<div class="flex items-center justify-between">' +
                '<div class="flex-1">' +
                    '<div class="flex items-center space-x-2">' +
                        '<h5 class="text-sm font-medium text-gray-900 dark:text-white">' + safeName + '</h5>' +
                        defaultBadge +
                    '</div>' +
                    descHtml +
                    '<div class="text-xs text-gray-400 dark:text-gray-500 mt-1">ID: ' + safeId + '</div>' +
                '</div>' +
                '<div class="flex items-center space-x-2">' +
                    '<button type="button" data-action="edit" data-provider="' + safeProvider + '" data-account-id="' + safeId + '"' +
                            ' class="inline-flex items-center px-2 py-1 border border-gray-300 dark:border-gray-600 shadow-sm text-xs font-medium rounded text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-600 hover:bg-gray-50 dark:hover:bg-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">' +
                        '<i class="fas fa-edit mr-1"></i>' +
                        'Edit' +
                    '</button>' +
                    '<button type="button" data-action="delete" data-provider="' + safeProvider + '" data-account-id="' + safeId + '"' +
                            ' class="inline-flex items-center px-2 py-1 border border-red-300 shadow-sm text-xs font-medium rounded text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">' +
                        '<i class="fas fa-trash mr-1"></i>' +
                        'Delete' +
                    '</button>' +
                '</div>' +
            '</div>';

        // Attach event listeners safely (no inline onclick with string interpolation)
        card.querySelector('[data-action="edit"]').addEventListener('click', function() { showEditAccountModal(provider, account.id); });
        card.querySelector('[data-action="delete"]').addEventListener('click', function() { deleteAccount(provider, account.id); });
        return card;
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
                reason: 'manual_backup'
            })
        })
        .then(function(response) {
            if (!response.ok) {
                return response.text().then(function(errorData) {
                    throw new Error('HTTP ' + response.status + ': ' + errorData);
                });
            }
            return response.json();
        })
        .then(function(result) {
            if (result.message) {
                addDebugLog('Backup created successfully: ' + result.backups.map(function(b) { return b.filename; }).join(', '), 'info');

                var message = (type === 'unified' ? 'Unified' : type) + ' backup created successfully!';
                if (result.recommendation) {
                    message += ' Note: ' + result.recommendation;
                }
                showMessage(message, 'success');

                // Refresh backup list
                return refreshBackupList();
            } else {
                throw new Error(result.error || 'Failed to create backup');
            }
        })
        .catch(function(error) {
            addDebugLog('Error creating backup: ' + error.message, 'error');
            showMessage('Error creating backup: ' + error.message, 'error');
        })
        .then(function() {
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

    function refreshBackupList() {
        addDebugLog('Refreshing backup list...', 'info');

        return fetch('/api/backups', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }
            return response.json();
        })
        .then(function(backups) {
            updateBackupList(backups);
            addDebugLog('Backup list refreshed: ' + backups.unified.length + ' backups', 'info');
        })
        .catch(function(error) {
            addDebugLog('Error refreshing backup list: ' + error.message, 'error');
            console.error('Error refreshing backup list:', error);

            // Show error in backup list container
            var backupList = document.getElementById('unified-backup-list');
            if (backupList) {
                backupList.innerHTML =
                    '<div class="p-4 text-center text-red-500 dark:text-red-400">' +
                        '<i class="fas fa-exclamation-triangle mr-2"></i>' +
                        'Error loading backups: ' + error.message +
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
                '<div class="p-4 text-center text-gray-500 dark:text-gray-400">' +
                    '<i class="fas fa-archive mr-2"></i>' +
                    'No backups yet' +
                    '<div class="text-xs mt-1">Create your first backup above!</div>' +
                '</div>';
        } else if (backups.unified) {
            var unifiedHtml = '';
            backups.unified.slice(0, 10).forEach(function(backup) {
                var metadata = backup.metadata || {};
                var createdDate = new Date(metadata.created || metadata.timestamp).toLocaleString();
                var sizeMB = Math.round((metadata.size || 0) / (1024 * 1024) * 10) / 10;
                var reason = metadata.backup_reason || metadata.reason || 'manual';
                var domains = metadata.total_domains || (metadata.domains && metadata.domains.length) || 0;

                var safeFilename = escapeHtml(backup.filename);
                var safeReason = escapeHtml(reason);
                unifiedHtml +=
                    '<div class="flex items-center justify-between p-3 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-700">' +
                        '<div class="flex-1 min-w-0">' +
                            '<div class="text-sm font-medium text-gray-900 dark:text-white truncate">' + safeFilename + '</div>' +
                            '<div class="text-xs text-gray-500 dark:text-gray-400 mt-1">' + createdDate + '</div>' +
                            '<div class="flex items-center space-x-3 text-xs text-gray-400 dark:text-gray-500 mt-1">' +
                                '<span><i class="fas fa-weight mr-1"></i>' + sizeMB + 'MB</span>' +
                                '<span><i class="fas fa-archive mr-1"></i>' + domains + ' domains</span>' +
                                '<span><i class="fas fa-tag mr-1"></i>' + safeReason + '</span>' +
                            '</div>' +
                        '</div>' +
                        '<div class="flex space-x-1 ml-2">' +
                            '<button data-action="download-backup" data-backup-type="unified" data-filename="' + safeFilename + '"' +
                                    ' class="p-2 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded transition-colors"' +
                                    ' title="Download backup">' +
                                '<i class="fas fa-download text-sm"></i>' +
                            '</button>' +
                            '<button data-action="restore-backup" data-backup-type="unified" data-filename="' + safeFilename + '"' +
                                    ' class="p-2 text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-300 hover:bg-green-50 dark:hover:bg-green-900/30 rounded transition-colors"' +
                                    ' title="Restore backup">' +
                                '<i class="fas fa-undo text-sm"></i>' +
                            '</button>' +
                            '<button data-action="delete-backup" data-backup-type="unified" data-filename="' + safeFilename + '"' +
                                    ' class="p-2 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 rounded transition-colors"' +
                                    ' title="Delete backup">' +
                                '<i class="fas fa-trash text-sm"></i>' +
                            '</button>' +
                        '</div>' +
                    '</div>';
            });

            if (backups.unified.length > 10) {
                unifiedHtml +=
                    '<div class="text-xs text-gray-500 dark:text-gray-400 text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">' +
                        '<i class="fas fa-ellipsis-h mr-1"></i>' +
                        (backups.unified.length - 10) + ' more backups available' +
                    '</div>';
            }

            unifiedBackupList.innerHTML = unifiedHtml;

            // Bind backup action buttons via event delegation
            unifiedBackupList.querySelectorAll('button[data-action]').forEach(function(btn) {
                btn.addEventListener('click', function() {
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
        .then(function(response) {
            if (!response.ok) {
                return response.text().then(function(errorText) {
                    throw new Error('HTTP ' + response.status + ': ' + errorText);
                });
            }
            return response.blob();
        })
        .then(function(blob) {
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
        .catch(function(error) {
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

        CertMate.confirm('Are you sure you want to restore from "' + escapeHtml(filename) + '"? This will atomically restore both settings and certificates, creating a backup of your current configuration first.', 'Restore Backup').then(function(confirmed) {
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
            .then(function(response) {
                if (!response.ok) {
                    return response.text().then(function(errorData) {
                        throw new Error('HTTP ' + response.status + ': ' + errorData);
                    });
                }
                return response.json();
            })
            .then(function(result) {
                addDebugLog('Backup restored successfully from: ' + filename, 'info');

                var successMessage = result.message || 'Backup restored successfully!';
                if (result.pre_restore_backup) {
                    successMessage += '\n\nA backup of the previous state was created: ' + result.pre_restore_backup;
                }

                // Show immediate success message
                showMessage(successMessage, 'success');

                // Try to reload the settings data and refresh the UI
                return loadSettings(true)
                    .then(function() {
                        return refreshBackupList();
                    })
                    .then(function() {
                        addDebugLog('Settings reloaded successfully after restore', 'info');
                        showMessage('Backup restored and configuration reloaded successfully!', 'success');
                    })
                    .catch(function(reloadError) {
                        addDebugLog('Settings reload failed after successful restore: ' + reloadError.message, 'warn');
                        showMessage('Backup restored successfully! Please refresh the page to see all changes.', 'success');

                        // Fallback to page reload after a delay
                        setTimeout(function() {
                            addDebugLog('Auto-refreshing page after restore...', 'info');
                            window.location.reload();
                        }, 3000);
                    });
            });
        })
        .catch(function(error) {
            addDebugLog('Error during backup restore: ' + error.message, 'error');
            showMessage('Error restoring backup: ' + error.message, 'error');
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

        CertMate.confirm('Are you sure you want to delete the backup "' + escapeHtml(filename) + '"? This action cannot be undone.', 'Delete Backup').then(function(confirmed) {
            if (!confirmed) return;

            addDebugLog('Deleting backup: ' + filename, 'info');

            return fetch('/api/backups/delete/unified/' + filename, {
                method: 'DELETE',
                headers: {}
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                return response.json();
            })
            .then(function(result) {
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
        .catch(function(error) {
            addDebugLog('Error deleting backup: ' + error.message, 'error');
            showMessage('Error deleting backup: ' + error.message, 'error');
        });
    }

    // =============================================
    // CA PROVIDER MANAGEMENT FUNCTIONS
    // =============================================

    function toggleCAProviderConfig() {
        var caProvider = document.getElementById('default-ca').value;

        // Map CA provider values to config IDs
        var caProviderToConfigId = {
            'letsencrypt': 'letsencrypt-config',
            'digicert': 'digicert-config',
            'private_ca': 'private-ca-config'
        };

        // Hide all CA configuration panels and disable their required fields
        var caConfigs = ['letsencrypt-config', 'digicert-config', 'private-ca-config'];
        caConfigs.forEach(function(configId) {
            var element = document.getElementById(configId);
            if (element) {
                element.style.display = 'none';
                // Disable required validation for hidden fields
                var requiredFields = element.querySelectorAll('[required]');
                requiredFields.forEach(function(field) {
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
            requiredFields.forEach(function(field) {
                field.setAttribute('required', '');
            });
        }

        // Update hint text based on selected CA
        var hintElement = document.getElementById('ca-test-hint');
        if (hintElement) {
            switch (caProvider) {
                case 'letsencrypt':
                    hintElement.textContent = 'Enter your email address and test Let\'s Encrypt connection';
                    break;
                case 'digicert':
                    hintElement.textContent = 'Enter ACME URL, EAB credentials, and email, then test DigiCert connection';
                    break;
                case 'private_ca':
                    hintElement.textContent = 'Enter your ACME directory URL and email, then test Private CA connection';
                    break;
                default:
                    hintElement.textContent = 'Select a CA provider and fill in required fields, then test the connection';
            }
        }
    }

    // =============================================
    // Test CA Provider
    // =============================================

    function testCAProvider() {
        var caProvider = document.getElementById('default-ca').value;
        var config = {};
        var missingFields = [];

        if (caProvider === 'letsencrypt') {
            var leEmail = document.getElementById('letsencrypt-email').value;
            if (!leEmail.trim()) {
                missingFields.push('Email');
            }
            config = {
                environment: document.getElementById('letsencrypt-environment').value,
                email: leEmail
            };
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
        var testButton = document.querySelector('button[onclick="testCAProvider()"]');
        var originalText = testButton.innerHTML;
        testButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Testing...';
        testButton.disabled = true;

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
        .then(function(response) {
            return response.json().then(function(result) {
                if (response.ok && result.success) {
                    showMessage('CA connection test successful! ' + result.message, 'success');
                } else {
                    var errorMsg = result.message || result.error || 'Unknown error occurred';
                    showMessage('CA connection test failed: ' + errorMsg, 'error');
                }
            });
        })
        .catch(function(error) {
            console.error('Error testing CA provider:', error);
            showMessage('Error testing CA provider connection. Please check your network connection.', 'error');
        })
        .then(function() {
            // finally block equivalent - restore button state
            testButton.innerHTML = originalText;
            testButton.disabled = false;
        });
    }

    // =============================================
    // STORAGE BACKEND MANAGEMENT FUNCTIONS
    // =============================================

    function toggleStorageBackendConfig() {
        var backend = document.getElementById('storage-backend').value;
        var configs = document.querySelectorAll('.storage-config');

        // Hide all configuration panels
        configs.forEach(function(config) {
            config.style.display = 'none';
        });

        // Map backend names to their corresponding config div IDs
        var backendToConfigId = {
            'local_filesystem': 'storage-local-config',
            'azure_keyvault': 'storage-azure-config',
            'aws_secrets_manager': 'storage-aws-config',
            'hashicorp_vault': 'storage-vault-config',
            'infisical': 'storage-infisical-config'
        };

        // Show the selected configuration panel
        var configId = backendToConfigId[backend];
        if (configId) {
            var selectedConfig = document.getElementById(configId);
            if (selectedConfig) {
                selectedConfig.style.display = 'block';
            }
        }
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
        .then(function(response) {
            if (!response.ok) {
                throw new Error('HTTP error! status: ' + response.status);
            }

            return response.json();
        })
        .then(function(data) {
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
        .catch(function(error) {
            console.error('Storage backend test error:', error);
            showMessage('Failed to test storage backend connection: ' + error.message, 'error');
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
                break;

            case 'aws_secrets_manager':
                config.region = document.getElementById('aws-region').value || 'us-east-1';
                config.access_key_id = document.getElementById('aws-access-key-id').value;
                config.secret_access_key = document.getElementById('aws-secret-access-key').value;
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
        }

        return config;
    }

    function validateStorageConfig(backend, config) {
        switch (backend) {
            case 'local_filesystem':
                return config.cert_dir && config.cert_dir.trim() !== '';

            case 'azure_keyvault':
                return config.vault_url && config.tenant_id && config.client_id && config.client_secret;

            case 'aws_secrets_manager':
                return config.access_key_id && config.secret_access_key;

            case 'hashicorp_vault':
                return config.vault_url && config.vault_token;

            case 'infisical':
                return config.client_id && config.client_secret && config.project_id;

            default:
                return false;
        }
    }

    // =============================================
    // CA Provider settings load/collect
    // =============================================

    function loadCAProviderSettings(settings) {
        // Set default CA provider
        var defaultCA = settings.default_ca || 'letsencrypt';
        document.getElementById('default-ca').value = defaultCA;
        toggleCAProviderConfig();

        // Load CA provider configurations
        var caProviders = settings.ca_providers || {};

        // Load Let's Encrypt settings
        var letsencryptConfig = caProviders.letsencrypt || {};
        if (letsencryptConfig.environment) {
            document.getElementById('letsencrypt-environment').value = letsencryptConfig.environment;
        }
        if (letsencryptConfig.email) {
            document.getElementById('letsencrypt-email').value = letsencryptConfig.email;
        }

        // Load DigiCert settings
        var digicertConfig = caProviders.digicert || {};
        if (digicertConfig.acme_url) {
            document.getElementById('digicert-acme-url').value = digicertConfig.acme_url;
        }
        if (digicertConfig.eab_kid) {
            document.getElementById('digicert-eab-kid').value = digicertConfig.eab_kid;
        }
        // Don't populate HMAC key for security reasons - user needs to re-enter
        if (digicertConfig.email) {
            document.getElementById('digicert-email').value = digicertConfig.email;
        }

        // Load Private CA settings
        var privateCaConfig = caProviders.private_ca || {};
        if (privateCaConfig.acme_url) {
            document.getElementById('private-ca-acme-url').value = privateCaConfig.acme_url;
        }
        if (privateCaConfig.ca_cert) {
            document.getElementById('private-ca-cert').value = privateCaConfig.ca_cert;
        }
        if (privateCaConfig.eab_kid) {
            document.getElementById('private-ca-eab-kid').value = privateCaConfig.eab_kid;
        }
        // Don't populate HMAC key for security reasons - user needs to re-enter
        if (privateCaConfig.email) {
            document.getElementById('private-ca-email').value = privateCaConfig.email;
        }
    }

    function loadStorageBackendSettings(settings) {
        var storageConfig = settings.certificate_storage || {};
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
                var azureConfig = storageConfig.azure_keyvault || {};
                document.getElementById('azure-vault-url').value = azureConfig.vault_url || '';
                document.getElementById('azure-tenant-id').value = azureConfig.tenant_id || '';
                document.getElementById('azure-client-id').value = azureConfig.client_id || '';
                // Don't populate client_secret for security
                break;

            case 'aws_secrets_manager':
                var awsConfig = storageConfig.aws_secrets_manager || {};
                document.getElementById('aws-region').value = awsConfig.region || 'us-east-1';
                document.getElementById('aws-access-key-id').value = awsConfig.access_key_id || '';
                // Don't populate secret_access_key for security
                break;

            case 'hashicorp_vault':
                var vaultConfig = storageConfig.hashicorp_vault || {};
                document.getElementById('vault-url').value = vaultConfig.vault_url || '';
                document.getElementById('vault-mount-point').value = vaultConfig.mount_point || 'secret';
                document.getElementById('vault-engine-version').value = vaultConfig.engine_version || 'v2';
                // Don't populate vault_token for security
                break;

            case 'infisical':
                var infisicalConfig = storageConfig.infisical || {};
                document.getElementById('infisical-site-url').value = infisicalConfig.site_url || 'https://app.infisical.com';
                document.getElementById('infisical-project-id').value = infisicalConfig.project_id || '';
                document.getElementById('infisical-environment').value = infisicalConfig.environment || 'prod';
                // Don't populate client credentials for security
                break;
        }
    }

    function collectCAProviderSettings() {
        var caProviders = {};

        // Let's Encrypt configuration
        caProviders.letsencrypt = {
            environment: document.getElementById('letsencrypt-environment').value || 'production',
            email: document.getElementById('letsencrypt-email').value || ''
        };

        // DigiCert configuration
        caProviders.digicert = {
            acme_url: document.getElementById('digicert-acme-url').value || 'https://acme.digicert.com/v2/acme/directory',
            eab_kid: document.getElementById('digicert-eab-kid').value || '',
            eab_hmac: document.getElementById('digicert-eab-hmac').value || '',
            email: document.getElementById('digicert-email').value || ''
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

        return Object.assign({ backend: backend }, config);
    }

    // =============================================
    // Storage migration
    // =============================================

    function showStorageMigrationModal() {
        // Create migration modal dynamically
        var modal = document.createElement('div');
        modal.id = 'storageMigrationModal';
        modal.className = 'fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50';
        modal.innerHTML =
            '<div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white dark:bg-gray-800">' +
                '<div class="mt-3">' +
                    '<div class="flex items-center justify-between mb-4">' +
                        '<h3 class="text-lg font-medium text-gray-900 dark:text-white">' +
                            '<i class="fas fa-exchange-alt mr-2"></i>Certificate Storage Migration' +
                        '</h3>' +
                        '<button type="button" onclick="closeStorageMigrationModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">' +
                            '<i class="fas fa-times"></i>' +
                        '</button>' +
                    '</div>' +
                    '<div class="mb-4">' +
                        '<p class="text-sm text-gray-600 dark:text-gray-400">' +
                            'This will migrate all existing certificates from the current storage backend to the newly configured backend.' +
                        '</p>' +
                        '<div class="mt-3 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-md">' +
                            '<div class="flex">' +
                                '<i class="fas fa-exclamation-triangle text-yellow-400 mt-0.5 mr-2"></i>' +
                                '<div class="text-sm text-yellow-800 dark:text-yellow-200">' +
                                    '<strong>Important:</strong> This operation will copy certificates to the new backend. ' +
                                    'Original certificates will remain in the current location until manually removed.' +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="flex justify-end space-x-3">' +
                        '<button type="button" onclick="closeStorageMigrationModal()" ' +
                                'class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-md">' +
                            'Cancel' +
                        '</button>' +
                        '<button type="button" onclick="performStorageMigration()" ' +
                                'class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md">' +
                            '<i class="fas fa-play mr-1"></i>Start Migration' +
                        '</button>' +
                    '</div>' +
                '</div>' +
            '</div>';
        document.body.appendChild(modal);
    }

    function closeStorageMigrationModal() {
        var modal = document.getElementById('storageMigrationModal');
        if (modal) {
            modal.remove();
        }
    }

    function performStorageMigration() {
        var currentBackend = document.getElementById('storage-backend').value;
        var newConfig = collectStorageBackendSettings();

        // Validate new configuration first
        if (!validateStorageConfig(newConfig.backend, newConfig)) {
            showMessage('Please configure and test the new storage backend before migrating.', 'error');
            return;
        }

        showMessage('Starting certificate migration...', 'info');
        closeStorageMigrationModal();

        fetch('/api/storage/migrate', {
            method: 'POST',
            headers: API_HEADERS,
            body: JSON.stringify({
                source_backend: currentBackend,
                target_config: newConfig
            })
        })
        .then(function(response) { return response.json(); })
        .then(function(data) {
            if (data.success) {
                showMessage('Migration completed successfully. ' + (data.migrated_count || 0) + ' certificates migrated.', 'success');
            } else {
                showMessage('Migration failed: ' + (data.message || 'Unknown error'), 'error');
            }
        })
        .catch(function(error) {
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
        .then(function(response) {
            if (response.ok) {
                return response.json().then(function(data) {
                    document.getElementById('localAuthToggle').checked = data.local_auth_enabled;
                    var banner = document.getElementById('authSecurityBanner');
                    if (banner) banner.style.display = data.local_auth_enabled ? 'none' : 'block';
                    return data;
                });
            }
            return null;
        })
        .catch(function(error) {
            console.error('Error loading auth config:', error);
            return null;
        });
    }

    function toggleLocalAuth() {
        var toggle = document.getElementById('localAuthToggle');
        var enabled = toggle.checked;

        fetch('/api/auth/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ local_auth_enabled: enabled })
        })
        .then(function(response) {
            return response.json().then(function(data) {
                if (response.ok) {
                    showMessage(data.message, 'success');
                    var banner = document.getElementById('authSecurityBanner');
                    if (banner) banner.style.display = enabled ? 'none' : 'block';
                } else {
                    showMessage(data.error || 'Failed to update auth config', 'error');
                    toggle.checked = !enabled; // Revert toggle
                }
            });
        })
        .catch(function(error) {
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

        fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: username, password: password, email: email || null, role: role })
        })
        .then(function(response) {
            return response.json().then(function(data) {
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
        .catch(function(error) {
            console.error('Error creating user:', error);
            showMessage('Failed to create user', 'error');
        });
    }

    function refreshUserList() {
        var userListDiv = document.getElementById('userList');
        userListDiv.innerHTML = '<div class="text-center py-4 text-gray-500 dark:text-gray-400 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i> Loading users...</div>';

        fetch('/api/users', {
            headers: {}
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error('Failed to fetch users');
            }
            return response.json();
        })
        .then(function(data) {
            var users = data.users || {};

            if (Object.keys(users).length === 0) {
                userListDiv.innerHTML = '<div class="text-center py-4 text-gray-500 dark:text-gray-400 text-sm"><i class="fas fa-users mr-2"></i> No users configured. Add a user above to enable local authentication.</div>';
                return;
            }

            var html = '';
            Object.keys(users).forEach(function(username) {
                var userInfo = users[username];
                var roleColor = userInfo.role === 'admin' ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300' : userInfo.role === 'operator' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' : 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300';
                var statusColor = userInfo.enabled !== false ? 'text-green-500' : 'text-red-500';
                var lastLogin = userInfo.last_login ? new Date(userInfo.last_login).toLocaleString() : 'Never';

                var emailHtml = userInfo.email ? '<span class="mr-3"><i class="fas fa-envelope mr-1"></i>' + escapeHtml(userInfo.email) + '</span>' : '';

                html +=
                    '<div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">' +
                        '<div class="flex items-center space-x-3">' +
                            '<i class="fas fa-user-circle text-2xl text-gray-400 dark:text-gray-500"></i>' +
                            '<div>' +
                                '<div class="flex items-center space-x-2">' +
                                    '<span class="font-medium text-gray-900 dark:text-white">' + escapeHtml(username) + '</span>' +
                                    '<span class="text-xs px-2 py-0.5 rounded-full ' + roleColor + '">' + escapeHtml(userInfo.role || '') + '</span>' +
                                    '<i class="fas fa-circle text-xs ' + statusColor + '" title="' + (userInfo.enabled !== false ? 'Active' : 'Disabled') + '"></i>' +
                                '</div>' +
                                '<div class="text-xs text-gray-500 dark:text-gray-400">' +
                                    emailHtml +
                                    '<span><i class="fas fa-clock mr-1"></i>Last login: ' + escapeHtml(lastLogin) + '</span>' +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="flex items-center space-x-2">' +
                            '<button data-action="toggle-user" data-username="' + escapeHtml(username) + '" data-enable="' + (userInfo.enabled === false) + '"' +
                                    ' class="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"' +
                                    ' title="' + (userInfo.enabled !== false ? 'Disable user' : 'Enable user') + '">' +
                                '<i class="fas fa-' + (userInfo.enabled !== false ? 'ban' : 'check') + '"></i>' +
                            '</button>' +
                            '<button data-action="reset-password" data-username="' + escapeHtml(username) + '"' +
                                    ' class="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"' +
                                    ' title="Reset password">' +
                                '<i class="fas fa-key"></i>' +
                            '</button>' +
                            '<button data-action="delete-user" data-username="' + escapeHtml(username) + '"' +
                                    ' class="p-2 text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"' +
                                    ' title="Delete user">' +
                                '<i class="fas fa-trash"></i>' +
                            '</button>' +
                        '</div>' +
                    '</div>';
            });

            userListDiv.innerHTML = html;

            // Bind user action buttons via event delegation
            userListDiv.querySelectorAll('button[data-action]').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var user = btn.dataset.username;
                    switch (btn.dataset.action) {
                        case 'toggle-user': toggleUserStatus(user, btn.dataset.enable === 'true'); break;
                        case 'reset-password': resetUserPassword(user); break;
                        case 'delete-user': deleteUser(user); break;
                    }
                });
            });
        })
        .catch(function(error) {
            console.error('Error loading users:', error);
            userListDiv.innerHTML = '<div class="text-center py-4 text-red-500 text-sm"><i class="fas fa-exclamation-triangle mr-2"></i> Failed to load users</div>';
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
        .then(function(response) {
            return response.json().then(function(data) {
                if (response.ok) {
                    showMessage('User \'' + username + '\' ' + (enable ? 'enabled' : 'disabled'), 'success');
                    refreshUserList();
                } else {
                    showMessage(data.error || 'Failed to update user', 'error');
                }
            });
        })
        .catch(function(error) {
            console.error('Error toggling user status:', error);
            showMessage('Failed to update user status', 'error');
        });
    }

    function resetUserPassword(username) {
        CertMate.prompt('Enter new password for \'' + escapeHtml(username) + '\':', 'Reset Password').then(function(newPassword) {
            if (!newPassword) return;

            fetch('/api/users/' + username, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: newPassword })
            })
            .then(function(response) {
                return response.json().then(function(data) {
                    if (response.ok) {
                        showMessage('Password reset for \'' + username + '\'', 'success');
                    } else {
                        showMessage(data.error || 'Failed to reset password', 'error');
                    }
                });
            })
            .catch(function(error) {
                console.error('Error resetting password:', error);
                showMessage('Failed to reset password', 'error');
            });
        });
    }

    function deleteUser(username) {
        CertMate.confirm('Are you sure you want to delete user \'' + escapeHtml(username) + '\'? This action cannot be undone.', 'Delete User').then(function(confirmed) {
            if (!confirmed) return;

            fetch('/api/users/' + username, {
                method: 'DELETE',
                headers: {}
            })
            .then(function(response) {
                return response.json().then(function(data) {
                    if (response.ok) {
                        showMessage('User \'' + username + '\' deleted', 'success');
                        refreshUserList();
                    } else {
                        showMessage(data.error || 'Failed to delete user', 'error');
                    }
                });
            })
            .catch(function(error) {
                console.error('Error deleting user:', error);
                showMessage('Failed to delete user', 'error');
            });
        });
    }

    // =============================================
    // DOMContentLoaded - consolidated
    // =============================================

    document.addEventListener('DOMContentLoaded', function() {
        form = document.getElementById('settingsForm');
        saveBtn = document.getElementById('saveBtn');
        statusMessage = document.getElementById('statusMessage');

        addDebugLog('DOM loaded, initializing settings page', 'info');

        // Add challenge type radio listeners
        document.querySelectorAll('input[name="challenge_type"]').forEach(function(radio) {
            radio.addEventListener('change', function() {
                toggleChallengeType();
                addDebugLog('Challenge type changed to: ' + this.value, 'info');
            });
        });

        // Add radio button listeners
        document.querySelectorAll('input[name="dns_provider"]').forEach(function(radio) {
            radio.addEventListener('change', function() {
                if (this.checked) {
                    showDNSConfig(this.value);
                    addDebugLog('DNS provider changed to: ' + this.value, 'info');
                }
            });
        });

        // Load settings on page load
        loadSettings();

        // Initialize CA provider configuration visibility
        toggleCAProviderConfig();

        // Refresh cache stats on load
        refreshCacheStats();

        // Form submit handler
        if (form) {
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                addDebugLog('Settings form submitted', 'info');
                saveSettings();
            });
        }

        // Backup list (delayed)
        setTimeout(function() { refreshBackupList(); }, 1000);

        // User management (delayed)
        setTimeout(function() {
            loadAuthConfig();
            refreshUserList();
        }, 500);
    });

    // =============================================
    // Window exposures needed by HTML onclick/onchange/x-data
    // =============================================

    window.notificationSettings = notificationSettings;
    window.showAddAccountModal = showAddAccountModal;
    window.closeAddAccountModal = closeAddAccountModal;
    window.saveAccount = saveAccount;
    window.showEditAccountModal = showEditAccountModal;
    window.closeEditAccountModal = closeEditAccountModal;
    window.saveEditAccount = saveEditAccount;
    window.deleteAccount = deleteAccount;
    window.toggleCAProviderConfig = toggleCAProviderConfig;
    window.testCAProvider = testCAProvider;
    window.toggleTokenVisibility = toggleTokenVisibility;
    window.generateToken = generateToken;
    window.toggleStorageBackendConfig = toggleStorageBackendConfig;
    window.testStorageBackend = testStorageBackend;
    window.showStorageMigrationModal = showStorageMigrationModal;
    window.closeStorageMigrationModal = closeStorageMigrationModal;
    window.performStorageMigration = performStorageMigration;
    window.toggleLocalAuth = toggleLocalAuth;
    window.createUser = createUser;
    window.refreshUserList = refreshUserList;
    window.createBackup = createBackup;
    window.refreshBackupList = refreshBackupList;
    window.downloadBackup = downloadBackup;
    window.restoreBackup = restoreBackup;
    window.deleteBackup = deleteBackup;
    window.clearDebugConsole = clearDebugConsole;
    window.toggleDebugConsole = toggleDebugConsole;
    window.toggleChallengeType = toggleChallengeType;
    window.toggleUserStatus = toggleUserStatus;
    window.resetUserPassword = resetUserPassword;
    window.deleteUser = deleteUser;
    window.clearDeploymentCache = clearDeploymentCache;
    window.refreshCacheStats = refreshCacheStats;

})();
