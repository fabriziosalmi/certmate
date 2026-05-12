"""
DNS providers management module for CertMate
Handles DNS provider configuration, account management, and provider-specific operations
"""

import logging

logger = logging.getLogger(__name__)


class DNSManager:
    """Class to handle DNS provider management"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager

    # Canonical list of supported DNS providers
    SUPPORTED_PROVIDERS = [
        'cloudflare', 'route53', 'azure', 'google', 'digitalocean',
        'namecheap', 'godaddy', 'linode', 'ovh', 'hetzner',
        'rfc2136', 'powerdns', 'desec',
    ]

    def get_available_providers(self):
        """List available DNS providers and their configuration status.

        Returns a list of dicts with provider name, label, and whether
        at least one account with credentials is configured.
        """
        settings = self.settings_manager.load_settings()
        settings = self.settings_manager.migrate_dns_providers_to_multi_account(settings)
        dns_providers = settings.get('dns_providers', {})

        result = []
        for provider in self.SUPPORTED_PROVIDERS:
            accounts = self.list_dns_provider_accounts(provider, settings=settings)
            configured = any(a.get('configured') for a in accounts)
            result.append({
                'name': provider,
                'label': provider.replace('_', ' ').title(),
                'configured': configured,
                'accounts': len(accounts),
            })
        return result

    def get_dns_provider_account_config(self, provider, account_id=None, settings=None):
        """Get DNS provider account configuration
        
        Args:
            provider: DNS provider name (e.g., 'cloudflare')
            account_id: Specific account ID (optional, uses default if not provided)
            settings: Settings dict (optional, loads current if not provided)
            
        Returns:
            tuple: (account_config_dict, used_account_id)
        """
        try:
            if not settings:
                settings = self.settings_manager.load_settings()
                
            # Ensure migration is applied
            settings = self.settings_manager.migrate_dns_providers_to_multi_account(settings)
            
            dns_providers = settings.get('dns_providers', {})
            provider_config = dns_providers.get(provider, {})
            
            if not isinstance(provider_config, dict) or not provider_config:
                return None, None
            
            # Check if this is multi-account format (has 'accounts' key)
            if 'accounts' in provider_config:
                accounts = provider_config['accounts']
                if not isinstance(accounts, dict):
                    return None, None
                
                # If account_id is specified, look for it directly
                if account_id:
                    if account_id in accounts:
                        account_config = accounts[account_id]
                        if isinstance(account_config, dict):
                            return account_config, account_id
                    else:
                        logger.warning(f"Account '{account_id}' not found for provider '{provider}'")
                        return None, None
                
                # If no account_id specified, try to use default account
                default_accounts = settings.get('default_accounts', {})
                default_account_id = default_accounts.get(provider)
                
                if default_account_id and default_account_id in accounts:
                    account_config = accounts[default_account_id]
                    if isinstance(account_config, dict):
                        return account_config, default_account_id
                
                # If we get here and no account_id was specified, try to use the first available account
                for acc_id, acc_config in accounts.items():
                    if isinstance(acc_config, dict) and any(key in acc_config for key in [
                        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                    ]):
                        return acc_config, acc_id
                
                return None, None
            else:
                # Check if this is old single-account format (has direct config keys)
                if any(key in provider_config for key in [
                    'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                ]):
                    # This is old single-account format
                    return provider_config, 'default'
                
                # If we get here, it's multi-account format but structured differently
                # Try to find account configs directly under provider
                if account_id:
                    # Look for specific account
                    if account_id in provider_config:
                        account_config = provider_config[account_id]
                        if isinstance(account_config, dict):
                            return account_config, account_id
                    # Specific account requested but not found
                    return None, None
                else:
                    # No specific account requested - try default or first available
                    default_accounts = settings.get('default_accounts', {})
                    default_account_id = default_accounts.get(provider)
                    
                    # Try default account first
                    if default_account_id and default_account_id in provider_config:
                        account_config = provider_config[default_account_id]
                        if isinstance(account_config, dict):
                            return account_config, default_account_id
                    
                    # Fall back to first available account
                    for acc_id, acc_config in provider_config.items():
                        if isinstance(acc_config, dict) and any(key in acc_config for key in [
                            'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token'
                        ]):
                            return acc_config, acc_id
                
                return None, None
                    
        except Exception as e:
            logger.error(f"Error getting DNS provider account config for {provider}: {e}")
            return None, None

    def list_dns_provider_accounts(self, provider, settings=None):
        """List all accounts for a DNS provider
        
        Args:
            provider: DNS provider name
            settings: Settings dict (optional, loads current if not provided)
            
        Returns:
            list: List of account configurations with metadata
        """
        try:
            if not settings:
                settings = self.settings_manager.load_settings()
                
            # Ensure migration is applied
            settings = self.settings_manager.migrate_dns_providers_to_multi_account(settings)
            
            dns_providers = settings.get('dns_providers', {})
            provider_config = dns_providers.get(provider, {})
            
            accounts = []
            
            if 'accounts' in provider_config:
                # Multi-account format
                for account_id, account_config in provider_config['accounts'].items():
                    accounts.append({
                        'account_id': account_id,
                        'name': account_config.get('name', account_id.title()),
                        'description': account_config.get('description', ''),
                        'configured': bool(any(account_config.get(key) for key in [
                            'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token',
                            'nameserver', 'tsig_key', 'tsig_secret', 'secret_key', 'password'
                        ]))
                    })
            elif provider_config:
                # Legacy single-account format
                accounts.append({
                    'account_id': 'default',
                    'name': f'Default {provider.title()} Account',
                    'description': 'Legacy single-account configuration',
                    'configured': bool(any(provider_config.get(key) for key in [
                        'api_token', 'access_key_id', 'api_key', 'api_url', 'username', 'token',
                        'nameserver', 'tsig_key', 'tsig_secret', 'secret_key', 'password'
                    ]))
                })
                
            return accounts
            
        except Exception as e:
            logger.error(f"Error listing DNS provider accounts for {provider}: {e}")
            return []

    def list_accounts(self, settings=None):
        """List all accounts for all providers"""
        try:
            if not settings:
                settings = self.settings_manager.load_settings()
            settings = self.settings_manager.migrate_dns_providers_to_multi_account(settings)
            dns_providers = settings.get('dns_providers', {})
            all_accounts = []
            for provider in dns_providers:
                accounts = self.list_dns_provider_accounts(provider, settings=settings)
                for acc in accounts:
                    acc['provider'] = provider
                all_accounts.extend(accounts)
            return all_accounts
        except Exception as e:
            logger.error(f"Error listing all DNS accounts: {e}")
            return []

    def suggest_dns_provider_for_domain(self, domain, settings=None):
        """Suggest DNS provider based on domain patterns and existing configuration
        
        Args:
            domain: Domain name to analyze
            settings: Current settings (optional)
            
        Returns:
            tuple: (suggested_provider, confidence_level)
        """
        if not domain:
            return None, 0
        
        # Load settings if not provided
        if settings is None:
            settings = self.settings_manager.load_settings()
        
        # Check if domain already exists in settings
        existing_domains = settings.get('domains', [])
        for domain_config in existing_domains:
            if isinstance(domain_config, dict):
                if domain_config.get('domain') == domain:
                    return domain_config.get('dns_provider', 'cloudflare'), 90  # High confidence
            elif domain_config == domain:
                # Old format, use global provider
                return settings.get('dns_provider', 'cloudflare'), 80
        
        # Pattern-based suggestions
        domain_lower = domain.lower()
        
        # AWS/Route53 patterns
        if any(pattern in domain_lower for pattern in ['aws', 'amazon', 'route53', 'test.certmate.org']):
            return 'route53', 70
        
        # Cloudflare patterns
        if any(pattern in domain_lower for pattern in ['cf-', 'cloudflare', 'audiolibri.org']):
            return 'cloudflare', 70
        
        # DigitalOcean patterns
        if any(pattern in domain_lower for pattern in ['do-', 'digitalocean']):
            return 'digitalocean', 70
        
        # Default to global setting
        return settings.get('dns_provider', 'cloudflare'), 30

    def create_dns_account(self, provider, account_id, account_config, settings=None):
        """Create or update a DNS provider account.

        The ``settings`` parameter is accepted for backward compatibility
        but ignored — the read/modify/write happens under the settings
        manager's lock so two concurrent admins editing different
        accounts can no longer race and lose each other's changes.
        """
        try:
            def _mutate(settings):
                # Migration mutates the settings dict in place.
                self.settings_manager.migrate_dns_providers_to_multi_account(settings)

                if 'dns_providers' not in settings:
                    settings['dns_providers'] = {}
                if provider not in settings['dns_providers']:
                    settings['dns_providers'][provider] = {}

                provider_config = settings['dns_providers'][provider]
                if 'accounts' not in provider_config:
                    provider_config['accounts'] = {}
                provider_config['accounts'][account_id] = account_config

                # First account for this provider becomes the default.
                if 'default_accounts' not in settings:
                    settings['default_accounts'] = {}
                if provider not in settings['default_accounts']:
                    settings['default_accounts'][provider] = account_id

            success = self.settings_manager.update(
                _mutate, f"dns_account_create_{provider}_{account_id}"
            )
            if success:
                logger.info(f"Created/updated DNS account '{account_id}' for provider '{provider}'")
            return success

        except Exception as e:
            logger.error(f"Error creating DNS account for {provider}: {e}")
            return False

    def add_account(self, account_id, provider, account_config, settings=None):
        """Alias for create_dns_account with consistent naming"""
        return self.create_dns_account(provider, account_id, account_config, settings)

    def delete_dns_account(self, provider, account_id, settings=None):
        """Delete a DNS provider account.

        The ``settings`` parameter is accepted for backward compatibility
        but ignored — read/modify/write happens under the settings lock.
        """
        try:
            outcome = {'ok': False}

            def _mutate(settings):
                dns_providers = settings.get('dns_providers', {})
                provider_config = dns_providers.get(provider, {})
                if 'accounts' not in provider_config:
                    logger.warning(f"No accounts found for provider '{provider}'")
                    return
                if account_id not in provider_config['accounts']:
                    logger.warning(f"Account '{account_id}' not found for provider '{provider}'")
                    return

                del provider_config['accounts'][account_id]

                default_accounts = settings.get('default_accounts', {})
                if default_accounts.get(provider) == account_id:
                    remaining = list(provider_config['accounts'].keys())
                    if remaining:
                        default_accounts[provider] = remaining[0]
                    else:
                        del default_accounts[provider]
                outcome['ok'] = True

            saved = self.settings_manager.update(
                _mutate, f"dns_account_delete_{provider}_{account_id}"
            )
            if not outcome['ok']:
                return False
            if saved:
                logger.info(f"Deleted DNS account '{account_id}' for provider '{provider}'")
            return saved

        except Exception as e:
            logger.error(f"Error deleting DNS account for {provider}: {e}")
            return False

    def delete_account(self, provider, account_id, settings=None):
        """Alias for delete_dns_account with consistent naming"""
        return self.delete_dns_account(provider, account_id, settings)

    def set_default_account(self, provider, account_id, settings=None):
        """Set the default account for a DNS provider (atomic).

        The ``settings`` parameter is accepted for backward compatibility
        but ignored — read/modify/write happens under the settings lock.
        """
        try:
            outcome = {'ok': False}

            def _mutate(settings):
                _, existing_account_id = self.get_dns_provider_account_config(
                    provider, account_id, settings
                )
                if not existing_account_id:
                    logger.warning(f"Account '{account_id}' not found for provider '{provider}'")
                    return
                if 'default_accounts' not in settings:
                    settings['default_accounts'] = {}
                settings['default_accounts'][provider] = account_id
                outcome['ok'] = True

            saved = self.settings_manager.update(
                _mutate, f"dns_default_account_{provider}_{account_id}"
            )
            if not outcome['ok']:
                return False
            if saved:
                logger.info(f"Set default DNS account '{account_id}' for provider '{provider}'")
            return saved

        except Exception as e:
            logger.error(f"Error setting default DNS account for {provider}: {e}")
            return False
