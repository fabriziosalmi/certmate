"""
Settings management module for CertMate
Handles loading/saving settings, migrations, and configuration management
"""

import os
import logging
from pathlib import Path
from datetime import datetime

from .file_operations import FileOperations
from .utils import generate_secure_token

logger = logging.getLogger(__name__)


class SettingsManager:
    """Class to handle settings management and migrations"""
    
    def __init__(self, file_ops: FileOperations, settings_file: Path):
        self.file_ops = file_ops
        self.settings_file = settings_file

    def _generate_secure_token_compat(self):
        """Generate secure token with compatibility layer for tests"""
        try:
            import app
            if hasattr(app, 'generate_secure_token'):
                return app.generate_secure_token()
        except ImportError:
            pass
        from modules.core.utils import generate_secure_token
        return generate_secure_token()

    def _safe_file_write_compat(self, file_path, data, is_json=True):
        """Write file with compatibility layer for tests"""
        try:
            import app
            if hasattr(app, 'safe_file_write'):
                return app.safe_file_write(file_path, data, is_json)
        except ImportError:
            pass
        return self.file_ops.safe_file_write(file_path, data, is_json)

    def _safe_file_read_compat(self, file_path, is_json=False, default=None):
        """Read file with compatibility layer for tests"""
        try:
            import app
            if hasattr(app, 'safe_file_read'):
                return app.safe_file_read(file_path, is_json, default)
        except ImportError:
            pass
        return self.file_ops.safe_file_read(file_path, is_json, default)

    def _settings_file_exists_compat(self):
        """Check if settings file exists with compatibility layer for tests"""
        try:
            import app
            if hasattr(app, 'SETTINGS_FILE'):
                return app.SETTINGS_FILE.exists()
        except ImportError:
            pass
        return self.settings_file.exists()

    def _save_settings_compat(self, settings, backup_reason="auto"):
        """Save settings with compatibility layer for tests"""
        try:
            import app
            if hasattr(app, 'save_settings'):
                return app.save_settings(settings, backup_reason)
        except ImportError:
            pass
        return self.save_settings(settings, backup_reason)

    def load_settings(self):
        """Load settings from file with improved error handling"""
        default_settings = {
            'cloudflare_token': '',
            'domains': [],
            'email': '',
            'auto_renew': True,
            'renewal_threshold_days': 30,  # Configurable certificate expiry threshold (days)
            'api_bearer_token': os.getenv('API_BEARER_TOKEN') or generate_secure_token(),
            'setup_completed': False,  # Track if initial setup is done
            'dns_provider': 'cloudflare',
            'challenge_type': 'dns-01',  # 'dns-01' or 'http-01'
            'dns_providers': {},  # Start with empty DNS providers - only add what's actually configured
            'certificate_storage': {  # New storage backend configuration
                'backend': 'local_filesystem',  # Default to local filesystem for backward compatibility
                'cert_dir': 'certificates',
                'azure_keyvault': {
                    'vault_url': '',
                    'client_id': '',
                    'client_secret': '',
                    'tenant_id': ''
                },
                'aws_secrets_manager': {
                    'region': 'us-east-1',
                    'access_key_id': '',
                    'secret_access_key': ''
                },
                'hashicorp_vault': {
                    'vault_url': '',
                    'vault_token': '',
                    'mount_point': 'secret',
                    'engine_version': 'v2'
                },
                'infisical': {
                    'site_url': 'https://app.infisical.com',
                    'client_id': '',
                    'client_secret': '',
                    'project_id': '',
                    'environment': 'prod'
                }
            }
        }
        
        # Only create full template for first-time setup
        first_time_template = {
            'cloudflare_token': '',
            'domains': [],
            'email': '',
            'auto_renew': True,
            'renewal_threshold_days': 30,  # Configurable certificate expiry threshold (days)
            'api_bearer_token': os.getenv('API_BEARER_TOKEN') or generate_secure_token(),
            'setup_completed': False,
            'dns_provider': 'cloudflare',
            'challenge_type': 'dns-01',
            'dns_providers': {
                'cloudflare': {'api_token': ''},
                'route53': {'access_key_id': '', 'secret_access_key': '', 'region': 'us-east-1'},
                'azure': {'subscription_id': '', 'resource_group': '', 'tenant_id': '', 'client_id': '', 'client_secret': ''},
                'google': {'project_id': '', 'service_account_key': ''},
                'powerdns': {'api_url': '', 'api_key': ''},
                'digitalocean': {'api_token': ''},
                'linode': {'api_key': ''},
                'gandi': {'api_token': ''},
                'ovh': {'endpoint': '', 'application_key': '', 'application_secret': '', 'consumer_key': ''},
                'namecheap': {'username': '', 'api_key': ''},
                'arvancloud': {'api_key': ''},
                'infomaniak': {'api_token': ''},
                'acme-dns': {'api_url': '', 'username': '', 'password': '', 'subdomain': ''}
            },
            'certificate_storage': default_settings['certificate_storage']
        }
        
        if not self._settings_file_exists_compat():
            # First time setup - create with full template for web UI
            logger.info("Creating initial settings file with full provider template for first-time setup")
            self._save_settings_compat(first_time_template)
            return first_time_template
        
        try:
            settings = self._safe_file_read_compat(self.settings_file, is_json=True)
            if settings is None:
                logger.warning("Settings file exists but is empty or corrupted, recreating with defaults")
                self._save_settings_compat(first_time_template)
                return first_time_template
            
            # Apply migrations for backward compatibility
            settings, was_migrated = self._migrate_settings_format(settings)
            
            # Only merge essential missing keys, NOT the full dns_providers template
            essential_keys = ['cloudflare_token', 'domains', 'email', 'auto_renew', 'renewal_threshold_days', 'api_bearer_token', 'setup_completed', 'dns_provider', 'challenge_type']
            for key in essential_keys:
                if key not in settings:
                    settings[key] = default_settings[key]
            
            # Ensure dns_providers exists but don't overwrite with empty template
            if 'dns_providers' not in settings:
                settings['dns_providers'] = {}
                was_migrated = True
                
            # Ensure certificate_storage exists with default configuration
            if 'certificate_storage' not in settings:
                settings['certificate_storage'] = default_settings['certificate_storage']
                was_migrated = True
            else:
                # Merge missing storage backend configuration keys
                for key, value in default_settings['certificate_storage'].items():
                    if key not in settings['certificate_storage']:
                        settings['certificate_storage'][key] = value
                        was_migrated = True
                    
            # Validate critical settings
            if settings.get('api_bearer_token') in ['change-this-token', 'certmate-api-token-12345', '']:
                logger.warning("Using default API token - please change for security")
                settings['api_bearer_token'] = self._generate_secure_token_compat()
                was_migrated = True
            
            # Save migrated settings if any changes were made
            if was_migrated:
                logger.info("Settings migrated, saving updated format")
                self._save_settings_compat(settings, backup_reason="migration")
            
            # Override settings with environment variables
            if os.getenv('LETSENCRYPT_EMAIL'):
                settings['email'] = os.getenv('LETSENCRYPT_EMAIL')

            if os.getenv('CLOUDFLARE_TOKEN'):
                if 'cloudflare' not in settings['dns_providers']:
                    settings['dns_providers']['cloudflare'] = {'accounts': {'default': {}}}
                settings['dns_providers']['cloudflare']['accounts']['default']['api_token'] = os.getenv('CLOUDFLARE_TOKEN')

            return settings
            
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
            logger.warning("Returning default settings in-memory (existing file preserved on disk)")
            return default_settings

    def save_settings(self, settings, backup_reason="auto_save"):
        """Save settings to file with improved error handling, validation, and automatic backup"""
        try:
            # Create backup before saving (if settings file exists)
            if self.settings_file.exists():
                self.file_ops.create_unified_backup(settings, backup_reason)
            
            # Validate settings structure
            if not isinstance(settings, dict):
                logger.error("Settings must be a dictionary")
                return False
                
            # Validate critical settings before saving
            if 'email' in settings and settings['email']:
                # Use compatibility layer for validation
                try:
                    import app
                    if hasattr(app, 'validate_email'):
                        is_valid, email_or_error = app.validate_email(settings['email'])
                    else:
                        from modules.core.utils import validate_email
                        is_valid, email_or_error = validate_email(settings['email'])
                except ImportError:
                    from modules.core.utils import validate_email
                    is_valid, email_or_error = validate_email(settings['email'])
                    
                if not is_valid:
                    logger.error(f"Invalid email in settings: {email_or_error}")
                    return False
                settings['email'] = email_or_error
                
            if 'api_bearer_token' in settings:
                # Use compatibility layer for validation
                try:
                    import app
                    if hasattr(app, 'validate_api_token'):
                        is_valid, token_or_error = app.validate_api_token(settings['api_bearer_token'])
                    else:
                        from modules.core.utils import validate_api_token
                        is_valid, token_or_error = validate_api_token(settings['api_bearer_token'])
                except ImportError:
                    from modules.core.utils import validate_api_token
                    is_valid, token_or_error = validate_api_token(settings['api_bearer_token'])
                    
                if not is_valid:
                    logger.error(f"Invalid API token: {token_or_error}")
                    return False
                    
            # Validate dns_provider against supported set
            supported_providers = {'cloudflare','route53','azure','google','powerdns','digitalocean','linode','gandi','ovh','namecheap','vultr','dnsmadeeasy','nsone','rfc2136','hetzner','porkbun','godaddy','he-ddns','dynudns','arvancloud','infomaniak','acme-dns'}
            if 'dns_provider' in settings and settings['dns_provider'] not in supported_providers:
                logger.error(f"Invalid dns_provider: {settings['dns_provider']}")
                return False
                    
            # Validate domains
            if 'domains' in settings:
                validated_domains = []
                for domain_entry in settings['domains']:
                    if isinstance(domain_entry, str):
                        # Use compatibility layer for validation
                        try:
                            import app
                            if hasattr(app, 'validate_domain'):
                                is_valid, domain_or_error = app.validate_domain(domain_entry)
                            else:
                                from modules.core.utils import validate_domain
                                is_valid, domain_or_error = validate_domain(domain_entry)
                        except ImportError:
                            from modules.core.utils import validate_domain
                            is_valid, domain_or_error = validate_domain(domain_entry)
                            
                        if is_valid:
                            validated_domains.append(domain_or_error)
                        else:
                            logger.warning(f"Invalid domain skipped: {domain_or_error}")
                    elif isinstance(domain_entry, dict) and 'domain' in domain_entry:
                        # Use compatibility layer for validation
                        try:
                            import app
                            if hasattr(app, 'validate_domain'):
                                is_valid, domain_or_error = app.validate_domain(domain_entry['domain'])
                            else:
                                from modules.core.utils import validate_domain
                                is_valid, domain_or_error = validate_domain(domain_entry['domain'])
                        except ImportError:
                            from modules.core.utils import validate_domain
                            is_valid, domain_or_error = validate_domain(domain_entry['domain'])
                            
                        if is_valid:
                            domain_entry['domain'] = domain_or_error
                            validated_domains.append(domain_entry)
                        else:
                            logger.warning(f"Invalid domain in object skipped: {domain_or_error}")
                settings['domains'] = validated_domains
                
            # Ensure required fields exist (but don't fail on missing fields, just warn)
            required_fields = ['email', 'domains', 'auto_renew', 'api_bearer_token', 'dns_provider']
            for field in required_fields:
                if field not in settings:
                    logger.warning(f"Missing required field '{field}' in settings")
                    
            # Allow DNS propagation seconds override per provider
            defaults = {
                'cloudflare': 60,
                'route53': 60,
                'digitalocean': 120,
                'linode': 120,
                'azure': 180,
                'google': 120,
                'powerdns': 60,
                'gandi': 180,
                'ovh': 180,
                'namecheap': 300,
                'arvancloud': 120,
                'infomaniak': 300,
                'acme-dns': 30
            }
            if 'dns_propagation_seconds' not in settings or not isinstance(settings['dns_propagation_seconds'], dict):
                settings['dns_propagation_seconds'] = defaults
            else:
                # Merge with defaults for missing providers
                for k, v in defaults.items():
                    settings['dns_propagation_seconds'].setdefault(k, v)
            
            # Save settings
            if self._safe_file_write_compat(self.settings_file, settings, is_json=True):
                logger.info("Settings saved successfully")
                return True
            else:
                logger.error("Failed to save settings")
                return False
                
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            return False

    def migrate_domains_format(self, settings):
        """Migrate old domain format (string) to new format (object with dns_provider)"""
        try:
            if 'domains' not in settings:
                return settings
                
            domains = settings['domains']
            default_provider = settings.get('dns_provider', 'cloudflare')
            migrated_domains = []
            
            for domain_entry in domains:
                if isinstance(domain_entry, str):
                    # Old format: just domain string
                    migrated_domains.append({
                        'domain': domain_entry,
                        'dns_provider': default_provider,
                        'account_id': 'default'
                    })
                elif isinstance(domain_entry, dict):
                    # New format: already has structure
                    if 'domain' in domain_entry:
                        # Ensure required fields exist
                        if 'dns_provider' not in domain_entry:
                            domain_entry['dns_provider'] = default_provider
                        if 'account_id' not in domain_entry:
                            domain_entry['account_id'] = 'default'
                        migrated_domains.append(domain_entry)
                    else:
                        logger.warning(f"Invalid domain entry format: {domain_entry}")
                else:
                    logger.warning(f"Unexpected domain entry type: {type(domain_entry)}")
                    
            settings['domains'] = migrated_domains
            return settings
            
        except Exception as e:
            logger.error(f"Error during domain format migration: {e}")
            return settings

    def _get_logger_compat(self):
        """Get logger with compatibility layer for tests"""
        try:
            import app
            if hasattr(app, 'logger'):
                return app.logger
        except ImportError:
            pass
        return logger

    def migrate_dns_providers_to_multi_account(self, settings):
        """Migrate old single-account DNS provider configurations to multi-account format"""
        try:
            dns_providers = settings.get('dns_providers', {})
            
            # Define credential keys for each provider (same as used later)
            old_config_keys = {
                'cloudflare': ['api_token'],
                'route53': ['access_key_id', 'secret_access_key', 'region'],
                'azure': ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret'],
                'google': ['project_id', 'service_account_key'],
                'powerdns': ['api_url', 'api_key'],
                'digitalocean': ['api_token'],
                'linode': ['api_key'],
                'gandi': ['api_token'],
                'ovh': ['endpoint', 'application_key', 'application_secret', 'consumer_key'],
                'namecheap': ['username', 'api_key'],
                'rfc2136': ['nameserver', 'tsig_key', 'tsig_secret', 'api_key'],
                'vultr': ['api_key'],
                'hetzner': ['api_token'],
                'porkbun': ['api_key', 'secret_key'],
                'godaddy': ['api_key', 'secret'],
                'he-ddns': ['username', 'password'],
                'arvancloud': ['api_key'],
                'infomaniak': ['api_token'],
                'acme-dns': ['api_url', 'username', 'password', 'subdomain']
            }
            
            # Check if migration is needed
            needs_migration = False
            for provider_name, provider_config in dns_providers.items():
                if provider_config and isinstance(provider_config, dict):
                    # If it doesn't have 'accounts' key but has credential keys, it needs migration
                    if 'accounts' not in provider_config:
                        provider_keys = old_config_keys.get(provider_name, ['api_token', 'api_key', 'username'])
                        if any(key in provider_config for key in provider_keys):
                            needs_migration = True
                            break
            
            if not needs_migration:
                return settings
                
            logger_compat = self._get_logger_compat()
            logger_compat.info("Migrating DNS providers to multi-account format")
            
            # Migrate each provider
            for provider_name, provider_config in dns_providers.items():
                if not provider_config or not isinstance(provider_config, dict):
                    continue
                    
                # Skip if already in multi-account format
                if 'accounts' in provider_config:
                    continue
                    
                provider_keys = old_config_keys.get(provider_name, ['api_token', 'api_key', 'username'])
                
                # Check if this provider has old-style configuration
                has_old_config = any(key in provider_config for key in provider_keys)
                
                # Check if it already has account-like objects
                has_account_objects = any(
                    isinstance(v, dict) and ('name' in v or any(k in v for k in provider_keys))
                    for k, v in provider_config.items()
                    if k not in provider_keys
                )
                
                if not has_old_config or has_account_objects:
                    continue
                    
                # Extract old configuration keys
                old_config = {}
                remaining_config = {}
                
                for key, value in provider_config.items():
                    if key in provider_keys:
                        old_config[key] = value
                    else:
                        remaining_config[key] = value
                        
                # Create new multi-account structure
                new_config = {
                    'accounts': {
                        'default': {
                            'name': f'Default {provider_name.title()} Account',
                            'description': 'Migrated from single-account configuration',
                            **old_config
                        }
                    },
                    **remaining_config
                }
                        
                dns_providers[provider_name] = new_config
                
            # Update default accounts if not set
            if 'default_accounts' not in settings:
                settings['default_accounts'] = {}
                
            # Set default account for each configured provider
            for provider_name, provider_config in dns_providers.items():
                if provider_config and isinstance(provider_config, dict) and 'accounts' in provider_config:
                    if provider_name not in settings['default_accounts']:
                        # Use 'default' as the default account ID
                        settings['default_accounts'][provider_name] = 'default'
                            
            logger_compat.info("DNS provider migration completed successfully")
            return settings
            
        except Exception as e:
            logger.error(f"Error during DNS provider migration: {e}")
            return settings

    def get_domain_dns_provider(self, domain, settings=None):
        """Get the DNS provider for a specific domain with backward compatibility
        
        Args:
            domain: The domain name to check
            settings: Current settings dict (optional, loads current if not provided)
            
        Returns:
            str: DNS provider name (e.g., 'cloudflare', 'route53')
        """
        try:
            if settings is None:
                settings = self.load_settings()
        
            # Check if domain has specific provider in new object format
            for domain_config in settings.get('domains', []):
                if isinstance(domain_config, dict) and domain_config.get('domain') == domain:
                    return domain_config.get('dns_provider', settings.get('dns_provider', 'cloudflare'))
                elif isinstance(domain_config, str) and domain_config == domain:
                    # Legacy string format - use default provider
                    return settings.get('dns_provider', 'cloudflare')
        
            # Domain not found in settings, use default provider
            return settings.get('dns_provider', 'cloudflare')
            
        except Exception as e:
            logger.error(f"Error getting DNS provider for domain {domain}: {e}")
            return 'cloudflare'  # Safe fallback

    def _migrate_settings_format(self, settings):
        """Migrate settings to handle format changes and ensure backward compatibility"""
        migrated = False
        
        # Migration 1: Handle backup format wrapping
        if 'settings' in settings and 'metadata' in settings:
            logger.info("Migrating settings from backup format")
            settings = settings['settings']
            migrated = True
        
        # Migration 2: Handle domains format transition (string array <-> object array)
        if 'domains' in settings:
            domains = settings['domains']
            if domains and isinstance(domains[0], str):
                # Convert simple string array to object array for new multi-account support
                logger.info("Migrating domains from string array to object array format")
                default_provider = settings.get('dns_provider', 'cloudflare')
                default_accounts = settings.get('default_accounts', {})
                default_account = default_accounts.get(default_provider, 'default')
                
                new_domains = []
                for domain in domains:
                    new_domains.append({
                        'domain': domain,
                        'dns_provider': default_provider,
                        'account_id': default_account
                    })
                settings['domains'] = new_domains
                migrated = True
        
        # Migration 3: Ensure metadata exists for existing certificates
        if migrated:
            self._ensure_certificate_metadata()
            
        return settings, migrated
    
    def _ensure_certificate_metadata(self):
        """Ensure all existing certificates have metadata.json files"""
        try:
            cert_dir = self.file_ops.cert_dir
            if not cert_dir.exists():
                return
                
            settings = self.load_settings()
            
            for cert_path in cert_dir.iterdir():
                if cert_path.is_dir():
                    metadata_file = cert_path / "metadata.json"
                    if not metadata_file.exists():
                        # Create metadata from settings or defaults
                        domain = cert_path.name
                        dns_provider = self._get_domain_provider_from_settings(domain, settings)
                        
                        metadata = {
                            "domain": domain,
                            "dns_provider": dns_provider,
                            "created_at": "unknown",
                            "version": "2.0.0",
                            "migrated": True
                        }
                        
                        try:
                            with open(metadata_file, 'w') as f:
                                import json
                                json.dump(metadata, f, indent=2)
                            logger.info(f"Created metadata for certificate: {domain}")
                        except Exception as e:
                            logger.warning(f"Failed to create metadata for {domain}: {e}")
                            
        except Exception as e:
            logger.error(f"Error ensuring certificate metadata: {e}")
    
    def _get_domain_provider_from_settings(self, domain, settings):
        """Get DNS provider for a domain from settings"""
        # Check if domain has specific provider in new format
        for domain_config in settings.get('domains', []):
            if isinstance(domain_config, dict) and domain_config.get('domain') == domain:
                return domain_config.get('dns_provider', settings.get('dns_provider', 'cloudflare'))
        
        # Fall back to default provider
        return settings.get('dns_provider', 'cloudflare')
