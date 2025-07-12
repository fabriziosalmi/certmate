"""
Certificate Authority (CA) Manager for CertMate
Handles different CA providers including Let's Encrypt, DigiCert, and Private CAs
"""

import logging
import tempfile
import os
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class CAManager:
    """Manages different Certificate Authority providers"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        
        # Supported CA providers
        self.ca_providers = {
            'letsencrypt': {
                'name': 'Let\'s Encrypt',
                'production_url': 'https://acme-v02.api.letsencrypt.org/directory',
                'staging_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
                'requires_eab': False,
                'supports_wildcard': True,
                'certificate_types': ['DV'],
                'description': 'Free, automated SSL certificates'
            },
            'digicert': {
                'name': 'DigiCert',
                'production_url': 'https://acme.digicert.com/v2/DV',
                'staging_url': 'https://acme.digicert.com/v2/DV/staging',
                'requires_eab': True,
                'supports_wildcard': True,
                'certificate_types': ['DV', 'OV', 'EV'],
                'description': 'Enterprise-grade SSL certificates from DigiCert'
            },
            'private_ca': {
                'name': 'Private CA',
                'production_url': 'custom',  # User-defined
                'staging_url': 'custom',     # User-defined
                'requires_eab': False,       # Configurable
                'supports_wildcard': True,
                'certificate_types': ['Private'],
                'description': 'Internal Certificate Authority for private networks'
            }
        }
    
    def get_supported_cas(self) -> Dict[str, Any]:
        """Get list of supported Certificate Authorities"""
        return self.ca_providers
    
    def get_ca_config(self, ca_provider: str, account_id: str = None) -> Tuple[Dict[str, Any], str]:
        """Get CA configuration for the specified provider and account"""
        settings = self.settings_manager.load_settings()
        
        # Get CA provider configuration
        ca_providers = settings.get('ca_providers', {})
        if ca_provider not in ca_providers:
            raise ValueError(f"CA provider '{ca_provider}' not configured")
        
        provider_config = ca_providers[ca_provider]
        
        # Handle multi-account support
        if 'accounts' in provider_config:
            accounts = provider_config['accounts']
            
            if account_id:
                if account_id not in accounts:
                    raise ValueError(f"Account '{account_id}' not found for CA provider '{ca_provider}'")
                account_config = accounts[account_id]
                used_account_id = account_id
            else:
                # Use default account
                default_accounts = settings.get('default_ca_accounts', {})
                default_account_id = default_accounts.get(ca_provider, 'default')
                
                if default_account_id in accounts:
                    account_config = accounts[default_account_id]
                    used_account_id = default_account_id
                else:
                    # Use first available account
                    if accounts:
                        used_account_id = list(accounts.keys())[0]
                        account_config = accounts[used_account_id]
                    else:
                        raise ValueError(f"No accounts configured for CA provider '{ca_provider}'")
        else:
            # Legacy single account configuration
            account_config = provider_config
            used_account_id = 'default'
        
        return account_config, used_account_id
    
    def get_acme_server_url(self, ca_provider: str, staging: bool = False, account_config: Dict[str, Any] = None) -> str:
        """Get ACME server URL for the specified CA provider"""
        if ca_provider not in self.ca_providers:
            raise ValueError(f"Unsupported CA provider: {ca_provider}")
        
        ca_info = self.ca_providers[ca_provider]
        
        if ca_provider == 'private_ca' and account_config:
            # For private CA, use custom URL from configuration
            if staging and account_config.get('staging_url'):
                return account_config['staging_url']
            elif account_config.get('acme_url'):
                return account_config['acme_url']
            else:
                raise ValueError("Private CA ACME URL not configured")
        else:
            # Use predefined URLs for public CAs
            if staging:
                return ca_info['staging_url']
            else:
                return ca_info['production_url']
    
    def requires_eab(self, ca_provider: str) -> bool:
        """Check if CA provider requires External Account Binding"""
        if ca_provider not in self.ca_providers:
            return False
        return self.ca_providers[ca_provider]['requires_eab']
    
    def get_eab_credentials(self, ca_provider: str, account_config: Dict[str, Any]) -> Tuple[str, str]:
        """Get External Account Binding credentials for CA provider"""
        if not self.requires_eab(ca_provider):
            return None, None
        
        eab_key_id = account_config.get('eab_key_id', '')
        eab_hmac_key = account_config.get('eab_hmac_key', '')
        
        if not eab_key_id or not eab_hmac_key:
            raise ValueError(f"EAB credentials not configured for CA provider '{ca_provider}'")
        
        return eab_key_id, eab_hmac_key
    
    def create_ca_trust_bundle(self, ca_provider: str, account_config: Dict[str, Any] = None) -> Optional[str]:
        """Create CA trust bundle file for private CAs"""
        if ca_provider != 'private_ca' or not account_config:
            return None
        
        ca_cert_content = account_config.get('ca_certificate', '')
        if not ca_cert_content:
            logger.warning("No CA certificate provided for private CA")
            return None
        
        # Create temporary file for CA certificate
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(ca_cert_content)
                f.flush()
                return f.name
        except Exception as e:
            logger.error(f"Failed to create CA trust bundle: {e}")
            return None
    
    def build_certbot_command(self, domain: str, email: str, ca_provider: str, 
                            dns_provider: str, dns_config: Dict[str, Any], 
                            account_config: Dict[str, Any], staging: bool = False,
                            cert_dir: Path = None) -> list:
        """Build certbot command with CA-specific parameters"""
        
        # Get ACME server URL
        acme_url = self.get_acme_server_url(ca_provider, staging, account_config)
        
        # Basic certbot command
        certbot_cmd = [
            'certbot', 'certonly',
            '--non-interactive',
            '--agree-tos',
            '--email', email,
            '--cert-name', domain,
            '--server', acme_url,
            '-d', domain
        ]
        
        # Add directory configuration if provided
        if cert_dir:
            cert_output_dir = cert_dir / domain
            cert_output_dir.mkdir(parents=True, exist_ok=True)
            
            certbot_cmd.extend([
                '--config-dir', str(cert_output_dir),
                '--work-dir', str(cert_output_dir / 'work'),
                '--logs-dir', str(cert_output_dir / 'logs')
            ])
        
        # Add EAB credentials if required
        if self.requires_eab(ca_provider):
            eab_key_id, eab_hmac_key = self.get_eab_credentials(ca_provider, account_config)
            if eab_key_id and eab_hmac_key:
                certbot_cmd.extend([
                    '--eab-kid', eab_key_id,
                    '--eab-hmac-key', eab_hmac_key
                ])
        
        # Add CA bundle for private CAs
        if ca_provider == 'private_ca':
            ca_bundle_path = self.create_ca_trust_bundle(ca_provider, account_config)
            if ca_bundle_path:
                # Use REQUESTS_CA_BUNDLE environment variable for certbot
                os.environ['REQUESTS_CA_BUNDLE'] = ca_bundle_path
        
        return certbot_cmd
    
    def validate_ca_configuration(self, ca_provider: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate CA provider configuration"""
        if ca_provider not in self.ca_providers:
            return False, f"Unsupported CA provider: {ca_provider}"
        
        ca_info = self.ca_providers[ca_provider]
        
        # Check required fields based on CA provider
        if ca_provider == 'digicert':
            if not config.get('eab_key_id') or not config.get('eab_hmac_key'):
                return False, "DigiCert requires EAB Key ID and HMAC Key"
        
        elif ca_provider == 'private_ca':
            if not config.get('acme_url'):
                return False, "Private CA requires ACME server URL"
            
            # Validate URL format
            acme_url = config.get('acme_url', '')
            if not acme_url.startswith(('http://', 'https://')):
                return False, "Invalid ACME server URL format"
        
        elif ca_provider == 'letsencrypt':
            # Let's Encrypt doesn't require additional configuration
            pass
        
        return True, "Configuration is valid"
    
    def get_ca_account_display_info(self, ca_provider: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Get display-friendly information about CA account"""
        display_info = {
            'provider_name': self.ca_providers.get(ca_provider, {}).get('name', ca_provider),
            'account_name': config.get('name', 'Default Account'),
            'description': config.get('description', ''),
            'certificate_types': self.ca_providers.get(ca_provider, {}).get('certificate_types', []),
            'supports_wildcard': self.ca_providers.get(ca_provider, {}).get('supports_wildcard', False)
        }
        
        # Add provider-specific display info
        if ca_provider == 'digicert':
            display_info['eab_configured'] = bool(config.get('eab_key_id'))
        elif ca_provider == 'private_ca':
            display_info['acme_url'] = config.get('acme_url', '')
            display_info['ca_cert_configured'] = bool(config.get('ca_certificate'))
        
        return display_info

    def _get_letsencrypt_directory_url(self, environment: str = 'production') -> str:
        """Get Let's Encrypt directory URL for the specified environment"""
        if environment == 'staging':
            return self.ca_providers['letsencrypt']['staging_url']
        else:
            return self.ca_providers['letsencrypt']['production_url']
