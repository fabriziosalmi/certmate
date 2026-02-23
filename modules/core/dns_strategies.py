"""
DNS Provider Strategy Module
Implements the Strategy Pattern for DNS provider configuration and management.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional

from .utils import (
    create_cloudflare_config, create_azure_config, create_google_config,
    create_powerdns_config, create_digitalocean_config, create_linode_config,
    create_gandi_config, create_ovh_config, create_namecheap_config,
    create_arvancloud_config, create_infomaniak_config, create_acme_dns_config,
    create_multi_provider_config, _create_config_file
)

logger = logging.getLogger(__name__)

class DNSProviderStrategy(ABC):
    """Abstract base class for DNS provider strategies"""
    
    @abstractmethod
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        """Create the configuration file for the provider"""
        pass
    
    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """Return the Certbot plugin name"""
        pass
    
    @property
    def default_propagation_seconds(self) -> int:
        """Return default propagation time in seconds"""
        return 120

    @property
    def supports_propagation_seconds_flag(self) -> bool:
        """Whether this provider's certbot plugin accepts a --{plugin}-propagation-seconds flag.

        Most plugins support this flag, but some (e.g. certbot-dns-route53 ≥ 1.22)
        removed it because propagation is handled internally.  Override and return
        ``False`` in subclasses where the flag is not accepted.
        """
        return True

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        """Add provider-specific arguments to the certbot command
        
        Args:
            cmd: Certbot command list to append arguments to
            credentials_file: Path to credentials file
            domain_alias: Optional domain alias for DNS validation
        """
        cmd.extend([f'--{self.plugin_name}'])
        if credentials_file:
            cmd.extend([f'--{self.plugin_name}-credentials', str(credentials_file)])
        
        # Add domain alias if provided
        if domain_alias:
            cmd.extend(['--domain-alias', domain_alias])

    def prepare_environment(self, env: Dict[str, str], config_data: Dict[str, Any]) -> None:
        """Set up environment variables if needed"""
        pass

    def cleanup_environment(self, env: Dict[str, str]) -> None:
        """Clean up environment variables"""
        pass

class CloudflareStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        token = config_data.get('api_token') or config_data.get('token', '')
        return create_cloudflare_config(token)
    
    @property
    def plugin_name(self) -> str:
        return 'dns-cloudflare'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 60

class Route53Strategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        # Route53 uses env vars, but we might create a file for Consistency or future use
        # For now, return None as the implementation in CertificateManager handles env vars specially
        # OR better: Refactor CertificateManager to ask the strategy to set up the environment!
        # But to avoid massive breakage now, we'll keep the specialized handling in CertificateManager for Route53
        # unless we refactor that part too.
        # The prompt asked to refactor the if/elif switch.
        return None 
    
    @property
    def plugin_name(self) -> str:
        return 'dns-route53'

    @property
    def supports_propagation_seconds_flag(self) -> bool:
        # certbot-dns-route53 ≥ 1.22 removed --dns-route53-propagation-seconds.
        # The plugin polls Route53 internally until the record propagates.
        return False

    @property
    def default_propagation_seconds(self) -> int:
        return 60

    def prepare_environment(self, env: Dict[str, str], config_data: Dict[str, Any]) -> None:
        env['AWS_ACCESS_KEY_ID'] = config_data.get('access_key_id', '')
        env['AWS_SECRET_ACCESS_KEY'] = config_data.get('secret_access_key', '')
        if config_data.get('region'):
            env['AWS_DEFAULT_REGION'] = config_data['region']

    def cleanup_environment(self, env: Dict[str, str]) -> None:
        for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION']:
            if key in env:
                del env[key]

class AzureStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_azure_config(
            config_data.get('subscription_id', ''),
            config_data.get('resource_group', ''),
            config_data.get('tenant_id', ''),
            config_data.get('client_id', ''),
            config_data.get('client_secret', ''),
        )
        
    @property
    def plugin_name(self) -> str:
        return 'dns-azure'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 180

class GoogleStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_google_config(
            config_data.get('project_id', ''),
            config_data.get('service_account_key', ''),
        )

    @property
    def plugin_name(self) -> str:
        return 'dns-google'

class PowerDNSStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_powerdns_config(
            config_data.get('api_url', ''),
            config_data.get('api_key', ''),
        )

    @property
    def plugin_name(self) -> str:
        return 'dns-powerdns'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 60

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        cmd.extend(['--authenticator', self.plugin_name])
        if credentials_file:
            cmd.extend([f'--{self.plugin_name}-credentials', str(credentials_file)])
        
        # Add domain alias if provided
        if domain_alias:
            cmd.extend(['--domain-alias', domain_alias])

class DigitalOceanStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_digitalocean_config(config_data.get('api_token', ''))

    @property
    def plugin_name(self) -> str:
        return 'dns-digitalocean'

class LinodeStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_linode_config(config_data.get('api_key', ''))

    @property
    def plugin_name(self) -> str:
        return 'dns-linode'

class GandiStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_gandi_config(config_data.get('api_token', ''))

    @property
    def plugin_name(self) -> str:
        return 'dns-gandi'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 180

class OVHStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_ovh_config(
            config_data.get('endpoint', ''),
            config_data.get('application_key', ''),
            config_data.get('application_secret', ''),
            config_data.get('consumer_key', ''),
        )

    @property
    def plugin_name(self) -> str:
        return 'dns-ovh'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 180

class NamecheapStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_namecheap_config(
            config_data.get('username', ''),
            config_data.get('api_key', ''),
        )

    @property
    def plugin_name(self) -> str:
        return 'dns-namecheap'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 300

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        cmd.extend(['--authenticator', self.plugin_name])
        if credentials_file:
            cmd.extend([f'--{self.plugin_name}-credentials', str(credentials_file)])
        
        # Add domain alias if provided
        if domain_alias:
            cmd.extend(['--domain-alias', domain_alias])

class ArvanCloudStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_arvancloud_config(config_data.get('api_key', ''))

    @property
    def plugin_name(self) -> str:
        return 'dns-arvancloud'

class InfomaniakStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_infomaniak_config(config_data.get('api_token', ''))

    @property
    def plugin_name(self) -> str:
        return 'dns-infomaniak'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 300

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        cmd.extend(['--authenticator', self.plugin_name])
        if credentials_file:
            cmd.extend([f'--{self.plugin_name}-credentials', str(credentials_file)])
        
        # Add domain alias if provided
        if domain_alias:
            cmd.extend(['--domain-alias', domain_alias])

class AcmeDNSStrategy(DNSProviderStrategy):
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_acme_dns_config(
            config_data.get('api_url', ''),
            config_data.get('username', ''),
            config_data.get('password', ''),
            config_data.get('subdomain', ''),
        )

    @property
    def plugin_name(self) -> str:
        # Note: ACME-DNS is a unique snowflake that doesn't follow dns- prefix convention in certmate args logic
        # But for strategy, we return the base name
        return 'acme-dns'
    
    @property
    def default_propagation_seconds(self) -> int:
        return 30

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        cmd.extend(['--authenticator', 'acme-dns'])
        if credentials_file:
            cmd.extend(['--acme-dns-credentials', str(credentials_file)])
        
        # Add domain alias if provided
        if domain_alias:
            cmd.extend(['--domain-alias', domain_alias])

class GenericMultiProviderStrategy(DNSProviderStrategy):
    def __init__(self, provider_name: str):
        self.provider_name = provider_name
        
    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_multi_provider_config(self.provider_name, config_data)

    @property
    def plugin_name(self) -> str:
        return f'dns-{self.provider_name}'

class HTTP01Strategy(DNSProviderStrategy):
    """HTTP-01 challenge using certbot --webroot plugin.

    No DNS credentials needed. CertMate serves challenge files
    via /.well-known/acme-challenge/<token> and certbot writes
    them to the webroot directory.
    """

    WEBROOT_DIR = 'data/acme-challenges'

    @property
    def plugin_name(self) -> str:
        return 'webroot'

    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return None  # No credentials needed

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        webroot = str(Path(self.WEBROOT_DIR).resolve())
        cmd.extend(['--webroot', '-w', webroot])

    def prepare_environment(self, env: Dict[str, str], config_data: Dict[str, Any]) -> None:
        pass  # No env vars needed

    @property
    def default_propagation_seconds(self) -> int:
        return 0  # No propagation needed for HTTP-01


class DNSStrategyFactory:
    """Factory to get the correct strategy for a provider"""

    _strategies = {
        'cloudflare': CloudflareStrategy,
        'route53': Route53Strategy,
        'azure': AzureStrategy,
        'google': GoogleStrategy,
        'powerdns': PowerDNSStrategy,
        'digitalocean': DigitalOceanStrategy,
        'linode': LinodeStrategy,
        'gandi': GandiStrategy,
        'ovh': OVHStrategy,
        'namecheap': NamecheapStrategy,
        'arvancloud': ArvanCloudStrategy,
        'infomaniak': InfomaniakStrategy,
        'acme-dns': AcmeDNSStrategy,
        'http-01': HTTP01Strategy,
    }
    
    @classmethod
    def get_strategy(cls, provider_name: str) -> DNSProviderStrategy:
        strategy_class = cls._strategies.get(provider_name)
        if strategy_class:
            return strategy_class()
        return GenericMultiProviderStrategy(provider_name)
