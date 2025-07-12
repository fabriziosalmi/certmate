"""
API models module for CertMate
Defines Flask-RESTX models for API documentation and validation
"""

from flask_restx import fields


def create_api_models(api):
    """Create and register all API models with the Flask-RESTX API instance"""
    
    # DNS Provider models
    cloudflare_model = api.model('CloudflareConfig', {
        'api_token': fields.String(description='Cloudflare API token')
    })

    route53_model = api.model('Route53Config', {
        'access_key_id': fields.String(description='AWS Access Key ID'),
        'secret_access_key': fields.String(description='AWS Secret Access Key'),
        'region': fields.String(description='AWS Region', default='us-east-1')
    })

    azure_model = api.model('AzureConfig', {
        'subscription_id': fields.String(description='Azure Subscription ID'),
        'resource_group': fields.String(description='Azure Resource Group'),
        'tenant_id': fields.String(description='Azure Tenant ID'),
        'client_id': fields.String(description='Azure Client ID'),
        'client_secret': fields.String(description='Azure Client Secret')
    })

    google_model = api.model('GoogleConfig', {
        'project_id': fields.String(description='Google Cloud Project ID'),
        'service_account_key': fields.String(description='Google Service Account JSON Key')
    })

    powerdns_model = api.model('PowerDNSConfig', {
        'api_url': fields.String(description='PowerDNS API URL'),
        'api_key': fields.String(description='PowerDNS API Key')
    })

    digitalocean_model = api.model('DigitalOceanConfig', {
        'api_token': fields.String(description='DigitalOcean API token')
    })

    linode_model = api.model('LinodeConfig', {
        'api_key': fields.String(description='Linode API key')
    })

    gandi_model = api.model('GandiConfig', {
        'api_token': fields.String(description='Gandi API token')
    })

    ovh_model = api.model('OvhConfig', {
        'endpoint': fields.String(description='OVH API endpoint'),
        'application_key': fields.String(description='OVH application key'),
        'application_secret': fields.String(description='OVH application secret'),
        'consumer_key': fields.String(description='OVH consumer key')
    })

    namecheap_model = api.model('NamecheapConfig', {
        'username': fields.String(description='Namecheap username'),
        'api_key': fields.String(description='Namecheap API key')
    })

    # Tier 3 DNS Providers (Additional individual plugins)
    hetzner_model = api.model('HetznerConfig', {
        'api_token': fields.String(description='Hetzner DNS API token')
    })

    porkbun_model = api.model('PorkbunConfig', {
        'api_key': fields.String(description='Porkbun API key'),
        'secret_key': fields.String(description='Porkbun secret key')
    })

    godaddy_model = api.model('GoDaddyConfig', {
        'api_key': fields.String(description='GoDaddy API key'),
        'secret': fields.String(description='GoDaddy API secret')
    })

    he_ddns_model = api.model('HurricaneElectricConfig', {
        'username': fields.String(description='Hurricane Electric username'),
        'password': fields.String(description='Hurricane Electric password')
    })

    dynudns_model = api.model('DynuConfig', {
        'token': fields.String(description='Dynu API token')
    })

    # Multi-provider model for certbot-dns-multi (117+ providers)
    multi_provider_model = api.model('MultiProviderConfig', {
        'provider': fields.String(description='DNS provider name (e.g., hetzner, porkbun, vultr)'),
        'config': fields.Raw(description='Provider-specific configuration (flexible key-value pairs)')
    })

    dns_providers_model = api.model('DNSProviders', {
        'cloudflare': fields.Nested(cloudflare_model),
        'route53': fields.Nested(route53_model),
        'azure': fields.Nested(azure_model),
        'google': fields.Nested(google_model),
        'powerdns': fields.Nested(powerdns_model),
        'digitalocean': fields.Nested(digitalocean_model),
        'linode': fields.Nested(linode_model),
        'gandi': fields.Nested(gandi_model),
        'ovh': fields.Nested(ovh_model),
        'namecheap': fields.Nested(namecheap_model),
        'vultr': fields.Nested(linode_model),  # Same API structure as Linode
        'dnsmadeeasy': fields.Nested(digitalocean_model),  # Simple API token
        'nsone': fields.Nested(digitalocean_model),  # Simple API token
        'rfc2136': fields.Nested(powerdns_model),  # Server URL and key
        'hetzner': fields.Nested(hetzner_model),
        'porkbun': fields.Nested(porkbun_model),
        'godaddy': fields.Nested(godaddy_model),
        'he-ddns': fields.Nested(he_ddns_model),
        'dynudns': fields.Nested(dynudns_model),
        # Support for any other provider via certbot-dns-multi
        'multi': fields.Raw(description='Configuration for any DNS provider via certbot-dns-multi')
    })

    certificate_model = api.model('Certificate', {
        'domain': fields.String(required=True, description='Domain name'),
        'exists': fields.Boolean(description='Whether certificate exists'),
        'expiry_date': fields.String(description='Certificate expiry date'),
        'days_left': fields.Integer(description='Days until expiry'),
        'days_until_expiry': fields.Integer(description='Days until expiry (alias for days_left)'),
        'needs_renewal': fields.Boolean(description='Whether certificate needs renewal'),
        'dns_provider': fields.String(description='DNS provider used for the certificate')
    })

    settings_model = api.model('Settings', {
        'cloudflare_token': fields.String(description='Cloudflare API token (deprecated, use dns_providers)'),
        'domains': fields.List(fields.Raw, description='List of domains (can be strings or objects)'),
        'email': fields.String(description='Email for Let\'s Encrypt'),
        'auto_renew': fields.Boolean(description='Enable auto-renewal'),
        'api_bearer_token': fields.String(description='API bearer token for authentication'),
        'dns_provider': fields.String(description='Active DNS provider', enum=['cloudflare', 'route53', 'azure', 'google', 'powerdns', 'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner', 'porkbun', 'godaddy', 'he-ddns', 'dynudns']),
        'dns_providers': fields.Nested(dns_providers_model, description='DNS provider configurations')
    })

    create_cert_model = api.model('CreateCertificate', {
        'domain': fields.String(required=True, description='Domain name to create certificate for'),
        'dns_provider': fields.String(description='DNS provider to use (optional, uses default from settings)', enum=['cloudflare', 'route53', 'azure', 'google', 'powerdns', 'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner', 'porkbun', 'godaddy', 'he-ddns', 'dynudns']),
        'account_id': fields.String(description='DNS provider account ID to use (optional, uses default account if not specified)')
    })

    # Cache models
    cache_entry_model = api.model('CacheEntry', {
        'domain': fields.String(description='Domain name'),
        'age': fields.Integer(description='Age of cache entry in seconds'),
        'remaining': fields.Integer(description='Remaining TTL in seconds'),
        'status': fields.String(description='Deployment status', enum=['deployed', 'not-deployed'])
    })

    cache_stats_model = api.model('CacheStats', {
        'total_entries': fields.Integer(description='Total number of cached entries'),
        'current_ttl': fields.Integer(description='Current TTL setting in seconds'),
        'entries': fields.List(fields.Nested(cache_entry_model), description='List of cached entries')
    })

    cache_clear_response_model = api.model('CacheClearResponse', {
        'success': fields.Boolean(description='Whether cache was cleared successfully'),
        'message': fields.String(description='Status message'),
        'cleared_entries': fields.Integer(description='Number of entries that were cleared')
    })

    # Backup models
    backup_metadata_model = api.model('BackupMetadata', {
        'filename': fields.String(description='Backup filename'),
        'size': fields.Integer(description='File size in bytes'),
        'created': fields.String(description='Creation timestamp'),
        'metadata': fields.Raw(description='Backup metadata')
    })

    backup_list_model = api.model('BackupList', {
        'unified': fields.List(fields.Nested(backup_metadata_model), description='Unified backups')
    })

    # Storage Backend models
    azure_keyvault_storage_model = api.model('AzureKeyVaultStorage', {
        'vault_url': fields.String(description='Azure Key Vault URL'),
        'client_id': fields.String(description='Azure Client ID'),
        'client_secret': fields.String(description='Azure Client Secret'),
        'tenant_id': fields.String(description='Azure Tenant ID')
    })

    aws_secrets_manager_storage_model = api.model('AWSSecretsManagerStorage', {
        'region': fields.String(description='AWS Region', default='us-east-1'),
        'access_key_id': fields.String(description='AWS Access Key ID'),
        'secret_access_key': fields.String(description='AWS Secret Access Key')
    })

    hashicorp_vault_storage_model = api.model('HashiCorpVaultStorage', {
        'vault_url': fields.String(description='HashiCorp Vault URL'),
        'vault_token': fields.String(description='HashiCorp Vault Token'),
        'mount_point': fields.String(description='Vault Mount Point', default='secret'),
        'engine_version': fields.String(description='KV Engine Version', default='v2')
    })

    infisical_storage_model = api.model('InfisicalStorage', {
        'site_url': fields.String(description='Infisical Site URL', default='https://app.infisical.com'),
        'client_id': fields.String(description='Infisical Client ID'),
        'client_secret': fields.String(description='Infisical Client Secret'),
        'project_id': fields.String(description='Infisical Project ID'),
        'environment': fields.String(description='Infisical Environment', default='prod')
    })

    storage_config_model = api.model('StorageConfig', {
        'backend': fields.String(description='Storage backend type', enum=['local_filesystem', 'azure_keyvault', 'aws_secrets_manager', 'hashicorp_vault', 'infisical']),
        'cert_dir': fields.String(description='Certificate directory for local filesystem'),
        'azure_keyvault': fields.Nested(azure_keyvault_storage_model),
        'aws_secrets_manager': fields.Nested(aws_secrets_manager_storage_model),
        'hashicorp_vault': fields.Nested(hashicorp_vault_storage_model),
        'infisical': fields.Nested(infisical_storage_model)
    })

    storage_test_config_model = api.model('StorageTestConfig', {
        'backend': fields.String(description='Storage backend type to test', required=True),
        'config': fields.Raw(description='Backend-specific configuration', required=True)
    })

    storage_migration_config_model = api.model('StorageMigrationConfig', {
        'source_backend': fields.String(description='Source storage backend type', required=True),
        'target_backend': fields.String(description='Target storage backend type', required=True),
        'source_config': fields.Raw(description='Source backend configuration', required=True),
        'target_config': fields.Raw(description='Target backend configuration', required=True)
    })

    # Return all models as a dict for easy access
    return {
        'certificate_model': certificate_model,
        'settings_model': settings_model,
        'create_cert_model': create_cert_model,
        'dns_providers_model': dns_providers_model,
        'cache_stats_model': cache_stats_model,
        'cache_clear_response_model': cache_clear_response_model,
        'backup_list_model': backup_list_model,
        'backup_metadata_model': backup_metadata_model,
        # DNS provider models
        'cloudflare_model': cloudflare_model,
        'route53_model': route53_model,
        'azure_model': azure_model,
        'google_model': google_model,
        'powerdns_model': powerdns_model,
        'digitalocean_model': digitalocean_model,
        'linode_model': linode_model,
        'gandi_model': gandi_model,
        'ovh_model': ovh_model,
        'namecheap_model': namecheap_model,
        'hetzner_model': hetzner_model,
        'porkbun_model': porkbun_model,
        'godaddy_model': godaddy_model,
        'he_ddns_model': he_ddns_model,
        'dynudns_model': dynudns_model,
        'multi_provider_model': multi_provider_model,
        # Storage backend models
        'StorageConfig': storage_config_model,
        'StorageTestConfig': storage_test_config_model,
        'StorageMigrationConfig': storage_migration_config_model,
        'AzureKeyVaultStorage': azure_keyvault_storage_model,
        'AWSSecretsManagerStorage': aws_secrets_manager_storage_model,
        'HashiCorpVaultStorage': hashicorp_vault_storage_model,
        'InfisicalStorage': infisical_storage_model
    }
