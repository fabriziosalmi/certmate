from flask_restx import fields


class MaskedString(fields.String):
    """Custom field that masks sensitive string values"""
    def format(self, value):
        if not value:
            return value
        s = str(value)
        if len(s) > 8:
            return f"{s[:4]}...{s[-4:]}"
        return "***"


def create_api_models(api):
    """Create and register all API models with the Flask-RESTX API instance"""

    # DNS Provider models
    cloudflare_model = api.model('CloudflareConfig', {
        'api_token': MaskedString(description='Cloudflare API token')
    })

    route53_model = api.model('Route53Config', {
        'access_key_id': fields.String(description='AWS Access Key ID'),
        'secret_access_key': MaskedString(description='AWS Secret Access Key'),
        'region': fields.String(description='AWS Region', default='us-east-1')
    })

    azure_model = api.model('AzureConfig', {
        'subscription_id': fields.String(description='Azure Subscription ID'),
        'resource_group': fields.String(description='Azure Resource Group'),
        'tenant_id': fields.String(description='Azure Tenant ID'),
        'client_id': fields.String(description='Azure Client ID'),
        'client_secret': MaskedString(description='Azure Client Secret')
    })

    google_model = api.model('GoogleConfig', {
        'project_id': fields.String(description='Google Cloud Project ID'),
        'service_account_key': MaskedString(description='Google Service Account JSON Key')
    })

    powerdns_model = api.model('PowerDNSConfig', {
        'api_url': fields.String(description='PowerDNS API URL'),
        'api_key': MaskedString(description='PowerDNS API Key')
    })

    digitalocean_model = api.model('DigitalOceanConfig', {
        'api_token': MaskedString(description='DigitalOcean API token')
    })

    linode_model = api.model('LinodeConfig', {
        'api_key': MaskedString(description='Linode API key')
    })

    gandi_model = api.model('GandiConfig', {
        'api_token': MaskedString(description='Gandi API token')
    })

    ovh_model = api.model('OvhConfig', {
        'endpoint': fields.String(description='OVH API endpoint'),
        'application_key': MaskedString(description='OVH application key'),
        'application_secret': MaskedString(description='OVH application secret'),
        'consumer_key': MaskedString(description='OVH consumer key')
    })

    namecheap_model = api.model('NamecheapConfig', {
        'username': fields.String(description='Namecheap username'),
        'api_key': MaskedString(description='Namecheap API key')
    })

    # Tier 3 DNS Providers (Additional individual plugins)
    hetzner_model = api.model('HetznerConfig', {
        'api_token': MaskedString(description='Hetzner DNS API token')
    })

    porkbun_model = api.model('PorkbunConfig', {
        'api_key': MaskedString(description='Porkbun API key'),
        'secret_key': MaskedString(description='Porkbun secret key')
    })

    godaddy_model = api.model('GoDaddyConfig', {
        'api_key': MaskedString(description='GoDaddy API key'),
        'secret': MaskedString(description='GoDaddy API secret')
    })

    he_ddns_model = api.model('HurricaneElectricConfig', {
        'username': fields.String(description='Hurricane Electric username'),
        'password': MaskedString(description='Hurricane Electric password')
    })

    dynudns_model = api.model('DynuConfig', {
        'token': MaskedString(description='Dynu API token')
    })

    arvancloud_model = api.model('ArvanCloudConfig', {
        'api_key': MaskedString(description='ArvanCloud API key')
    })

    acme_dns_model = api.model('ACMEDNSConfig', {
        'api_url': fields.String(description='ACME-DNS server URL'),
        'username': fields.String(description='ACME-DNS username'),
        'password': MaskedString(description='ACME-DNS password'),
        'subdomain': fields.String(description='ACME-DNS subdomain')
    })

    duckdns_model = api.model('DuckDNSConfig', {
        'api_token': MaskedString(description='DuckDNS account token (UUID format, from https://www.duckdns.org)')
    })

    edgedns_model = api.model('EdgeDNSConfig', {
        'client_token': MaskedString(description='Akamai EdgeGrid client_token'),
        'client_secret': MaskedString(description='Akamai EdgeGrid client_secret'),
        'access_token': MaskedString(description='Akamai EdgeGrid access_token'),
        'host': fields.String(description='Akamai EdgeGrid host (e.g. akab-xxx.luna.akamaiapis.net)')
    })

    # multi_provider_model removed as it is now flexible

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
        'arvancloud': fields.Nested(arvancloud_model),
        'acme-dns': fields.Nested(acme_dns_model),
        'duckdns': fields.Nested(duckdns_model),
        'edgedns': fields.Nested(edgedns_model),
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
        'auto_renew': fields.Boolean(description='Whether automatic renewal is enabled for this certificate'),
        'dns_provider': fields.String(description='DNS provider used for the certificate'),
        'domain_alias': fields.String(description='DNS alias target used for DNS-01 validation'),
        'alias_dns_provider': fields.String(description='DNS provider used to manage the alias target'),
        'san_domains': fields.List(fields.String, description='Subject Alternative Names included in the certificate'),
        'total_issued': fields.Integer(description='Total certificates issued'),
        'total_active': fields.Integer(description='Total active certificates'),
        'total_revoked': fields.Integer(description='Total revoked certificates'),
        'total_expired': fields.Integer(description='Total expired certificates'),
        'latest_issuance': fields.String(description='Latest issuance timestamp'),
        'oldest_active_issuance': fields.String(description='Oldest active issuance timestamp')
    })

    settings_model = api.model('Settings', {
        'cloudflare_token': MaskedString(description='Cloudflare API token (deprecated, use dns_providers)'),
        'domains': fields.List(fields.Raw, description='List of domains (can be strings or objects)'),
        'email': fields.String(description='Email for Let\'s Encrypt'),
        'auto_renew': fields.Boolean(description='Enable auto-renewal'),
        'api_bearer_token': MaskedString(description='API bearer token for authentication'),
        'dns_provider': fields.String(
            description='Active DNS provider',
            enum=[
                'cloudflare', 'route53', 'azure', 'google', 'powerdns',
                'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap',
                'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner',
                'porkbun', 'godaddy', 'he-ddns', 'dynudns', 'arvancloud',
                'acme-dns', 'duckdns', 'edgedns'
            ]
        ),
        'dns_providers': fields.Nested(dns_providers_model, description='DNS provider configurations')
    })

    create_cert_model = api.model('CreateCertificate', {
        'domain': fields.String(required=True, description='Primary domain name to create certificate for'),
        'san_domains': fields.List(fields.String,
                                   description='Additional SANs (e.g., ["*.example.com"])'),
        'dns_provider': fields.String(
            description='DNS provider to use (optional, uses default from settings)',
            enum=[
                'cloudflare', 'route53', 'azure', 'google', 'powerdns',
                'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap',
                'vultr', 'dnsmadeeasy', 'nsone', 'rfc2136', 'hetzner',
                'porkbun', 'godaddy', 'he-ddns', 'dynudns', 'arvancloud',
                'acme-dns', 'duckdns', 'edgedns'
            ]
        ),
        'account_id': fields.String(description='DNS provider account ID'),
        'ca_provider': fields.String(description='CA provider (optional)',
                                     enum=['letsencrypt', 'digicert', 'private_ca']),
        'domain_alias': fields.String(description='Optional domain alias for DNS validation')
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

    browser_deployment_model = api.model('BrowserDeploymentStatus', {
        'reachable': fields.Boolean(description='Whether the browser could reach the domain'),
        'checked_at': fields.String(description='When the browser check happened'),
        'method': fields.String(description='How the browser check was performed'),
        'source': fields.String(description='Source of the browser report')
    })

    deployment_status_model = api.model('DeploymentStatus', {
        'domain': fields.String(description='Domain name'),
        'deployed': fields.Boolean(description='Whether the domain is serving a certificate'),
        'reachable': fields.Boolean(description='Whether the domain responds over HTTPS'),
        'certificate_match': fields.Raw(description='Whether the served certificate matches the local certificate'),
        'method': fields.String(description='Check method'),
        'timestamp': fields.String(description='Check timestamp'),
        'error': fields.String(description='Optional error message'),
        # Machine-readable error code surfaced when _check_domain_scope denies
        # a scoped API key (e.g. 'DOMAIN_OUT_OF_SCOPE'). Without listing it
        # here, @api.marshal_with would silently strip it from the 403 body.
        'code': fields.String(description='Optional machine-readable error code'),
        'browser': fields.Nested(browser_deployment_model, description='Browser-reported reachability')
    })

    browser_deployment_report_model = api.model('BrowserDeploymentReport', {
        'domain': fields.String(required=True, description='Domain name'),
        'reachable': fields.Boolean(required=True, description='Whether the browser could reach the domain'),
        'checked_at': fields.String(description='When the browser check happened'),
        'method': fields.String(description='How the browser check was performed'),
        'source': fields.String(description='Source of the browser report')
    })

    browser_deployment_reports_model = api.model('BrowserDeploymentReports', {
        'reports': fields.List(fields.Nested(browser_deployment_report_model), required=True, description='Batch of browser deployment reports')
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
        'backend': fields.String(description='Storage backend type',
                                 enum=['local_filesystem', 'azure_keyvault', 'aws_secrets_manager',
                                       'hashicorp_vault', 'infisical']),
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

    # CA Provider models
    ca_test_config_model = api.model('CATestConfig', {
        'ca_provider': fields.String(description='CA provider type to test', required=True),
        'config': fields.Raw(description='CA provider-specific configuration', required=True)
    })

    # API Key models
    api_key_model = api.model('ApiKey', {
        'id': fields.String(description='API Key ID'),
        'name': fields.String(description='API Key name'),
        'role': fields.String(description='Key role (admin, viewer, operator)'),
        'created_at': fields.String(description='Creation timestamp'),
        'expires_at': fields.String(description='Expiration timestamp'),
        'last_used': fields.String(description='Last used timestamp'),
        'is_revoked': fields.Boolean(description='Whether key is revoked'),
        'is_expired': fields.Boolean(description='Whether key is expired')
    })

    # Client Certificate models
    client_certificate_model = api.model('ClientCertificate', {
        'common_name': fields.String(description='Common name'),
        'email': fields.String(description='Email address'),
        'organization': fields.String(description='Organization'),
        'cert_usage': fields.String(description='Usage type'),
        'created_at': fields.String(description='Creation date'),
        'expires_at': fields.String(description='Expiration date'),
        'revoked': fields.Boolean(description='Revocation status'),
        'notes': fields.String(description='Notes')
    })

    client_certificate_request_model = api.model('ClientCertificateRequest', {
        'common_name': fields.String(description='Common name', required=True),
        'email': fields.String(description='Email address'),
        'organization': fields.String(description='Organization'),
        'organizational_unit': fields.String(description='Organizational unit'),
        'cert_usage': fields.String(description='Usage type'),
        'days_valid': fields.Integer(description='Days until expiration'),
        'generate_key': fields.Boolean(description='Generate private key'),
        'notes': fields.String(description='Notes')
    })

    client_certificate_revoke_model = api.model('ClientCertificateRevoke', {
        'reason': fields.String(description='Reason for revocation')
    })

    # Register models
    return {
        'settings_model': settings_model,
        'dns_providers_model': dns_providers_model,
        'cache_stats_model': cache_stats_model,
        'cache_clear_response_model': cache_clear_response_model,
        'browser_deployment_model': browser_deployment_model,
        'browser_deployment_report_model': browser_deployment_report_model,
        'browser_deployment_reports_model': browser_deployment_reports_model,
        'deployment_status_model': deployment_status_model,
        'certificate_model': certificate_model,
        'create_cert_model': create_cert_model,
        'cache_entry_model': cache_entry_model,
        'backup_metadata_model': backup_metadata_model,
        'backup_list_model': backup_list_model,
        'storage_config_model': storage_config_model,
        'storage_test_config_model': storage_test_config_model,
        'storage_migration_config_model': storage_migration_config_model,
        'azure_keyvault_storage_model': azure_keyvault_storage_model,
        'aws_secrets_manager_storage_model': aws_secrets_manager_storage_model,
        'hashicorp_vault_storage_model': hashicorp_vault_storage_model,
        'infisical_storage_model': infisical_storage_model,
        'ca_test_config_model': ca_test_config_model,
        'api_key_model': api_key_model,
        'client_certificate_model': client_certificate_model,
        'client_certificate_request_model': client_certificate_request_model,
        'client_certificate_revoke_model': client_certificate_revoke_model,
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
        'arvancloud_model': arvancloud_model,
        'acme_dns_model': acme_dns_model,
        'duckdns_model': duckdns_model,
        'edgedns_model': edgedns_model
    }
