from flask_restx import fields

from ..core.settings import SECRET_MASK_SENTINEL


class MaskedString(fields.String):
    """Field that masks a secret completely in API responses.

    It used to reveal the first four and last four characters (#432). That is
    a meaningful head start on a DNS API token — and `GET /api/settings`,
    where these fields live, is readable by the **viewer** role: the role you
    hand to people you do not fully trust. The web settings route already
    masked the same values as a flat sentinel, so the API was the weaker of
    two answers about identical data.

    Uses the same sentinel as the settings path, so a client can recognise
    "this is masked, not the value" one way everywhere.
    """
    def format(self, value):
        if not value:
            return value
        return SECRET_MASK_SENTINEL


# The description every field that nothing fills starts with (#1108, #1114). A test reads it.
_NEVER_FILLED = ('DEPRECATED. Always null: nothing computes it. Removed in API contract 3.0 '
                 '(#1114). ')


def create_api_models(api):
    """Create and register all API models with the Flask-RESTX API instance"""

    # DNS Provider models
    cloudflare_model = api.model('CloudflareConfig', {
        'api_token': MaskedString(description='Cloudflare API token')
    })

    route53_model = api.model('Route53Config', {
        'access_key_id': fields.String(description='AWS Access Key ID'),
        'secret_access_key': MaskedString(description='AWS Secret Access Key'),
        'region': fields.String(description='AWS Region', default='us-east-1'),
        'auth_mode': fields.String(description='access_keys (default) or iam_role',
                                   enum=['access_keys', 'iam_role']),
        'assume_role_arn': fields.String(description='Optional AWS role ARN to assume via STS')
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

    # What the CA's ARI endpoint (RFC 9773) said at the last renewal sweep
    # (#962). Read from the record the sweep keeps, never fetched on request.
    renewal_info_model = api.model('RenewalInfo', {
        'status': fields.String(
            enum=['window', 'unsupported', 'unavailable', 'no_identifier',
                  'disabled'],
            description=(
                "'window': the CA answered with a renewal window. "
                "'unsupported': it publishes no renewalInfo, which will not "
                "change. 'unavailable': it does, and the last sweep got no "
                "usable answer. 'no_identifier': the certificate has no "
                "Authority Key Identifier to name it by. 'disabled': "
                "ari_enabled is false, so nothing is asked.")),
        'checked_at': fields.String(
            description='When the sweep asked, RFC 3339 UTC with Z.'),
        'window_start': fields.String(
            description="Start of the CA's suggested window, RFC 3339 UTC. Null unless status is 'window'."),
        'window_end': fields.String(
            description="End of the CA's suggested window, RFC 3339 UTC. Null unless status is 'window'."),
        'renew_at': fields.String(
            description=(
                'The point inside the window at which the sweep renews this '
                'certificate if the configured threshold has not already. '
                'Derived from the certificate id, so it is stable across '
                'sweeps. Null unless status is window.')),
        'explanation_url': fields.String(
            description="The CA's page explaining the window, when it gave one (https only)."),
    })

    certificate_model = api.model('Certificate', {
        'domain': fields.String(required=True, description='Domain name'),
        'exists': fields.Boolean(description='Whether certificate exists'),
        'expiry_date': fields.String(
            description=(
                "Certificate expiry, 'YYYY-MM-DD HH:MM:SS' in UTC. Deprecated "
                "since API contract 2.42 and removed in 3.0 (#1114): read "
                "expires_at, the same instant in the form every other date-time "
                "has."
            )),
        'expires_at': fields.String(
            description=(
                'Certificate expiry, ISO 8601 UTC with a Z, like every date-time '
                'the API answers with since contract 2.42. Null when the '
                'certificate could not be parsed.'
            )),
        'days_left': fields.Integer(description='Days until expiry'),
        'days_until_expiry': fields.Integer(description='Days until expiry (alias for days_left)'),
        'expired': fields.Boolean(
            description=(
                'Whether this certificate has expired. Read this rather than '
                'comparing days_left to zero: days_left is a whole number of '
                'days and rounds down, so a certificate with 23 hours of life '
                'left reports 0 and that comparison calls it expired. Null '
                'when the certificate could not be parsed, which is neither '
                'expired nor fine. Added in API contract 2.2.'
            )),
        'seconds_left': fields.Integer(
            description=(
                'Remaining life in seconds, negative once expired. The field '
                'to use for ordering or for anything finer than a day; '
                'days_left cannot separate a certificate with hours left from '
                'one that lapsed hours ago. Null when the certificate could '
                'not be parsed. Added in API contract 2.2.'
            )),
        'needs_renewal': fields.Boolean(
            description=(
                'Whether the certificate needs renewing: true from renews_at '
                'on, or now when its private key is missing or does not match. '
                'Since API contract 2.40 decided by the same rule the renewal '
                'sweep acts on.'
            )),
        'acme_profile': fields.String(
            description=(
                "The ACME profile the certificate was issued with (#395): "
                "'classic', 'tlsserver', 'shortlived' on Let's Encrypt. Null "
                "for the CA's default. Added in API contract 2.41."
            )),
        'acme_profile_withdrawn_at': fields.String(
            description=(
                'When a renewal found that the CA no longer offers acme_profile '
                'and the CA issued its default profile instead, UTC; null '
                'otherwise. Added in API contract 2.41.'
            )),
        'renews_at': fields.String(
            description=(
                'The instant the renewal sweep renews this certificate at, UTC '
                'with a Z: the threshold where it is at most half the lifetime, '
                'otherwise a third of the lifetime (half under 10 days), or the '
                "CA's recorded ARI window, never with less than a sixth of the "
                'lifetime left. Null when the certificate could not be parsed. '
                'Added in API contract 2.40.'
            )),
        'usable': fields.Boolean(
            description=(
                'Whether this certificate can actually serve TLS: it exists AND '
                'a matching private key is beside it. Null only when the '
                'storage backend does not fetch key material on this path and '
                'says so, which today means Azure Key Vault; the default '
                'filesystem backend answers. It used to be null on every '
                'storage-backed read, including the default one, which is how '
                'a certificate with no key at all was reported as needing '
                'nothing (#830). A false here forces needs_renewal, because a '
                'keyless certificate has nothing to wait for.'
            )),
        'private_key_present': fields.Boolean(
            description=(
                'Whether a private key was found beside the certificate. Null '
                'when it was not looked for. Restoring a share-safe backup '
                'produces certificates with no key, which is why this is '
                'reported rather than assumed.'
            )),
        'private_key_state': fields.String(
            description=(
                "One of 'present', 'missing', 'mismatched', 'unknown' or "
                "'external'. 'external' is a CSR-only certificate (#599): the "
                "key was generated on the device that will serve it and was "
                "never sent here, so its absence is the design rather than a "
                "fault. Unlike 'missing' it does not force needs_renewal, and "
                "`usable` is null because this node cannot answer for a key it "
                "does not hold."
            )),
        'reissue_required': fields.Boolean(
            description=(
                'True when this certificate has no private key anywhere: not '
                'served, not in live/, not in any archived generation. What '
                'restoring a share-safe backup leaves. Renewal answers '
                'REISSUE_REQUIRED for it, and POST '
                '/api/certificates/reissue-keyless reissues it. A key missing '
                'only from the served copy is not this: it is republished from '
                'the lineage. Added in API contract 2.28 (#966).'
            )),
        'auto_renew': fields.Boolean(description='Whether automatic renewal is enabled for this certificate'),
        'dns_provider': fields.String(description='DNS provider used for the certificate'),
        'domain_alias': fields.String(description='DNS alias target used for DNS-01 validation'),
        'alias_dns_provider': fields.String(description='DNS provider used to manage the alias target'),
        'san_domains': fields.List(fields.String, description='Subject Alternative Names included in the certificate'),
        'ca_provider': fields.String(description='CA provider the certificate was issued with (from metadata; null for older certificates)'),
        'challenge_type': fields.String(description='Challenge type used at issuance (from metadata)'),
        'account_id': fields.String(description='DNS provider account used at issuance (from metadata)'),
        'storage_warning': fields.String(
            description=(
                'Why the last write to the configured external storage did not '
                'land, or null when it did. Surfaced on the certificate rather '
                'than left in the logs, because a disaster-recovery copy that '
                'is missing or stale is not something to discover during a '
                'recovery.'
            )),
        'created_at': fields.String(
            description='When the certificate was first issued, ISO 8601, from its metadata.'),
        'renewed_at': fields.String(
            description='When the certificate was last renewed, ISO 8601, from its metadata. Null if it has never been renewed.'),
        'renewal_info': fields.Nested(
            renewal_info_model, allow_null=True,
            description=(
                "What the CA's ARI endpoint said at the last renewal sweep. "
                'Null when no sweep has asked about this certificate yet, '
                'including right after a renewal. Since API contract 2.23.')),
        # The six fields below have been null in every answer since they were added (v2.2.0):
        # nothing computes them. Deprecated, and removed by the next MAJOR of the API contract
        # (#1114); they are sent, as null, until then. `latest_issuance` is `created_at` or
        # `renewed_at`; the rest have no counterpart, because CertMate keeps no ledger of issuances.
        'total_issued': fields.Integer(
            description=_NEVER_FILLED + 'Was meant to be the total of certificates issued.'),
        'total_active': fields.Integer(
            description=_NEVER_FILLED + 'Was meant to be the total of active certificates.'),
        'total_revoked': fields.Integer(
            description=_NEVER_FILLED + 'Was meant to be the total of revoked certificates.'),
        'total_expired': fields.Integer(
            description=_NEVER_FILLED + 'Was meant to be the total of expired certificates.'),
        'latest_issuance': fields.String(
            description=_NEVER_FILLED + 'Was meant to be the latest issuance timestamp: read '
                                        '`renewed_at`, or `created_at`.'),
        'oldest_active_issuance': fields.String(
            description=_NEVER_FILLED + 'Was meant to be the oldest active issuance timestamp.'),
        'notes': fields.String(description=(
            'Free-text note an operator attached to the certificate, or null. '
            'Since API contract 2.33.')),
        'tags': fields.List(fields.String, description=(
            'Short tags an operator attached to the certificate, lower case; '
            'an empty list when there are none. Since API contract 2.33.')),
        'deployment_host': fields.String(description=(
            'Hostname the deployment probe connects to and sends as SNI, when it is not the '
            'certificate name (a wildcard is verified through a name it covers). Null when unset. '
            'Since API contract 2.33.')),
        'deployment_port': fields.Integer(description='TCP port for deployment probe'),
        'deployment_protocol': fields.String(description='Protocol used by deployment probe (https-tls, tls, or smtp-starttls)')
    })

    # Single source of truth: the dns_provider enum is derived from the
    # canonical advertised provider list (DNSManager.SUPPORTED_PROVIDERS) so it
    # cannot drift. The previous hand-maintained literal listed 24 of the 26
    # providers, silently omitting hetzner-cloud and infomaniak from the API
    # contract / Swagger. Pinned by
    # test_api_models_dns_provider_enum_matches_supported.
    from modules.core.dns_providers import DNSManager
    dns_provider_enum = list(DNSManager.SUPPORTED_PROVIDERS)

    settings_model = api.model('Settings', {
        'cloudflare_token': MaskedString(description='Cloudflare API token (deprecated, use dns_providers)'),
        'domains': fields.List(fields.Raw, description=(
            'Managed domains. A request may send either a bare domain string or an '
            'object carrying the domain plus per-domain overrides; both are accepted '
            'and stored as objects, so a response always returns the object form.')),
        'email': fields.String(description='Email for Let\'s Encrypt'),
        'auto_renew': fields.Boolean(description='Enable auto-renewal'),
        'api_bearer_token': MaskedString(description='API bearer token for authentication'),
        'dns_provider': fields.String(
            description='Active DNS provider',
            enum=dns_provider_enum
        ),
        'dns_providers': fields.Nested(dns_providers_model, description='DNS provider configurations'),
        'default_key_type': fields.String(
            description='Global default key type for new certificates (per-domain overrides take precedence).',
            enum=['rsa', 'ecdsa']
        ),
        'default_key_size': fields.Integer(
            description="Global default RSA key size — applied when default_key_type='rsa'.",
            enum=[2048, 3072, 4096]
        ),
        'default_elliptic_curve': fields.String(
            description="Global default ECDSA curve — applied when default_key_type='ecdsa'.",
            enum=['secp256r1', 'secp384r1']
        ),
        'dns_propagation_seconds': fields.Raw(
            description=('Seconds certbot waits after publishing the DNS-01 TXT record '
                         'before the CA checks it, per DNS provider, e.g. '
                         '{"edgedns": 180}. Raise a provider\'s value when validation '
                         'fails although the record appears shortly after. POST it '
                         'whole: providers left out return to their defaults. '
                         'Returned since API contract 2.30.')),
    })

    create_cert_model = api.model('CreateCertificate', {
        'domain': fields.String(required=True, description='Primary domain name to create certificate for'),
        'san_domains': fields.List(fields.String,
                                   description='Additional SANs (e.g., ["*.example.com"])'),
        'dns_provider': fields.String(
            description='DNS provider to use (optional, uses default from settings)',
            enum=dns_provider_enum
        ),
        'account_id': fields.String(description='DNS provider account ID'),
        'ca_provider': fields.String(description='CA provider (optional)',
                                     enum=['letsencrypt', 'letsencrypt_staging', 'zerossl',
                                           'google', 'digicert', 'sslcom',
                                           'actalis', 'sectigo', 'private_ca']),
        'ca_account_id': fields.String(description='CA provider account ID (optional)'),
        'challenge_type': fields.String(
            description='ACME challenge (prevalidated requires Sectigo SCM authorization)',
            enum=['dns-01', 'http-01', 'prevalidated']),
        'domain_alias': fields.String(description='Optional domain alias for DNS validation'),
        'alias_dns_provider': fields.String(
            description=('DNS provider that hosts the alias zone, when it is '
                         'not the one hosting the primary. Ignored without '
                         'domain_alias.')),
        'acme_profile': fields.String(
            description=(
                "ACME profile to ask the CA for (#395), such as 'tlsserver' "
                "(45 days) or 'shortlived' (160 hours) on Let's Encrypt. Omit "
                "to use the CA account's default; pass '' for the CA's own "
                "default. Required at issuance: a CA that does not offer it "
                "refuses the order. Since API contract 2.41."
            )),
        'key_type': fields.String(
            description=(
                "Optional override of the global default key type. Omit to "
                "inherit settings.default_key_type."
            ),
            enum=['rsa', 'ecdsa']
        ),
        'key_size': fields.Integer(
            description="RSA key size in bits — required when key_type='rsa'.",
            enum=[2048, 3072, 4096]
        ),
        'elliptic_curve': fields.String(
            description="ECDSA curve — required when key_type='ecdsa'.",
            enum=['secp256r1', 'secp384r1']
        ),
        'csr': fields.String(
            description=(
                "PEM certificate signing request generated elsewhere (#599). "
                "When given, CertMate never sees or stores the private key: "
                "the certificate covers the names inside the CSR, so "
                "san_domains and the key options must be omitted, and the "
                "primary `domain` must be one of them. These certificates "
                "report private_key_state='external' and are renewed by "
                "re-submitting the stored CSR to the CA."
            )),
        # Declared here because callers already send it and the server already
        # honours it (`_wants_async`, resources.py). certmate-sdk has sent
        # `async: True` on every create since 0.1.x; leaving it out of the model
        # meant the published Swagger contract described a request the shipped
        # client does not make, and would reject it outright if validation were
        # ever turned on. ReissueCertificate has always declared it.
        'async': fields.Boolean(
            description='Defer issuance to a background job (202 + job id). '
                        'Poll GET /api/certificates/jobs/<job_id>.'
        )
    })

    reissue_cert_model = api.model('ReissueCertificate', {
        'san_domains': fields.List(
            fields.String,
            description='Replacement SAN set. Omit to keep the current SANs; '
                        'pass [] to drop every SAN. The set replaces the '
                        "lineage's domains (expand and shrink)."),
        'dns_provider': fields.String(description='Omit to keep the value the certificate was issued with'),
        'account_id': fields.String(description='Omit to keep the value the certificate was issued with'),
        'ca_provider': fields.String(description='Omit to keep the value the certificate was issued with'),
        'challenge_type': fields.String(
            description='Omit to keep the issued challenge (prevalidated is Sectigo-only)',
            enum=['dns-01', 'http-01', 'prevalidated']),
        'domain_alias': fields.String(description='Omit to keep the current alias; pass "" to clear it'),
        'alias_dns_provider': fields.String(description='Provider managing the alias zone when it differs from dns_provider. Omit to keep the issued value'),
        'csr': fields.String(
            description=(
                "PEM certificate signing request, to rotate the key of a "
                "CSR-only certificate without deleting it first (#876). The "
                "certificate covers the names inside the CSR, so san_domains "
                "and the key options must be omitted; SANs inherited from the "
                "current certificate are replaced rather than added to. Same "
                "field name and same rules as on create."
            )),
        'acme_profile': fields.String(
            description=("ACME profile (#395). Omit to keep the certificate's "
                         "current one; pass '' for the CA's default. Since API "
                         "contract 2.41.")),
        'key_type': fields.String(
            description='Omit to keep the existing key shape (no key flags are '
                        'sent and certbot preserves the lineage key). Set to '
                        'deliberately re-key.',
            enum=['rsa', 'ecdsa']
        ),
        'key_size': fields.Integer(description="RSA key size — required when key_type='rsa'.",
                                   enum=[2048, 3072, 4096]),
        'elliptic_curve': fields.String(description="ECDSA curve — required when key_type='ecdsa'.",
                                        enum=['secp256r1', 'secp384r1']),
        'async': fields.Boolean(description='Defer issuance to a background job (202 + job id)')
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
        'certificate_match': fields.Boolean(description='Whether the served certificate matches the local certificate'),
        'method': fields.String(description='Check method'),
        'port': fields.Integer(description='TCP port probed', default=443),
        'protocol': fields.String(description='Probe protocol (https-tls, tls, smtp-starttls)'),
        'timestamp': fields.String(description='Check timestamp'),
        'error': fields.String(description='Optional error message'),
        # Machine-readable error code surfaced when _check_domain_scope denies
        # a scoped API key (e.g. 'DOMAIN_OUT_OF_SCOPE'). Without listing it
        # here, @api.marshal_with would silently strip it from the 403 body.
        'code': fields.String(description='Optional machine-readable error code'),
        # Deployment-probe diagnostics (#381). @api.marshal_with strips any key
        # not declared here, so these MUST be listed for the UI to receive them.
        'probe_host': fields.String(description='Host the probe actually connected to / SNI-d'),
        'probe_status': fields.String(description="Probe outcome: 'match', 'mismatch', 'unreachable', or 'unverifiable' (wildcard with no deployment_host)"),
        'mismatch_reason': fields.String(description='Human-readable explanation of a mismatch or why the status is inconclusive'),
        'served_subject': fields.String(description='Subject CN/SAN of the certificate actually served on a mismatch'),
        'served_fingerprint': fields.String(description='Fingerprint prefix of the served certificate on a mismatch'),
        'expected_fingerprint': fields.String(description='Fingerprint prefix of the stored certificate on a mismatch'),
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
        'can_restore': fields.Boolean(
            description=(
                'Whether this archive can actually restore the instance. '
                'Automatic backups are taken with secrets masked so a leaked '
                'archive is not also a credential dump, and those cannot '
                'restore: installing one writes the mask in place of every '
                'credential. Decided with the same predicate the restore path '
                'applies, and false whenever the archive cannot be inspected.'
            )),
        'contains_key_material': fields.Boolean(
            description=(
                'Whether this archive carries private keys, read from the '
                'archive itself rather than from its manifest. Every backup '
                'made before v2.26.0 says secrets_masked: true and carries '
                'them anyway. Null when the archive could not be inspected — '
                'which is not the same as carrying none.'
            )),
        'key_file_count': fields.Integer(
            description='How many key files were found; null when uninspectable.'),
        'restore_blocked_reason': fields.String(
            description='Why it cannot restore; null when it can.'),
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
        'tenant_id': fields.String(description='Azure Tenant ID'),
        'storage_mode': fields.String(
            description=(
                "Whether to store certificates as Secrets, native Certificate "
                "objects, or both. 'certificate'/'both' enables native consumption "
                "from App Service, Application Gateway, Front Door, API Management "
                "and AKS Ingress."
            ),
            enum=['secrets', 'certificate', 'both'],
            default='secrets'
        )
    })

    aws_secrets_manager_storage_model = api.model('AWSSecretsManagerStorage', {
        'region': fields.String(description='AWS Region', default='us-east-1'),
        'auth_mode': fields.String(description='Key pair or AWS credential chain',
                                   enum=['access_keys', 'iam_role']),
        'access_key_id': fields.String(description='AWS Access Key ID (access_keys mode)'),
        'secret_access_key': fields.String(description='AWS Secret Access Key (access_keys mode)'),
        'assume_role_arn': fields.String(description='Optional AWS IAM role ARN to assume via STS')
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

    s3_compatible_storage_model = api.model('S3CompatibleStorage', {
        'endpoint_url': fields.String(description='S3-compatible endpoint URL; omit for AWS S3'),
        'bucket': fields.String(description='Bucket name'),
        'auth_mode': fields.String(description='Key pair or AWS credential chain',
                                   enum=['access_keys', 'iam_role']),
        'access_key_id': fields.String(description='S3 access key ID (access_keys mode)'),
        'secret_access_key': fields.String(description='S3 secret access key (access_keys mode)'),
        'assume_role_arn': fields.String(description='Optional AWS IAM role ARN to assume via STS'),
        'region': fields.String(description='Region', default='us-east-1'),
        'prefix': fields.String(description='Object key prefix', default='certmate/certificates')
    })

    storage_config_model = api.model('StorageConfig', {
        'backend': fields.String(description='Storage backend type',
                                 enum=['local_filesystem', 'azure_keyvault', 'aws_secrets_manager',
                                       'hashicorp_vault', 'infisical', 's3_compatible']),
        'cert_dir': fields.String(description='Certificate directory for local filesystem'),
        'azure_keyvault': fields.Nested(azure_keyvault_storage_model),
        'aws_secrets_manager': fields.Nested(aws_secrets_manager_storage_model),
        'hashicorp_vault': fields.Nested(hashicorp_vault_storage_model),
        'infisical': fields.Nested(infisical_storage_model),
        's3_compatible': fields.Nested(s3_compatible_storage_model)
    })

    storage_test_config_model = api.model('StorageTestConfig', {
        'backend': fields.String(description='Storage backend type to test', required=True),
        'config': fields.Raw(description='Backend-specific configuration', required=True)
    })

    storage_migration_config_model = api.model('StorageMigrationConfig', {
        # All four fields are optional: source defaults to the active
        # certificate_storage from settings and target_backend can be read
        # from target_config['backend'] (the envelope shape the settings
        # form emits via collectStorageBackendSettings()).
        'source_backend': fields.String(description='Source storage backend type (defaults to current certificate_storage.backend)'),
        'target_backend': fields.String(description='Target storage backend type (defaults to target_config.backend)'),
        'source_config': fields.Raw(description='Source backend configuration (defaults to current certificate_storage)'),
        'target_config': fields.Raw(description='Target backend configuration; accepts either the per-backend dict or the {backend, <backend>: {...}} envelope', required=True)
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
        'reissue_cert_model': reissue_cert_model,
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
