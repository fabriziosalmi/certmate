"""
Certificate Authority (CA) Manager for CertMate
Handles different CA providers including Let's Encrypt, DigiCert, and Private CAs
"""

import logging
import tempfile
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


def acme_directory_refusal(url, what='ACME Directory URL'):
    """Why *url* is not usable as an ACME directory, or None if it is.

    One rule, one spelling. There were three, and they disagreed:

    * `validate_ca_configuration`'s private-CA branch compared the scheme
      case-insensitively and said "must use https" (#885);
    * its branch for every other `requires_acme_url` provider used
      `startswith('https://')`, which **refuses `HTTPS://`** — a valid URL,
      since RFC 3986 makes the scheme case-insensitive — while telling the
      operator they need HTTPS, which they have;
    * `get_acme_server_url` carried a third copy of the same `startswith`.

    The divergence appeared when #885 improved one branch and left the others
    where they were, so it is not a defect in the provider that arrived after.
    Measured before this:

        private_ca  HTTPS://acme.example.com/directory -> accepted
        sectigo     HTTPS://acme.example.com/directory -> refused

    `http` gets its own message rather than falling into "invalid format",
    because an operator told their URL is malformed goes looking for a typo.
    """
    text = str(url or '')
    scheme = text.split('://', 1)[0].lower() if '://' in text else ''
    if scheme == 'https':
        return None
    if scheme == 'http':
        return (f"{what} must use https. A directory fetched over plain HTTP "
                f"cannot be trusted to be the one you meant.")
    return f"Invalid {what} format"


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
            # Staging modelled as its own CA entry (#279) instead of a
            # per-certificate boolean: it behaves like a different authority
            # in every way that matters (directory, trust, rate limits).
            'letsencrypt_staging': {
                'name': 'Let\'s Encrypt (Staging)',
                'production_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
                'staging_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
                'requires_eab': False,
                'supports_wildcard': True,
                'certificate_types': ['DV'],
                'description': 'Let\'s Encrypt staging environment - untrusted test certificates with generous rate limits'
            },
            'digicert': {
                'name': 'DigiCert',
                # `acme.digicert.com` no longer exists — NXDOMAIN, verified
                # against Cloudflare's resolver while every other digicert.com
                # host answers. It was CertCentral's legacy ACME service, which
                # DigiCert stopped supporting on 24 February 2026; this entry
                # kept pointing at it for months afterwards while the README
                # advertised DigiCert ACME as a supported CA.
                #
                # The replacement is the DigiCert ONE mPKI endpoint, which
                # returns a real directory (newAccount / newNonce / newOrder /
                # renewalInfo) and sets externalAccountRequired: true, matching
                # requires_eab below. It is REGIONAL: an account outside the
                # default region has its own directory URL, shown in
                # CertCentral. Operators override it per certificate via
                # `acme_url`; this is the default, not the only value.
                # Declared, not implied: `get_acme_server_url` reads this to
                # decide whether an account's own directory wins over the
                # pinned one. Without it the comment above promised an
                # override the code did not perform.
                'accepts_account_directory': True,
                'production_url': 'https://one.digicert.com/mpki/api/v1/acme/v2/directory',
                # DigiCert publishes no public ACME staging directory. Pointing
                # this at an invented `/staging` path is what produced the dead
                # URL above, so it names the same endpoint rather than a guess.
                'staging_url': 'https://one.digicert.com/mpki/api/v1/acme/v2/directory',
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
            },
            'zerossl': {
                'name': 'ZeroSSL',
                'production_url': 'https://acme.zerossl.com/v2/DV90',
                'staging_url': 'https://acme.zerossl.com/v2/DV90',
                'requires_eab': True,
                'supports_wildcard': True,
                'certificate_types': ['DV'],
                'description': 'Free SSL certificates with 90-day validity from ZeroSSL'
            },
            'google': {
                'name': 'Google Trust Services',
                'production_url': 'https://dv.acme-v02.api.pki.goog/directory',
                # dv.acme-staging.api.pki.goog serves a certificate for a
                # different name, so the TLS handshake fails hostname
                # verification and no ACME client will talk to it. Google's
                # staging directory is dv.acme-v02.test-api.pki.goog, which
                # answers correctly and advertises externalAccountRequired.
                'staging_url': 'https://dv.acme-v02.test-api.pki.goog/directory',
                'requires_eab': True,
                'supports_wildcard': True,
                'certificate_types': ['DV'],
                'description': 'Free SSL certificates from Google Trust Services'
            },
            'sslcom': {
                'name': 'SSL.com',
                'production_url': 'https://acme.ssl.com/sslcom-dv-rsa',
                'staging_url': 'https://acme.ssl.com/sslcom-dv-rsa',
                'requires_eab': True,
                'supports_wildcard': True,
                'certificate_types': ['DV', 'OV', 'EV'],
                'description': 'Enterprise SSL certificates from SSL.com'
            },
            'actalis': {
                'name': 'Actalis',
                'production_url': 'https://acme-api.actalis.com/acme/directory',
                # Actalis does not publish a staging/test ACME endpoint.
                'staging_url': 'https://acme-api.actalis.com/acme/directory',
                'requires_eab': True,
                # ACME plans are DV only; wildcard is explicitly not
                # offered via ACME (guide.actalis.com FAQ). The free plan
                # is limited to single-domain 90-day certificates.
                'supports_wildcard': False,
                'certificate_types': ['DV'],
                'description': 'European CA (Italy) with free 90-day DV certificates via ACME'
            },
            'sectigo': {
                'name': 'Sectigo',
                'production_url': 'custom',
                'staging_url': 'custom',
                'requires_acme_url': True,
                'requires_eab': True,
                'supports_wildcard': True,
                'certificate_types': ['DV', 'OV'],
                'description': 'Sectigo Certificate Manager ACME certificates (account-specific directory)'
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
        if ca_provider == 'letsencrypt_staging' and 'letsencrypt' in ca_providers:
            # Staging shares the Let's Encrypt account shape (just an email,
            # no credentials) — inherit it so selecting the staging CA works
            # without re-entering settings. A populated letsencrypt_staging
            # entry takes precedence, but the settings UI materializes the
            # entry as {email: ''} on every save, so an EMPTY entry must
            # alias too or the inheritance is dead for UI-managed installs.
            staging_config = ca_providers.get('letsencrypt_staging')
            if not staging_config or not (
                    staging_config.get('email') or staging_config.get('accounts')):
                ca_provider = 'letsencrypt'
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
        
        account = account_config or {}
        # Three kinds of provider, and the difference is declared in the
        # registry rather than inferred here:
        #
        #   requires  - the directory only exists in the account (private_ca,
        #               and anything with requires_acme_url). No pinned URL to
        #               fall back to, so a missing one is an error.
        #   accepts   - a pinned default the account may override. DigiCert's
        #               mPKI directory is REGIONAL: an account outside the
        #               default region has its own URL, shown in CertCentral.
        #   pinned    - a single public directory (ZeroSSL, Google, SSL.com,
        #               Actalis). Their settings forms do not collect a URL.
        #
        # The middle kind is what was missing. The registry entry for DigiCert
        # said "Operators override it per certificate via `acme_url`; this is
        # the default, not the only value", the settings form collected the
        # field and the connection test required it — and this function
        # returned the pinned URL anyway, so a customer outside the default
        # region was silently sent to the wrong endpoint. Two comments in one
        # file, disagreeing, with the code implementing the other one.
        requires = ca_provider == 'private_ca' or ca_info.get('requires_acme_url')
        may_override = requires or ca_info.get('accepts_account_directory')

        url = None
        if may_override:
            url = (account.get('staging_url') if staging and account.get('staging_url')
                   else account.get('acme_url'))
        if url:
            refusal = acme_directory_refusal(
                url, f"{ca_info['name']} ACME Directory URL")
            if refusal:
                raise ValueError(refusal)
            return url
        if requires:
            raise ValueError(f"{ca_info['name']} ACME URL not configured")
        return ca_info['staging_url' if staging else 'production_url']
    
    def requires_eab(self, ca_provider: str) -> bool:
        """Check if CA provider requires External Account Binding"""
        if ca_provider not in self.ca_providers:
            return False
        return self.ca_providers[ca_provider]['requires_eab']
    
    def get_eab_credentials(self, ca_provider: str, account_config: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Get External Account Binding credentials for CA provider.

        Accepts both field spellings: ``eab_key_id``/``eab_hmac_key``
        (canonical, manual settings.json) and ``eab_kid``/``eab_hmac``
        (what the settings UI saves via collectCAProviderSettings).

        The UI spelling wins when both pairs are present: the settings
        form is the only surface that rotates credentials, while the
        canonical pair can only come from a past hand-edit the UI never
        displays — preferring it would make a UI rotation a silent
        no-op. An empty UI value falls back to the canonical one.

        For ``private_ca`` EAB is optional: the generic Private CA entry
        can point at any ACME directory — including public CAs that
        enforce account binding (e.g. Actalis used without its dedicated
        entry) — so credentials are returned when present and (None,
        None) when absent. Public CAs with ``requires_eab: False`` never
        emit EAB even if stray fields exist in the saved config, since
        an unexpected externalAccountBinding can fail registration.
        """
        if not self.requires_eab(ca_provider) and ca_provider != 'private_ca':
            return None, None

        account_config = account_config or {}
        eab_key_id = account_config.get('eab_kid') or account_config.get('eab_key_id', '')
        eab_hmac_key = account_config.get('eab_hmac') or account_config.get('eab_hmac_key', '')

        if not eab_key_id or not eab_hmac_key:
            if self.requires_eab(ca_provider):
                raise ValueError(f"EAB credentials not configured for CA provider '{ca_provider}'")
            if eab_key_id or eab_hmac_key:
                # Exactly one half of the pair — proceeding without EAB is
                # the only option, but silently dropping a half-configured
                # binding makes the eventual registration failure baffling.
                logger.warning(
                    f"Incomplete EAB credentials for CA provider '{ca_provider}' "
                    f"(only {'Key ID' if eab_key_id else 'HMAC key'} is set); "
                    f"proceeding without EAB"
                )
            return None, None

        return eab_key_id, eab_hmac_key
    
    def create_ca_trust_bundle(self, ca_provider: str, account_config: Dict[str, Any] = None) -> Optional[str]:
        """Create CA trust bundle file for private CAs"""
        if ca_provider != 'private_ca' or not account_config:
            return None
        
        ca_cert_content = account_config.get('ca_cert', '')
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
                            cert_dir: Path = None, san_domains: list = None,
                            key_type: Optional[str] = None,
                            key_size: Optional[int] = None,
                            elliptic_curve: Optional[str] = None) -> tuple:
        """Build certbot command with CA-specific parameters.

        Args:
            key_type: Optional 'rsa' or 'ecdsa'. When omitted, no
                ``--key-type`` flag is emitted and certbot picks its own
                default (currently RSA-2048) — this preserves the
                pre-feature behaviour for callers that don't opt in.
            key_size: RSA key size in bits (2048/3072/4096). Required when
                ``key_type='rsa'`` and ignored otherwise.
            elliptic_curve: ECDSA curve name (secp256r1/secp384r1).
                Required when ``key_type='ecdsa'`` and ignored otherwise.

        Returns:
            Tuple of (certbot_cmd list, extra_env dict) — extra_env contains
            environment variables to pass to the subprocess (e.g. REQUESTS_CA_BUNDLE).
        """
        extra_env = {}

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

        # Add SAN domains
        if san_domains:
            for san in san_domains:
                certbot_cmd.extend(['-d', san])

        # Key type / size flags. Only emitted when the caller explicitly
        # picked one — leaving them off keeps the previous certbot default.
        if key_type == 'rsa' and key_size:
            certbot_cmd.extend(['--key-type', 'rsa', '--rsa-key-size', str(key_size)])
        elif key_type == 'ecdsa' and elliptic_curve:
            certbot_cmd.extend(['--key-type', 'ecdsa', '--elliptic-curve', elliptic_curve])

        # Add directory configuration if provided
        if cert_dir:
            cert_output_dir = cert_dir / domain
            cert_output_dir.mkdir(parents=True, exist_ok=True)

            certbot_cmd.extend([
                '--config-dir', str(cert_output_dir),
                '--work-dir', str(cert_output_dir / 'work'),
                '--logs-dir', str(cert_output_dir / 'logs')
            ])

        # Add EAB credentials if required — or optionally configured for
        # a private CA whose ACME server enforces account binding.
        eab_key_id, eab_hmac_key = self.get_eab_credentials(ca_provider, account_config)
        if eab_key_id and eab_hmac_key:
            certbot_cmd.extend([
                '--eab-kid', eab_key_id,
                '--eab-hmac-key', eab_hmac_key
            ])

        # Add CA bundle for private CAs (pass via extra_env, not os.environ)
        if ca_provider == 'private_ca':
            ca_bundle_path = self.create_ca_trust_bundle(ca_provider, account_config)
            if ca_bundle_path:
                extra_env['REQUESTS_CA_BUNDLE'] = ca_bundle_path

        return certbot_cmd, extra_env
    
    def validate_ca_configuration(self, ca_provider: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate CA provider configuration"""
        if ca_provider not in self.ca_providers:
            return False, f"Unsupported CA provider: {ca_provider}"
        
        ca_info = self.ca_providers[ca_provider]

        if ca_provider == 'private_ca' or ca_info.get('requires_acme_url'):
            if not config.get('acme_url'):
                if ca_provider == 'private_ca':
                    return False, "Private CA requires ACME server URL"
                return False, f"{ca_info['name']} requires an ACME Directory URL"
            # The same HTTPS rule for every directory an account configures,
            # private CA or public (#885). The wording keeps naming the
            # provider so an operator with several configured knows which
            # form refused them.
            what = ('ACME server URL' if ca_provider == 'private_ca'
                    else f"{ca_info['name']} ACME Directory URL")
            refusal = acme_directory_refusal(config['acme_url'], what)
            if refusal:
                return False, refusal
        
        # Check required fields based on CA provider
        if ca_info['requires_eab']:
            has_kid = config.get('eab_key_id') or config.get('eab_kid')
            has_hmac = config.get('eab_hmac_key') or config.get('eab_hmac')
            if not has_kid or not has_hmac:
                return False, f"{ca_info['name']} requires EAB Key ID and HMAC Key"

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
        if self.requires_eab(ca_provider):
            display_info['eab_configured'] = bool(
                config.get('eab_key_id') or config.get('eab_kid')
            )
            if self.ca_providers[ca_provider].get('requires_acme_url'):
                display_info['acme_url'] = config.get('acme_url', '')
        elif ca_provider == 'private_ca':
            display_info['acme_url'] = config.get('acme_url', '')
            display_info['ca_cert_configured'] = bool(config.get('ca_cert'))
            display_info['eab_configured'] = bool(
                config.get('eab_key_id') or config.get('eab_kid')
            )
        
        return display_info
