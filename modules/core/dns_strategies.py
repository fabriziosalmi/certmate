"""
DNS Provider Strategy Module
Implements the Strategy Pattern for DNS provider configuration and management.
"""

import logging
import os
import shlex
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional

from .utils import (
    create_cloudflare_config, create_azure_config, create_google_config,
    create_powerdns_config, create_digitalocean_config, create_linode_config,
    create_gandi_config, create_ovh_config, create_namecheap_config,
    create_arvancloud_config, create_infomaniak_config, create_acme_dns_config,
    create_duckdns_config, create_edgedns_config, create_multi_provider_config,
    _create_config_file
)

logger = logging.getLogger(__name__)


def check_certbot_plugin_installed(plugin_name: str) -> bool:
    """Check if a certbot plugin is installed and registered.

    Runs ``certbot plugins`` and looks for the given *plugin_name*
    (e.g. ``dns-route53``) in the output.  Returns ``True`` when found.
    """
    try:
        result = subprocess.run(
            ['certbot', 'plugins', '--prepare'],
            capture_output=True, text=True, timeout=30,
        )
        # Plugin names appear as "* dns-route53" or "PluginEntryPoint#dns-route53"
        return plugin_name in result.stdout or plugin_name in result.stderr
    except Exception:
        # If we can't check, assume it's available and let certbot fail
        # with its own error message.
        return True

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
            domain_alias: Optional domain alias for DNS validation.
                Certbot does not have a native ``--domain-alias`` flag.
                DNS alias validation works via CNAME delegation:
                create a CNAME from ``_acme-challenge.<domain>`` pointing to
                ``_acme-challenge.<alias-domain>`` in your DNS zone, and certbot
                will follow the CNAME transparently.
        """
        # Select the plugin via ``--authenticator <name>`` rather than the
        # shorthand ``--<name>``. The shorthand only works when argparse can
        # uniquely match its prefix; plugins that expose several
        # ``--<name>-…`` options (Azure: -credentials, -config,
        # -propagation-seconds; DuckDNS: -credentials, -token, -token-env,
        # -propagation-seconds, -no-txt-restore; …) make the prefix
        # ambiguous and certbot aborts with::
        #
        #   certbot: error: ambiguous option: --dns-azure could match
        #   --dns-azure-propagation-seconds, --dns-azure-config,
        #   --dns-azure-credentials
        #
        # ``--authenticator`` is the canonical, documented selector and is
        # immune to that prefix collision, so it works for every plugin
        # uniformly. See issue #113 (Azure) and the prior duckdns fix
        # (commit 4ea7269) for the same class of bug.
        cmd.extend(['--authenticator', self.plugin_name])
        if credentials_file:
            cmd.extend([f'--{self.plugin_name}-credentials', str(credentials_file)])

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} "
                f"exists in your DNS zone. Certbot follows CNAMEs automatically."
            )

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
        # The caller (CertificateManager.create_certificate /
        # renew_certificate via _dns_config_for_strategy) injects either:
        #   * ``_zone_domains`` — list of zones resolved by the per-provider
        #     discovery hook (the path that unlocks wildcard issuance
        #     against a parent hosted zone, e.g. ``*.example2.example.com``
        #     under Azure-hosted ``example.com``); written as multiple
        #     ``dns_azure_zoneN`` lines so the plugin's longest-match
        #     selects the right zone per challenge, OR
        #   * ``_zone_domain`` — single-zone string (legacy shape, kept so
        #     pre-discovery callers and existing tests keep working).
        # certbot-dns-azure 2.x aborts with "At least one zone mapping
        # needs to be provided" if neither is present.
        zone_domains = config_data.get('_zone_domains')
        if zone_domains:
            zones = [str(z).strip() for z in zone_domains if str(z).strip()]
            if not zones:
                raise ValueError(
                    "Azure DNS config received an empty '_zone_domains' "
                    "list. The discovery hook must return at least one "
                    "hosted zone covering the cert FQDN(s)."
                )
            zone_arg: Any = zones
        else:
            single = str(config_data.get('_zone_domain') or '').strip()
            if not single:
                raise ValueError(
                    "Azure DNS config requires a zone domain. The caller "
                    "must inject '_zone_domains' (list) or '_zone_domain' "
                    "(str) into dns_config before calling "
                    "AzureStrategy.create_config_file()."
                )
            zone_arg = single
        return create_azure_config(
            config_data.get('subscription_id', ''),
            config_data.get('resource_group', ''),
            config_data.get('tenant_id', ''),
            config_data.get('client_id', ''),
            config_data.get('client_secret', ''),
            zone_arg,
        )

    @property
    def plugin_name(self) -> str:
        return 'dns-azure'

    @property
    def default_propagation_seconds(self) -> int:
        return 180

    # The configure_certbot_arguments override that v2.4.3 added here for
    # #113 was made redundant by 47aacfd, which generalised the
    # --authenticator selector to the base DNSProviderStrategy. The base
    # method now does the same thing for every plugin, so AzureStrategy
    # can fall through to it unchanged.

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

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested for PowerDNS — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} exists."
            )

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

class EdgeDNSStrategy(DNSProviderStrategy):
    """Akamai Edge DNS strategy.

    Uses the certbot-plugin-edgedns package (akamai/certbot-plugin-edgedns),
    which registers itself with certbot under the plugin name ``edgedns`` and
    expects a standard Akamai EdgeGrid ``.edgerc`` credentials file with a
    ``[default]`` section.
    """

    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_edgedns_config(
            config_data.get('client_token', ''),
            config_data.get('client_secret', ''),
            config_data.get('access_token', ''),
            config_data.get('host', ''),
        )

    @property
    def plugin_name(self) -> str:
        return 'edgedns'

    @property
    def default_propagation_seconds(self) -> int:
        return 90

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        cmd.extend(['--authenticator', self.plugin_name])
        if credentials_file:
            cmd.extend([f'--{self.plugin_name}-credentials', str(credentials_file)])

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested for Akamai Edge DNS — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} exists."
            )

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
    """Namecheap DNS strategy.

    WARNING: The ``certbot-dns-namecheap`` PyPI package (v1.0.0, alpha) only
    supports Python 2.7-3.8 and is incompatible with certbot 2.x / Python 3.12.
    Users should prefer acme-dns or manual DNS challenge for Namecheap domains.
    """

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

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested for Namecheap — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} exists."
            )

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

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested for Infomaniak — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} exists."
            )

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

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested for ACME-DNS — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} exists."
            )

class DuckDNSStrategy(DNSProviderStrategy):
    """DuckDNS free DDNS provider via certbot-dns-duckdns plugin.

    DuckDNS gives anyone a free ``<name>.duckdns.org`` subdomain, which is
    the canonical "I don't own a domain" path to a publicly-trusted cert.
    Only the apex account token is required; the same token can issue
    certificates for any subdomain the account owns, including wildcards.
    """

    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_duckdns_config(config_data.get('api_token', ''))

    @property
    def plugin_name(self) -> str:
        return 'dns-duckdns'

    @property
    def default_propagation_seconds(self) -> int:
        # Plugin default is 30s but DuckDNS propagation occasionally exceeds
        # that under load; 60s gives a safer margin without being disruptive.
        return 60

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        # certbot-dns-duckdns exposes multiple --dns-duckdns-* options
        # (credentials, token, token-env, propagation-seconds, no-txt-restore),
        # which makes the bare --dns-duckdns selector flag ambiguous to
        # certbot's argparse. Select the plugin via --authenticator instead.
        cmd.extend(['--authenticator', 'dns-duckdns'])
        if credentials_file:
            cmd.extend(['--dns-duckdns-credentials', str(credentials_file)])

        if domain_alias:
            logger.info(
                f"DNS alias '{domain_alias}' requested for DuckDNS — ensure a CNAME "
                f"from _acme-challenge.<domain> to _acme-challenge.{domain_alias} exists."
            )


class GenericMultiProviderStrategy(DNSProviderStrategy):
    def __init__(self, provider_name: str):
        self.provider_name = provider_name

    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return create_multi_provider_config(self.provider_name, config_data)

    @property
    def plugin_name(self) -> str:
        return f'dns-{self.provider_name}'


class CustomScriptStrategy(DNSProviderStrategy):
    """Admin-supplied DNS hook scripts via certbot --manual (#286).

    Covers any DNS provider without a certbot plugin (OCI, in-house DNS,
    appliance APIs, ...): the admin points CertMate at an auth script and
    an optional cleanup script, and certbot invokes them with
    CERTBOT_DOMAIN / CERTBOT_VALIDATION in the environment exactly as
    documented for --manual-auth-hook. The auth script is responsible for
    creating the _acme-challenge TXT record AND waiting until it has
    propagated — certbot does not sleep between hook and validation.

    Trust model: same as deploy hooks — the script paths are configured by
    an authenticated admin and execute with CertMate's privileges. The
    paths are validated at issuance time (absolute, existing, executable,
    not world-writable) so a typo or a tampered-permissions file fails
    loudly instead of producing a baffling certbot error. certbot executes
    manual hooks THROUGH THE SHELL (subprocess shell=True) and validates
    them by splitting on whitespace, so paths containing whitespace or any
    shell metacharacter are rejected outright — they cannot work even
    quoted, and rejecting them here beats certbot's cryptic
    HookCommandNotFound on a truncated token.

    Renewals work because certbot persists manual_auth_hook /
    manual_cleanup_hook in its per-domain renewal conf: the scripts are
    stable admin paths, not temp files, so the replay just works. If the
    admin moves a script after issuance, the conf still points at the old
    path — reissue (or edit the renewal conf) after relocating scripts.
    """

    def __init__(self):
        self._auth_hook: Optional[str] = None
        self._cleanup_hook: Optional[str] = None

    @staticmethod
    def _validated_hook_path(path_value: Optional[str], label: str) -> Optional[str]:
        if not path_value or not str(path_value).strip():
            return None
        path = Path(str(path_value).strip())
        if not path.is_absolute():
            raise ValueError(f"custom-script {label} must be an absolute path: {path}")
        if not path.is_file():
            raise ValueError(f"custom-script {label} does not exist: {path}")
        if not os.access(path, os.X_OK):
            raise ValueError(f"custom-script {label} is not executable: {path}")
        if shlex.quote(str(path)) != str(path):
            # certbot executes manual hooks through the shell AND its hook
            # validation splits the command on whitespace, so a path with
            # spaces or shell metacharacters cannot work even when quoted.
            # Failing here gives a clear message instead of certbot's
            # HookCommandNotFound on a truncated token.
            raise ValueError(
                f"custom-script {label} path contains whitespace or shell "
                f"metacharacters, which certbot's shell-based hook execution "
                f"cannot handle: {path}. Use a path containing only letters, "
                f"digits, '/', '.', '_' and '-'."
            )
        mode = path.stat().st_mode
        if mode & 0o002:
            raise ValueError(
                f"custom-script {label} is world-writable ({oct(mode & 0o777)}): {path}. "
                f"Refusing to execute a script anyone on the host can modify."
            )
        if mode & 0o020:
            logger.warning(
                f"custom-script {label} {path} is group-writable "
                f"({oct(mode & 0o777)}); consider chmod 755 or stricter."
            )
        return str(path)

    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        # The "credentials" are the hook paths themselves; validate them and
        # keep them on the instance for configure_certbot_arguments. No temp
        # credentials file is needed.
        self._auth_hook = self._validated_hook_path(config_data.get('auth_hook'), 'auth hook')
        if not self._auth_hook:
            raise ValueError(
                "custom-script DNS provider requires an 'auth_hook' script path"
            )
        self._cleanup_hook = self._validated_hook_path(config_data.get('cleanup_hook'), 'cleanup hook')
        return None

    @property
    def plugin_name(self) -> str:
        # 'manual' is a certbot core feature, not an installable plugin —
        # the plugin-installed preflight skips it (see certificates.py).
        return 'manual'

    @property
    def supports_propagation_seconds_flag(self) -> bool:
        # --manual has no propagation flag; waiting is the auth hook's job.
        return False

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        if not self._auth_hook:
            raise ValueError(
                "CustomScriptStrategy.configure_certbot_arguments called "
                "before create_config_file validated the hook paths"
            )
        # The validated paths are shell-safe by construction (validation
        # rejects anything shlex.quote would alter), so raw emission is
        # safe for certbot's shell-based hook execution AND survives its
        # whitespace-splitting hook validation, which a quoted spaced path
        # would not.
        cmd.extend([
            '--manual',
            '--preferred-challenges', 'dns',
            '--manual-auth-hook', self._auth_hook,
        ])
        if self._cleanup_hook:
            cmd.extend(['--manual-cleanup-hook', self._cleanup_hook])

    def prepare_environment(self, env: Dict[str, str], config_data: Dict[str, Any]) -> None:
        # Optional hint for scripts that prefer a configurable sleep over
        # polling their DNS API: surfaces the account-level setting.
        propagation = config_data.get('propagation_seconds')
        if propagation:
            env['CERTMATE_DNS_PROPAGATION_SECONDS'] = str(propagation)

def acme_webroot_dir() -> Path:
    """Absolute filesystem root for HTTP-01 webroot challenges.

    Single source of truth for the three call sites that must agree or
    issuance silently fails: the certbot ``--webroot`` argument (where certbot
    writes the token), the challenge-directory pre-creation in
    ``CertificateManager``, and the Flask route that serves
    ``/.well-known/acme-challenge/<token>`` (see ``modules/web/routes.py`` and
    ``modules/core/factory.py``). Override the location with the
    ``ACME_CHALLENGES_DIR`` environment variable; the default keeps the
    historical ``<cwd>/data/acme-challenges`` path.
    """
    return Path(os.environ.get('ACME_CHALLENGES_DIR', 'data/acme-challenges')).resolve()


class HTTP01Strategy(DNSProviderStrategy):
    """HTTP-01 challenge using certbot --webroot plugin.

    No DNS credentials needed. CertMate serves challenge files
    via /.well-known/acme-challenge/<token> and certbot writes
    them to the webroot directory (see ``acme_webroot_dir``).
    """

    @property
    def plugin_name(self) -> str:
        return 'webroot'

    def create_config_file(self, config_data: Dict[str, Any]) -> Optional[Path]:
        return None  # No credentials needed

    def configure_certbot_arguments(self, cmd: list, credentials_file: Optional[Path], domain_alias: Optional[str] = None) -> None:
        cmd.extend(['--webroot', '-w', str(acme_webroot_dir())])

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
        'edgedns': EdgeDNSStrategy,
        'gandi': GandiStrategy,
        'ovh': OVHStrategy,
        'namecheap': NamecheapStrategy,
        'arvancloud': ArvanCloudStrategy,
        'infomaniak': InfomaniakStrategy,
        'acme-dns': AcmeDNSStrategy,
        'duckdns': DuckDNSStrategy,
        'custom-script': CustomScriptStrategy,
        'http-01': HTTP01Strategy,
    }
    
    @classmethod
    def get_strategy(cls, provider_name: str) -> DNSProviderStrategy:
        strategy_class = cls._strategies.get(provider_name)
        if strategy_class:
            return strategy_class()
        return GenericMultiProviderStrategy(provider_name)
