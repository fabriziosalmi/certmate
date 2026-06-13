"""
Certificate operations module for CertMate
Handles certificate creation, renewal, and information retrieval
"""

import os
import copy
import json
import shlex
import subprocess
import sys
import tempfile
import time
import logging
import shutil
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from .shell import ShellExecutor
from .dns_strategies import DNSStrategyFactory, HTTP01Strategy, acme_webroot_dir, check_certbot_plugin_installed
from .constants import CERTIFICATE_FILES, get_domain_name
from .utils import DeploymentStatusCache, validate_domain, utc_now, utc_now_iso, validate_key_options

logger = logging.getLogger(__name__)

DNS_ALIAS_SUPPORTED_PROVIDERS = {
    'cloudflare',
    'route53',
    'azure',
    'google',
    'powerdns',
    'digitalocean',
    'linode',
    'edgedns',
    'gandi',
    'ovh',
    'namecheap',
    'arvancloud',
    'infomaniak',
    'acme-dns',
    'duckdns',
}

DNS_ALIAS_REQUIRED_FIELDS = {
    'cloudflare': ('api_token',),
    'route53': ('access_key_id', 'secret_access_key'),
    'azure': ('subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret'),
    'google': ('project_id', 'service_account_key'),
    'powerdns': ('api_url', 'api_key'),
    'digitalocean': ('api_token',),
    'linode': ('api_key',),
    'edgedns': ('client_token', 'client_secret', 'access_token', 'host'),
    'gandi': ('api_token',),
    'ovh': ('endpoint', 'application_key', 'application_secret', 'consumer_key'),
    'namecheap': ('username', 'api_key'),
    'arvancloud': ('api_key',),
    'infomaniak': ('api_token',),
    'acme-dns': ('api_url', 'username', 'password', 'subdomain'),
    'duckdns': ('api_token',),
}


class DomainOperationInProgress(RuntimeError):
    """Raised when a create/renew can't acquire the per-domain lock within the
    timeout because another operation for the same domain is in progress."""
    def __init__(self, domain):
        self.domain = domain
        super().__init__(f"A certificate operation for {domain} is already in progress")


class CertificateManager:
    """Class to handle certificate operations"""
    
    def __init__(self, cert_dir, settings_manager, dns_manager, storage_manager=None, ca_manager=None, shell_executor=None):
        self.cert_dir = Path(cert_dir)
        self.settings_manager = settings_manager
        self.dns_manager = dns_manager
        self.storage_manager = storage_manager
        self.ca_manager = ca_manager
        self.shell_executor = shell_executor or ShellExecutor()
        self._certificate_info_cache = DeploymentStatusCache(default_ttl=self._certificate_info_cache_ttl())
        # Per-domain locks to prevent concurrent create/renew on the same domain
        self._domain_locks: dict[str, threading.Lock] = {}
        self._domain_locks_mutex = threading.Lock()

    @staticmethod
    def _certificate_info_cache_ttl() -> int:
        try:
            return max(0, min(3600, int(os.environ.get('CERTMATE_CERT_INFO_CACHE_TTL', '60'))))
        except (TypeError, ValueError):
            return 60

    @staticmethod
    def _domain_lock_timeout() -> float:
        """Seconds to wait for the per-domain lock before reporting the domain
        busy. Override via CERTMATE_DOMAIN_LOCK_TIMEOUT (clamped 0-60)."""
        try:
            return max(0.0, min(60.0, float(os.environ.get('CERTMATE_DOMAIN_LOCK_TIMEOUT', '5'))))
        except (TypeError, ValueError):
            return 5.0

    @staticmethod
    def _certificate_info_cache_key(domain: str, settings: dict | None) -> str:
        threshold = 30
        if isinstance(settings, dict):
            try:
                threshold = int(settings.get('renewal_threshold_days', 30))
            except (TypeError, ValueError):
                threshold = 30
        return f"{domain}|renewal_threshold_days={threshold}|date={utc_now().date().isoformat()}"

    def _get_cached_certificate_info(self, domain: str, settings: dict | None = None):
        cached = self._certificate_info_cache.get(self._certificate_info_cache_key(domain, settings))
        return copy.deepcopy(cached) if cached is not None else None

    def _set_cached_certificate_info(self, domain: str, info: dict, settings: dict | None = None) -> None:
        ttl = self._certificate_info_cache_ttl()
        if ttl > 0:
            self._certificate_info_cache.set(
                self._certificate_info_cache_key(domain, settings),
                copy.deepcopy(info),
                ttl=ttl,
            )

    def _invalidate_certificate_info_cache(self, domain: str) -> None:
        # Cache keys are "{domain}|renewal_threshold_days=...|date=...", so a
        # single domain can have multiple active entries (different thresholds
        # / UTC dates). Clear only this domain's variants via the "{domain}|"
        # prefix — the literal pipe separator guarantees we never wipe an
        # unrelated domain that merely shares a string prefix (e.g.
        # "example.com" vs "example.com.evil"). A single-domain mutation must
        # not invalidate every other domain's cached info.
        self._certificate_info_cache.clear_prefix(f"{domain}|")

    @staticmethod
    def _atomic_binary_copy(src: Path, dest: Path) -> None:
        """Copy a binary file atomically via a temp sibling + rename."""
        tmp = dest.with_suffix('.tmp')
        try:
            tmp.write_bytes(src.read_bytes())
            tmp.replace(dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    @staticmethod
    def _atomic_json_write(path: Path, data: dict) -> None:
        """Write JSON atomically via a temp file + rename to avoid partial writes on crash."""
        import json
        tmp = path.with_suffix('.tmp')
        try:
            tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')
            tmp.replace(path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    def _get_domain_lock(self, domain: str) -> threading.Lock:
        """Return the per-domain lock, creating it on first use."""
        with self._domain_locks_mutex:
            if domain not in self._domain_locks:
                self._domain_locks[domain] = threading.Lock()
            return self._domain_locks[domain]

    def _metadata_path(self, domain: str) -> Path:
        return self.cert_dir / domain / 'metadata.json'

    def _load_metadata(self, domain: str) -> dict:
        metadata_file = self._metadata_path(domain)
        if not metadata_file.exists():
            return {}
        try:
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                return metadata if isinstance(metadata, dict) else {}
        except json.JSONDecodeError as e:
            # The on-disk metadata is unparseable. Quarantine it before
            # returning {} — otherwise the next _save_metadata would overwrite
            # the only copy with an empty dict and destroy whatever was in it.
            quarantine = metadata_file.with_suffix(
                f'.json.corrupt-{utc_now().strftime("%Y%m%dT%H%M%SZ")}'
            )
            try:
                metadata_file.rename(quarantine)
                logger.error(
                    f"Corrupt metadata for {domain}: {e}. "
                    f"Quarantined to {quarantine.name}; downstream callers "
                    f"will see an empty metadata dict until a fresh write."
                )
            except OSError as rename_err:
                logger.error(
                    f"Corrupt metadata for {domain}: {e}. "
                    f"Could not quarantine ({rename_err}); leaving file in "
                    f"place to avoid clobbering on next save."
                )
            return {}
        except OSError as e:
            logger.warning(f"Failed to read metadata for {domain}: {e}")
            return {}

    def _save_metadata(self, domain: str, metadata: dict) -> bool:
        metadata_file = self._metadata_path(domain)
        try:
            self._atomic_json_write(metadata_file, metadata)
            self._invalidate_certificate_info_cache(domain)
            return True
        except Exception as e:
            logger.warning(f"Failed to save metadata for {domain}: {e}")
            return False

    def _write_pfx(self, domain: str) -> None:
        """(Re)generate <domain>/cert.pfx from the on-disk PEMs when a PFX
        export password is configured, else remove any stale bundle.

        Called after each successful issuance/renewal so the .pfx fingerprint
        tracks the live certificate — Windows automation can poll it to detect
        a fresh cert (issue #230). Best-effort: it never fails the surrounding
        certificate operation.
        """
        domain_dir = self.cert_dir / domain
        pfx_path = domain_dir / 'cert.pfx'
        try:
            settings = self.settings_manager.load_settings()
        except Exception as e:
            logger.debug("Failed to load settings for PFX generation: %s", e)
            settings = {}
        password = ''
        if isinstance(settings, dict):
            password = (settings.get('pfx_password') or '').strip()

        if not password:
            # Export disabled: don't leave a bundle encrypted with an old
            # password lying around.
            try:
                pfx_path.unlink()
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"Could not remove stale PFX for {domain}: {e}")
            return

        cert_file = domain_dir / 'cert.pem'
        key_file = domain_dir / 'privkey.pem'
        chain_file = domain_dir / 'chain.pem'
        if not cert_file.exists() or not key_file.exists():
            logger.warning(f"Cannot build PFX for {domain}: cert.pem/privkey.pem missing")
            return

        try:
            from .storage_backends import _build_pfx
            chain_bytes = chain_file.read_bytes() if chain_file.exists() else None
            pfx_bytes = _build_pfx(
                cert_file.read_bytes(), chain_bytes, key_file.read_bytes(),
                password=password.encode('utf-8'),
            )
            tmp = pfx_path.with_name('cert.pfx.tmp')
            with open(tmp, 'wb') as f:
                f.write(pfx_bytes)
            os.chmod(tmp, 0o600)
            os.replace(tmp, pfx_path)
            logger.info(f"Wrote encrypted PKCS#12 bundle for {domain}")
        except Exception as e:
            logger.warning(f"Failed to build PFX for {domain}: {e}")

    def get_deployment_status_record(self, domain: str) -> dict:
        metadata = self._load_metadata(domain)
        status = metadata.get('deployment_status')
        return status if isinstance(status, dict) else {}

    def record_backend_deployment_status(self, domain: str, backend_status: dict) -> dict:
        # Hold the per-domain lock around the read-modify-write so a concurrent
        # record_browser_deployment_status for the same domain cannot overwrite
        # the backend block we are about to persist (lost-write window).
        with self._get_domain_lock(domain):
            metadata = self._load_metadata(domain)
            deployment_status = metadata.get('deployment_status')
            if not isinstance(deployment_status, dict):
                deployment_status = {}

            deployment_status['backend'] = {
                'domain': backend_status.get('domain', domain),
                'deployed': bool(backend_status.get('deployed', False)),
                'reachable': bool(backend_status.get('reachable', False)),
                'certificate_match': backend_status.get('certificate_match'),
                'method': backend_status.get('method'),
                'timestamp': backend_status.get('timestamp') or utc_now_iso(),
                'error': backend_status.get('error'),
            }

            metadata['deployment_status'] = deployment_status
            self._save_metadata(domain, metadata)
            return deployment_status

    def record_browser_deployment_status(self, domain: str, browser_status: dict) -> dict:
        with self._get_domain_lock(domain):
            metadata = self._load_metadata(domain)
            deployment_status = metadata.get('deployment_status')
            if not isinstance(deployment_status, dict):
                deployment_status = {}

            deployment_status['browser'] = {
                'reachable': bool(browser_status.get('reachable', False)),
                'checked_at': browser_status.get('checked_at') or utc_now_iso(),
                'method': browser_status.get('method') or 'browser-fallback',
                'source': browser_status.get('source') or 'browser',
            }

            metadata['deployment_status'] = deployment_status
            self._save_metadata(domain, metadata)
            return deployment_status

    @staticmethod
    def _dns_config_for_strategy(dns_provider, dns_config, domain, san_domains=None):
        """Return a strategy-ready copy of dns_config with provider-specific extras.

        Azure DNS is currently the only provider whose certbot plugin
        cannot self-discover the hosted zone for an ACME challenge — it
        wants explicit ``dns_azure_zoneN`` lines in its ini file. We hand
        it the list of hosted zones the account actually owns (looked up
        via :func:`modules.core.dns_zone_discovery.resolve_zones_for_domains`)
        so the plugin's longest-match selects the right zone per
        challenge. This is what unlocks nested-subdomain wildcards
        against a parent hosted zone — e.g. issuing
        ``*.example2.example.com`` when Azure only hosts ``example.com``.

        **RBAC escape hatch**: if ``dns_config`` carries an explicit
        ``zone_domains`` list (set by the operator on the account), we
        skip the live discovery call and use the supplied list directly.
        That keeps existing Azure service principals working when their
        scope only includes ``Microsoft.Network/dnsZones/TXT/write`` on
        specific zones and lacks ``dnsZones/read`` on the resource group
        — granting the broader read permission for auto-discovery would
        otherwise be a hard prerequisite for the v2.6.10 upgrade.

        For any provider without a discovery hook the legacy single-zone
        shape is preserved: the cert FQDN apex goes into ``_zone_domain``
        and the strategy uses it verbatim. Today that branch is unused
        because Azure is the only entry in the registry, but it keeps
        the contract stable for any future caller / test that still
        passes the legacy shape.
        """
        if dns_provider != 'azure':
            return dns_config

        from .dns_zone_discovery import (
            has_zone_discovery, resolve_zones_for_domains,
            resolve_zones_against_explicit_list,
        )

        if has_zone_discovery(dns_provider):
            fqdns = [domain]
            if san_domains:
                for san in san_domains:
                    if san and san not in fqdns:
                        fqdns.append(san)

            explicit_zones = dns_config.get('zone_domains') if isinstance(dns_config, dict) else None
            if explicit_zones:
                # Operator-supplied list — no Azure ARM call needed.
                # Same matching + fail-early semantics as the discovery
                # path; just skips the SDK round-trip.
                zone_domains, per_fqdn = resolve_zones_against_explicit_list(
                    dns_provider, explicit_zones, fqdns,
                )
                source = 'explicit zone_domains'
            else:
                zone_domains, per_fqdn = resolve_zones_for_domains(
                    dns_provider, dns_config, fqdns,
                )
                source = 'discovery'

            # One INFO per cert with the full FQDN -> zone map; avoids the
            # N-line spam a SAN cert with many entries used to produce.
            logger.info(
                "Resolved %s DNS zones (%s) for %d FQDN(s): %s",
                dns_provider, source, len(fqdns),
                ', '.join(f"{f}->{z}" for f, z in per_fqdn),
            )
            return {**dns_config, '_zone_domains': zone_domains}

        # Legacy single-zone fallback (no discovery registered).
        zone_domain = (domain or '').strip().removeprefix('*.')
        return {**dns_config, '_zone_domain': zone_domain}

    @staticmethod
    def _create_dns_alias_hook_config(dns_provider, dns_config, domain_alias, propagation_seconds):
        """Write temporary config consumed by the DNS alias hook."""
        if dns_provider not in DNS_ALIAS_SUPPORTED_PROVIDERS:
            raise RuntimeError(f"DNS alias mode is not implemented for provider '{dns_provider}'")

        missing_fields = [
            field for field in DNS_ALIAS_REQUIRED_FIELDS[dns_provider]
            if not str(dns_config.get(field) or '').strip()
        ]
        if missing_fields:
            raise ValueError(
                f"{dns_provider} DNS alias mode requires: {', '.join(missing_fields)}"
            )

        if dns_provider == 'acme-dns':
            configured_alias = str(dns_config.get('subdomain') or '').strip().rstrip('.')
            requested_alias = domain_alias.strip().rstrip('.')
            if configured_alias != requested_alias:
                raise ValueError(
                    f"ACME-DNS domain_alias must match configured subdomain '{configured_alias}'"
                )

        # Note: for Azure the DNS alias hook resolves the (possibly
        # sub-delegated) hosted zone at runtime via Lexicon's
        # resolve_zone_name (dnspython SOA lookup). We deliberately do NOT
        # pre-resolve it here — tldextract-style pre-resolution collapsed
        # sub-delegated zones to the registered domain and broke issuance
        # (issue #243).

        fd, path = tempfile.mkstemp(prefix='certmate-dns-alias-', suffix='.json')
        config_path = Path(path)
        payload = {
            'provider': dns_provider,
            'domain_alias': domain_alias.strip().rstrip('.'),
            'propagation_seconds': int(propagation_seconds),
            'config': dns_config,
        }
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(payload, f)
            config_path.chmod(0o600)
            return config_path
        except Exception:
            config_path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _configure_dns_alias_arguments(cmd, hook_config):
        """Configure certbot manual DNS hooks for DNS alias validation."""
        hook_script = Path(__file__).with_name('dns_alias_hook.py')
        auth_hook = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(hook_script))} "
            f"--config {shlex.quote(str(hook_config))} --action auth"
        )
        cleanup_hook = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(hook_script))} "
            f"--config {shlex.quote(str(hook_config))} --action cleanup"
        )
        cmd.extend([
            '--manual',
            '--preferred-challenges', 'dns',
            '--manual-auth-hook', auth_hook,
            '--manual-cleanup-hook', cleanup_hook,
        ])

    @staticmethod
    def _normalize_dns_name(value):
        return (value or '').strip().lower().removeprefix('*.').rstrip('.')

    @classmethod
    def _dns01_challenge_name(cls, domain):
        normalized = cls._normalize_dns_name(domain)
        return f"_acme-challenge.{normalized}" if normalized else ''

    @classmethod
    def build_dns_alias_expectations(cls, domain, domain_alias, san_domains=None):
        """Build expected DNS-01 CNAME records for an alias-mode certificate."""
        alias = cls._normalize_dns_name(domain_alias).removeprefix('_acme-challenge.')
        if not domain or not alias:
            return []

        expected_target = f"_acme-challenge.{alias}"
        challenge_names = []
        for candidate in [domain] + list(san_domains or []):
            challenge_name = cls._dns01_challenge_name(candidate)
            if challenge_name and challenge_name not in challenge_names:
                challenge_names.append(challenge_name)

        return [
            {
                'source': challenge_name,
                'expected_target': expected_target,
            }
            for challenge_name in challenge_names
        ]

    @staticmethod
    def _normalize_cname_target(value):
        return (value or '').strip().lower().rstrip('.')

    @classmethod
    def _resolve_cname(cls, source):
        query = urllib.parse.urlencode({'name': source, 'type': 'CNAME'})
        # Hardcoded https URL (Cloudflare's DNS-over-HTTPS endpoint). Bandit
        # B310 fires defensively on urlopen, but the scheme + host are both
        # compile-time literals here, only the query string is variable.
        request = urllib.request.Request(
            f'https://cloudflare-dns.com/dns-query?{query}',
            headers={'accept': 'application/dns-json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310 - hardcoded https literal
                payload = json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f'DNS query failed with HTTP {e.code}') from e
        except urllib.error.URLError as e:
            raise RuntimeError(f'DNS query failed: {e.reason}') from e

        answers = payload.get('Answer') or []
        return [
            answer.get('data', '').strip()
            for answer in answers
            if answer.get('type') == 5 and answer.get('data')
        ]

    def check_dns_alias_records(self, domain, domain_alias, san_domains=None):
        """Check that DNS-01 alias CNAMEs exist for a requested certificate."""
        checks = []
        for expectation in self.build_dns_alias_expectations(domain, domain_alias, san_domains):
            source = expectation['source']
            expected_target = self._normalize_cname_target(expectation['expected_target'])
            found_targets = []
            error = None

            try:
                found_targets = self._resolve_cname(source)
            except Exception as e:
                error = str(e)

            normalized_found = [self._normalize_cname_target(target) for target in found_targets]
            status = 'ok' if expected_target in normalized_found else 'missing'
            if normalized_found and expected_target not in normalized_found:
                status = 'mismatch'
            if error:
                status = 'error'

            checks.append({
                'source': source,
                'expected_target': expectation['expected_target'],
                'found_targets': found_targets,
                'status': status,
                'ok': status == 'ok',
                'error': error,
            })

        return {
            'domain': domain,
            'domain_alias': domain_alias,
            'checks': checks,
            'ok': bool(checks) and all(check['ok'] for check in checks),
        }





    def get_certificate_info(self, domain, settings=None, use_cache=True):
        """Get certificate information for a domain.

        ``settings`` is an optional pre-loaded settings dict. Callers
        that already have settings in hand (notably check_renewals,
        which iterates 100s of domains in a background job) should
        pass it in to skip the per-domain load_settings call inside
        this method and _parse_certificate_info — outside a Flask
        request context the request-scoped cache does not apply, so
        without this parameter the renewal job hit disk once per
        domain for the same settings.json.

        ``use_cache`` controls the cross-request ``_certificate_info_cache``
        (storage-backend path only) independently of ``settings``. It is
        ON by default so listing endpoints keep the 60s cert-info cache
        even when they thread their already-loaded ``settings`` through.
        Bulk one-pass callers that visit each domain exactly once per run
        (e.g. check_renewals) should pass ``use_cache=False`` to skip the
        pointless deepcopy-on-set — they never get a read hit anyway.
        """
        if not domain:
            return None

        # First try to get certificate from storage backend if available
        if self.storage_manager:
            cache_enabled = use_cache
            cache_settings = settings
            if cache_settings is None:
                try:
                    cache_settings = self.settings_manager.load_settings()
                except Exception as e:
                    logger.debug("Failed to load settings in get_certificate_info: %s", e)
                    cache_settings = {}
            if cache_enabled:
                cached = self._get_cached_certificate_info(domain, cache_settings)
                if cached is not None:
                    return cached
            try:
                retrieve_info = getattr(self.storage_manager, 'retrieve_certificate_info', None)
                storage_result = None
                if callable(retrieve_info):
                    candidate = retrieve_info(domain)
                    if candidate is None:
                        storage_result = None
                    elif isinstance(candidate, tuple) and len(candidate) == 2:
                        storage_result = candidate
                    else:
                        logger.debug(
                            "Storage backend returned invalid certificate-info "
                            "shape for %s; falling back to full retrieve.",
                            domain,
                        )
                        storage_result = self.storage_manager.retrieve_certificate(domain)
                else:
                    storage_result = self.storage_manager.retrieve_certificate(domain)
                if storage_result:
                    cert_files, metadata = storage_result
                    if 'cert.pem' in cert_files:
                        info = self._parse_certificate_info(domain, cert_files['cert.pem'], metadata, settings=cache_settings)
                        if cache_enabled:
                            self._set_cached_certificate_info(domain, info, cache_settings)
                        return info
            except Exception as e:
                logger.warning(f"Failed to retrieve certificate from storage backend for {domain}: {e}")
        
        # Fall back to local filesystem for backward compatibility
        cert_dir = self.cert_dir
        cert_path = cert_dir / domain
        if not cert_path.exists():
            logger.info(f"Certificate directory does not exist for domain: {domain}")
            return self._create_empty_cert_info(domain)
        
        cert_file = cert_path / "cert.pem"
        if not cert_file.exists():
            logger.info(f"Certificate file does not exist for domain: {domain}")
            return self._create_empty_cert_info(domain)
        
        # Get DNS provider info from metadata file first, then fall back to
        # settings. Uses the centralised _load_metadata so a corrupt JSON file
        # gets quarantined consistently and we don't have two divergent
        # readers handling JSONDecodeError differently.
        metadata = self._load_metadata(domain)
        dns_provider = metadata.get('dns_provider') if metadata else None
        if dns_provider:
            logger.debug(f"Found DNS provider '{dns_provider}' in metadata for {domain}")
        
        if not dns_provider:
            # Fall back to current settings. Reuse the caller-supplied dict
            # when present (renewal job) to avoid reloading from disk.
            if settings is None:
                settings = self.settings_manager.load_settings()
            dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)
            logger.debug(f"Using DNS provider '{dns_provider}' from settings for {domain}")

        # Read certificate file and parse info
        try:
            with open(cert_file, 'rb') as f:
                cert_content = f.read()
            return self._parse_certificate_info(domain, cert_content, metadata, settings=settings)
        except Exception as e:
            logger.error(f"Failed to read certificate file for {domain}: {e}")
            return self._create_empty_cert_info(domain)
    
    def _parse_certificate_info(self, domain, cert_content, metadata=None, settings=None):
        """Parse certificate information from certificate content.

        ``settings`` mirrors the get_certificate_info parameter: callers
        that pre-loaded settings (renewal job) pass it in to skip the
        per-domain reload from disk.
        """
        if metadata is None:
            metadata = {}

        dns_provider = metadata.get('dns_provider')
        domain_alias = metadata.get('domain_alias')
        alias_dns_provider = metadata.get('alias_dns_provider')
        san_domains = metadata.get('san_domains') or []
        # Issuance config surfaced for the Edit & Reissue prefill (#267):
        # without these the edit form would silently reset a non-default CA
        # or challenge type back to the global defaults.
        ca_provider = metadata.get('ca_provider')
        challenge_type = metadata.get('challenge_type')
        account_id = metadata.get('account_id')
        if settings is None:
            settings = self.settings_manager.load_settings()
        if not dns_provider:
            # Fall back to current settings
            dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)

        # Get configurable renewal threshold (default 30 days for backward compatibility)
        renewal_threshold_days = settings.get('renewal_threshold_days', 30)

        try:
            # Parse the certificate in-process with `cryptography` (already a
            # dependency, used elsewhere in this codebase). The previous
            # implementation wrote each cert to a temp file and spawned an
            # `openssl x509 -enddate` subprocess; with many certificates that
            # meant one process spawn + one temp file per row on every table
            # load, which dominated listing latency on a CPU-throttled
            # container.
            cert = x509.load_pem_x509_certificate(cert_content)
            # not_valid_after_utc is timezone-aware UTC; drop the tzinfo so the
            # arithmetic matches utc_now(), which is naive UTC by design.
            expiry_date = cert.not_valid_after_utc.replace(tzinfo=None)
            now_utc = utc_now()
            days_left = (expiry_date - now_utc).days

            return {
                'domain': domain,
                'exists': True,
                'expiry_date': expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                'days_left': days_left,
                'days_until_expiry': days_left,
                # Inclusive boundary: a cert with exactly renewal_threshold_days
                # left must renew. Using `<` skipped the boundary, delaying
                # renewal by a day; digest.py and metrics.py already use `<=`.
                'needs_renewal': days_left <= renewal_threshold_days,
                'dns_provider': dns_provider,
                'domain_alias': domain_alias,
                'alias_dns_provider': alias_dns_provider,
                'san_domains': san_domains,
                'ca_provider': ca_provider,
                'challenge_type': challenge_type,
                'account_id': account_id
            }
        except Exception as e:
            logger.error(f"Error parsing certificate for {domain}: {e}")

        # Certificate file exists but we couldn't parse the expiry — still mark exists=True
        return {
            'domain': domain,
            'exists': True,
            'expiry_date': None,
            'days_left': None,
            'days_until_expiry': None,
            'needs_renewal': True,
            'dns_provider': dns_provider,
            'domain_alias': domain_alias,
            'alias_dns_provider': alias_dns_provider,
            'san_domains': san_domains,
            'ca_provider': ca_provider,
            'challenge_type': challenge_type,
            'account_id': account_id
        }

    def _create_empty_cert_info(self, domain):
        """Create empty certificate info structure"""
        settings = self.settings_manager.load_settings()
        dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)
        
        return {
            'domain': domain,
            'exists': False,
            'expiry_date': None,
            'days_left': None,
            'days_until_expiry': None,
            'needs_renewal': False,
            'dns_provider': dns_provider
        }

    def create_certificate(self, domain, email, dns_provider=None, dns_config=None, account_id=None, staging=False, ca_provider=None, ca_account_id=None, domain_alias=None, alias_dns_provider=None, san_domains=None, challenge_type=None, key_type=None, key_size=None, elliptic_curve=None, replace=False):
        """Create SSL certificate using configurable CA with DNS challenge

        Args:
            domain: Primary domain name for certificate
            email: Contact email for certificate authority
            dns_provider: DNS provider name (e.g., 'cloudflare')
            dns_config: Explicit DNS configuration (overrides account lookup)
            account_id: Specific account ID to use for the DNS provider
            staging: Use staging environment for testing
            ca_provider: Certificate Authority provider (letsencrypt, digicert, private_ca)
            ca_account_id: Specific CA account ID to use
            domain_alias: Optional domain alias for DNS validation (e.g., '_acme-challenge.validation.example.org')
            alias_dns_provider: Provider managing the ALIAS zone when it
                differs from dns_provider (set via PATCH, issue #129, and
                honoured by renewals). The alias challenge hook runs with
                this provider's account; metadata records it so future
                renewals keep using it.
            san_domains: Optional list of additional domains for Subject Alternative Names (SAN)
            key_type: Optional 'rsa' or 'ecdsa'. If all three key kwargs are
                None the global ``default_key_*`` from settings are applied,
                so callers (legacy web routes, scripts) get the configured
                default for free. Pass an explicit value here to override
                per-domain.
            key_size: RSA key size in bits (only valid with key_type='rsa').
            elliptic_curve: ECDSA curve (only valid with key_type='ecdsa').
            replace: Reissue over the existing certbot lineage (#267). The
                same ``--cert-name`` with a different ``-d`` set makes
                certbot replace the lineage's domain set (expand AND
                shrink); ``--renew-with-new-domains`` is added so the
                domain-change confirmation never depends on prompt
                defaults. The old certificate keeps being served until
                certbot succeeds. With ``replace`` the global key-shape
                defaults are NOT applied when no key option is passed:
                emitting them would silently re-key the lineage, while
                omitting the flags makes certbot keep the existing key
                type.
        """
        # Acquire per-domain lock to prevent concurrent create/renew operations
        domain_lock = self._get_domain_lock(domain)
        if not domain_lock.acquire(timeout=self._domain_lock_timeout()):
            raise DomainOperationInProgress(domain)

        # Track timing for metrics
        start_time = time.time()
        credentials_file = None
        # Initialized early: the finally block reads ca_extra_env to clean up
        # the REQUESTS_CA_BUNDLE temp file, and an exception raised before the
        # ca_manager.build_certbot_command call (e.g. plugin-not-installed)
        # would otherwise surface as UnboundLocalError, masking the real cause.
        ca_extra_env = {}

        try:
            # Settings are loaded lazily and at most once: several branches
            # below need settings (CA default, challenge type, DNS provider,
            # key shape, propagation time) but a fully-specified HTTP-01 caller
            # needs none, so we keep the load conditional and reuse the result.
            settings = None

            # Return conflict if cert already exists (use renew to refresh it,
            # or replace=True to reissue with a changed domain set — #267).
            # This existence check runs *under* the per-domain lock acquired
            # above so two concurrent creates for the same domain can't both
            # pass the check and race to issue duplicate certificates.
            existing_cert = self.cert_dir / domain / 'cert.pem'
            if existing_cert.exists() and not replace:
                raise FileExistsError(f"Certificate for {domain} already exists. Use renew to refresh it.")

            logger.info(f"Starting certificate {'reissue' if replace else 'creation'} for domain: {domain}")
            
            # ... (Validation and CA setup remains the same until DNS config)
            
            # Validate inputs
            if not domain or not email:
                raise ValueError("Domain and email are required")
            
            # Get CA provider configuration
            if not ca_provider:
                if settings is None:
                    settings = self.settings_manager.load_settings()
                ca_provider = settings.get('default_ca', 'letsencrypt')

            # Back-compat (#279): the legacy per-cert staging boolean maps
            # onto the dedicated staging CA entry, and the boolean is derived
            # from the entry from here on. Keeping both views coherent means
            # the no-ca_manager fallback below (which only knows --staging)
            # and metadata stay correct whichever way the caller asked.
            if staging and ca_provider == 'letsencrypt':
                ca_provider = 'letsencrypt_staging'
            staging = staging or ca_provider == 'letsencrypt_staging'

            logger.info(f"Using CA provider: {ca_provider}")

            # Get CA account configuration if CA manager is available
            ca_account_config = None
            used_ca_account_id = None
            if self.ca_manager:
                try:
                    ca_account_config, used_ca_account_id = self.ca_manager.get_ca_config(ca_provider, ca_account_id)
                    logger.info(f"Using CA account: {used_ca_account_id}")
                except Exception as e:
                    if ca_provider in ('letsencrypt', 'letsencrypt_staging'):
                        # Let's Encrypt needs no per-account credentials; with
                        # no saved CA config the plain-certbot branch below
                        # handles it (staging via --staging). Do NOT reset the
                        # provider — that would silently flip a staging
                        # request to production issuance.
                        logger.info(f"No saved CA config for {ca_provider}; using certbot defaults: {e}")
                    else:
                        # Preserve the caller's staging intent across the
                        # fallback: resetting to production letsencrypt here
                        # would turn a test request into trusted production
                        # issuance (and burn real rate limits).
                        ca_provider = 'letsencrypt_staging' if staging else 'letsencrypt'
                        logger.warning(f"Could not get CA config, falling back to {ca_provider}: {e}")
            
            # Resolve challenge type from settings if not provided
            if not challenge_type:
                if settings is None:
                    settings = self.settings_manager.load_settings()
                challenge_type = settings.get('challenge_type', 'dns-01')

            # HTTP-01 path: skip DNS config entirely
            if challenge_type == 'http-01':
                strategy = HTTP01Strategy()
                dns_config = dns_config or {}
                dns_provider = dns_provider or 'http-01'
                # Ensure webroot directory exists (same path the serving route
                # reads — see acme_webroot_dir).
                challenge_dir = acme_webroot_dir() / '.well-known' / 'acme-challenge'
                challenge_dir.mkdir(parents=True, exist_ok=True)
                logger.info("Using HTTP-01 challenge (webroot)")
            else:
                # DNS-01 path: get DNS configuration
                if not dns_config:
                    if not dns_provider:
                        if settings is None:
                            settings = self.settings_manager.load_settings()
                        dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)

                    if not dns_provider:
                        raise ValueError("No DNS provider configured. Go to Settings and select a DNS provider.")

                    dns_config, used_account_id = self._get_dns_config(
                        dns_provider, account_id
                    )

                    if not dns_config:
                        raise ValueError(f"DNS provider '{dns_provider}' account '{account_id or 'default'}' not configured")

                    logger.info(f"Using DNS provider: {dns_provider} with account: {used_account_id}")

                # Get Strategy
                strategy = DNSStrategyFactory.get_strategy(dns_provider)

                if domain_alias and (alias_dns_provider or dns_provider) not in DNS_ALIAS_SUPPORTED_PROVIDERS:
                    raise RuntimeError(
                        "DNS alias mode does not support this DNS provider yet. "
                        "Use a supported account that controls the alias zone, "
                        "or omit domain_alias for the provider's normal DNS-01 flow."
                    )

                # Alias mode uses CertMate's manual DNS hook instead of the
                # provider certbot authenticator, so the plugin is only needed
                # for the normal non-alias DNS-01 flow. 'manual' is a certbot
                # core feature (custom-script provider), never an installable
                # plugin — skip the preflight for it.
                if not domain_alias and strategy.plugin_name != 'manual':
                    plugin = strategy.plugin_name
                    if not check_certbot_plugin_installed(plugin):
                        pkg = f"certbot-{plugin}"
                        raise RuntimeError(
                            f"The certbot plugin '{plugin}' is not installed. "
                            f"Install it with: pip install {pkg}  "
                            f"(Docker users: rebuild with REQUIREMENTS_FILE=requirements.txt)"
                        )

            # Build list of all domains (primary + SANs)
            all_domains = [domain]
            if san_domains:
                # Filter and validate SAN domains
                for san in san_domains:
                    san = san.strip()
                    if san and san != domain and san not in all_domains:
                        is_valid, validation_msg = validate_domain(san)
                        if not is_valid:
                            raise ValueError(f"Invalid SAN domain '{san}': {validation_msg}")
                        all_domains.append(san)
                logger.info(f"Creating SAN certificate with domains: {', '.join(all_domains)}")

            # HTTP-01 does not support wildcard domains
            if challenge_type == 'http-01':
                for d in all_domains:
                    if d.startswith('*.'):
                        raise ValueError("HTTP-01 challenge does not support wildcard domains. Use DNS-01 instead.")

            # Create output directory
            cert_dir = self.cert_dir
            cert_output_dir = cert_dir / domain
            cert_output_dir.mkdir(parents=True, exist_ok=True)

            # Resolve key shape. If the caller did not pick anything we fall
            # back to the global default from settings — this lets legacy
            # callers (web routes, scripts, tests) get the configured
            # default for free without having to fetch it themselves. If
            # the caller did pick something, validate the triple here too
            # so the cert is never built with an inconsistent shape (the
            # API endpoint validates earlier, but renew_certificate also
            # routes through this method and can pass values from disk).
            # On reissue (#267) the defaults are deliberately NOT applied:
            # metadata does not record the lineage's key shape, so forwarding
            # settings defaults as explicit flags would silently re-key the
            # certificate. With no key flags certbot keeps the existing key
            # type; an explicit key option on reissue is an intentional re-key.
            if not replace and key_type is None and key_size is None and elliptic_curve is None:
                if settings is None:
                    settings = self.settings_manager.load_settings()
                key_type = settings.get('default_key_type')
                if key_type == 'rsa':
                    key_size = settings.get('default_key_size')
                elif key_type == 'ecdsa':
                    elliptic_curve = settings.get('default_elliptic_curve')
            if key_type is not None:
                ok, err = validate_key_options(key_type, key_size, elliptic_curve)
                if not ok:
                    raise ValueError(f"Invalid key options for {domain}: {err}")

            # Build certbot command (ca_extra_env was hoisted above the try
            # so the finally block can clean up safely on early failure)
            san_list = all_domains[1:] if len(all_domains) > 1 else None
            if self.ca_manager and ca_account_config:
                try:
                    certbot_cmd, ca_extra_env = self.ca_manager.build_certbot_command(
                        domain, email, ca_provider, dns_provider, dns_config,
                        ca_account_config, staging, cert_dir, san_domains=san_list,
                        key_type=key_type, key_size=key_size, elliptic_curve=elliptic_curve,
                    )
                except TypeError as e:
                    # Defensive fallback: older build_certbot_command without san_domains
                    logger.warning(f"build_certbot_command does not accept san_domains, adding manually: {e}")
                    result = self.ca_manager.build_certbot_command(
                        domain, email, ca_provider, dns_provider, dns_config,
                        ca_account_config, staging, cert_dir
                    )
                    if isinstance(result, tuple):
                        certbot_cmd, ca_extra_env = result
                    else:
                        certbot_cmd = result
                    # Manually append SAN domains
                    if san_list:
                        for san in san_list:
                            certbot_cmd.extend(['-d', san])
                    # Fallback path also needs the key flags appended manually
                    # so a stale ca_manager doesn't silently downgrade certs.
                    if key_type == 'rsa' and key_size:
                        certbot_cmd.extend(['--key-type', 'rsa', '--rsa-key-size', str(key_size)])
                    elif key_type == 'ecdsa' and elliptic_curve:
                        certbot_cmd.extend(['--key-type', 'ecdsa', '--elliptic-curve', elliptic_curve])
            else:
                certbot_cmd = [
                    'certbot', 'certonly',
                    '--non-interactive',
                    '--agree-tos',
                    '--email', email,
                    '--cert-name', domain,
                    '--config-dir', str(cert_output_dir),
                    '--work-dir', str(cert_output_dir / 'work'),
                    '--logs-dir', str(cert_output_dir / 'logs'),
                ]

                # Add all domains
                for d in all_domains:
                    certbot_cmd.extend(['-d', d])

                if staging:
                    certbot_cmd.append('--staging')

                # No-ca_manager path: still honour the resolved key shape so
                # this branch produces the same cert as the main path.
                if key_type == 'rsa' and key_size:
                    certbot_cmd.extend(['--key-type', 'rsa', '--rsa-key-size', str(key_size)])
                elif key_type == 'ecdsa' and elliptic_curve:
                    certbot_cmd.extend(['--key-type', 'ecdsa', '--elliptic-curve', elliptic_curve])

            if replace:
                # Reissue over the existing lineage: a different -d set with
                # the same --cert-name replaces the lineage's domains (expand
                # and shrink). --renew-with-new-domains makes that
                # confirmation deterministic. --force-renewal is load-bearing
                # for the UNCHANGED-set case (config-only edits: CA switch,
                # provider change, alias clear, same-type re-key): without it
                # certbot hits _handle_identical_cert_request outside the
                # renewal window, takes the keep-existing default, and exits 0
                # WITHOUT issuing — and CertMate would then rewrite metadata
                # with configuration that was never applied. A reissue must
                # always issue.
                certbot_cmd.extend(['--renew-with-new-domains', '--force-renewal'])

            # Build per-request environment (avoid race conditions with os.environ)
            process_env = os.environ.copy()
            process_env.update(ca_extra_env)
            strategy.prepare_environment(process_env, dns_config)

            # Set propagation time (DNS-01 only; HTTP-01 has no propagation)
            propagation_time = None
            if challenge_type != 'http-01':
                try:
                    if settings is None:
                        settings = self.settings_manager.load_settings()
                    propagation_map = settings.get('dns_propagation_seconds', {}) or {}
                except Exception as e:
                    logger.debug("Failed to load settings in issue_certificate for propagation time: %s", e)
                    propagation_map = {}

                # Default to strategy default if not in settings map
                default_seconds = strategy.default_propagation_seconds
                try:
                    propagation_time = int(propagation_map.get(dns_provider, default_seconds))
                except (ValueError, TypeError):
                    propagation_time = default_seconds
                # Ensure propagation time is within reasonable bounds (1 second to 1 hour)
                propagation_time = max(1, min(3600, propagation_time))

                # --manual has no propagation flag: surface the configured
                # per-provider value to custom-script hooks via env instead.
                # An account-level propagation_seconds (exported earlier by
                # prepare_environment) wins over the global setting.
                if dns_provider == 'custom-script':
                    process_env.setdefault('CERTMATE_DNS_PROPAGATION_SECONDS', str(propagation_time))

            alias_hook_provider = alias_dns_provider or dns_provider
            use_dns_alias_hook = (
                challenge_type != 'http-01'
                and domain_alias
                and alias_hook_provider in DNS_ALIAS_SUPPORTED_PROVIDERS
            )

            if use_dns_alias_hook:
                # The TXT records land on the ALIAS zone, so the hook must run
                # with the account that controls that zone — which renewals
                # already honour via metadata alias_dns_provider (issue #129).
                alias_hook_config = dns_config
                if alias_hook_provider != dns_provider:
                    alias_hook_config, _ = self._get_dns_config(alias_hook_provider, account_id)
                    if not alias_hook_config:
                        raise ValueError(
                            f"Alias DNS provider '{alias_hook_provider}' is not configured"
                        )
                logger.info(
                    f"DNS alias '{domain_alias}' requested for {domain}; "
                    f"using {alias_hook_provider} manual hook to create TXT records on the alias zone."
                )
                credentials_file = self._create_dns_alias_hook_config(
                    alias_hook_provider, alias_hook_config, domain_alias, propagation_time or strategy.default_propagation_seconds
                )
                self._configure_dns_alias_arguments(certbot_cmd, credentials_file)
            else:
                # Create Config File. Pass the SAN list so the discovery
                # path (Azure today) can resolve every cert FQDN against
                # the account's hosted zones in one pass.
                strategy_config = self._dns_config_for_strategy(
                    dns_provider, dns_config, domain,
                    san_domains=all_domains[1:] if len(all_domains) > 1 else None,
                )
                credentials_file = strategy.create_config_file(strategy_config)

                # Configure Args
                strategy.configure_certbot_arguments(certbot_cmd, credentials_file, domain_alias=domain_alias)

                # Some plugins (e.g. certbot-dns-route53 >= 1.22) do not accept a
                # --{plugin}-propagation-seconds flag and handle propagation internally.
                if challenge_type != 'http-01' and strategy.supports_propagation_seconds_flag:
                    certbot_cmd.extend([f'--{strategy.plugin_name}-propagation-seconds', str(propagation_time)])

            logger.info(f"Running certbot command for {domain} with {dns_provider}")
            # Redact sensitive arguments before logging
            _redact = {'--eab-kid', '--eab-hmac-key', '--email'}
            safe_cmd = []
            skip_next = False
            for part in certbot_cmd:
                if skip_next:
                    safe_cmd.append('***')
                    skip_next = False
                elif str(part) in _redact:
                    safe_cmd.append(str(part))
                    skip_next = True
                else:
                    safe_cmd.append(str(part))
            logger.debug(f"Certbot command: {' '.join(safe_cmd)}")

            # Run certbot with isolated environment
            result = self.shell_executor.run(
                certbot_cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minute timeout
                env=process_env
            )

            if result.returncode != 0:
                # Log the FULL stderr internally for operator debugging.
                # certbot-dns-azure and a few other plugins echo the
                # offending credentials .ini line on parse failure, so
                # the raw stderr carries secret material. Sanitise
                # before bubbling up into the exception that becomes
                # the API response body. Internal audit finding H3.
                logger.error(f"Certbot failed for {domain}: {result.stderr}")
                from .utils import sanitize_certbot_stderr
                safe_stderr = sanitize_certbot_stderr(result.stderr)
                raise RuntimeError(f"Certificate creation failed: {safe_stderr}")
            
            # Move certificates to standard location
            live_dir = cert_output_dir / 'live' / domain
            cert_files = {}
            
            if live_dir.exists():
                for cert_file in CERTIFICATE_FILES:
                    src_file = live_dir / cert_file
                    dst_file = cert_output_dir / cert_file
                    if src_file.exists():
                        # Single content read: copy bytes once and reuse them
                        # for cert_files instead of re-opening the destination.
                        src_real = os.path.realpath(src_file)
                        data = Path(src_real).read_bytes()
                        dst_file.write_bytes(data)
                        # Preserve the source mode bits. shutil.copy did this
                        # implicitly; without it privkey.pem (often 0600) would
                        # be created under the umask (e.g. 0644), exposing the
                        # private key — a security regression.
                        shutil.copymode(src_real, dst_file)
                        logger.info(f"Copied {cert_file} to {dst_file}")
                        cert_files[cert_file] = data
            
            # Save metadata. 'staging' is kept alongside the new
            # 'ca_provider' key for backward compatibility: external storage
            # backends (Azure KV tags) and pre-#279 readers still understand
            # it, and it is now always derivable from the provider.
            metadata = {
                'domain': domain,
                'san_domains': all_domains[1:] if len(all_domains) > 1 else [],
                'dns_provider': dns_provider,
                'challenge_type': challenge_type,
                'created_at': utc_now_iso(),
                'email': email,
                'staging': staging,
                'account_id': account_id,
                'ca_provider': ca_provider,
                'ca_account_id': used_ca_account_id
            }
            if domain_alias:
                metadata['domain_alias'] = domain_alias
                metadata['alias_dns_provider'] = alias_dns_provider or dns_provider
            
            if self.storage_manager:
                try:
                    storage_success = self.storage_manager.store_certificate(domain, cert_files, metadata)
                    if storage_success:
                        logger.info(f"Certificate stored in {self.storage_manager.get_backend_name()} backend for {domain}")
                    else:
                        logger.warning(f"Failed to store certificate in {self.storage_manager.get_backend_name()} backend for {domain}")
                except Exception as e:
                    logger.error(f"Error storing certificate in storage backend for {domain}: {e}")
            
            if self._save_metadata(domain, metadata):
                logger.info(f"Saved certificate metadata to {self._metadata_path(domain)}")
            
            duration = time.time() - start_time
            logger.info(f"Certificate created successfully for {domain} in {duration:.2f} seconds")
            self._invalidate_certificate_info_cache(domain)
            self._write_pfx(domain)

            return {
                'success': True,
                'domain': domain,
                'dns_provider': dns_provider,
                'duration': duration,
                'staging': staging,
                'ca_provider': ca_provider
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Certificate creation timeout for {domain}")
            raise RuntimeError("Certificate creation timed out")
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Certificate creation failed for {domain}: {str(e)} (duration: {duration:.2f}s)")
            raise
        finally:
            domain_lock.release()
            # Always clean up credential files (even on failure)
            if credentials_file:
                try:
                    os.unlink(credentials_file)
                except (FileNotFoundError, OSError):
                    pass
            # Clean up CA bundle temp file if created
            ca_bundle = ca_extra_env.get('REQUESTS_CA_BUNDLE')
            if ca_bundle:
                try:
                    os.unlink(ca_bundle)
                except (FileNotFoundError, OSError):
                    pass

    def renew_certificate(self, domain, force=False):
        """Renew a certificate"""
        domain_lock = self._get_domain_lock(domain)
        if not domain_lock.acquire(timeout=self._domain_lock_timeout()):
            raise DomainOperationInProgress(domain)
        alias_hook_config = None
        credentials_file = None
        try:
            # Use the same config/work/log directories as during creation
            cert_dir = self.cert_dir
            domain_dir = cert_dir / domain
            if not domain_dir.exists() or not (domain_dir / 'cert.pem').exists():
                raise FileNotFoundError(f"No certificate found for domain: {domain}")
            work_dir = domain_dir / 'work'
            logs_dir = domain_dir / 'logs'

            metadata_file = domain_dir / 'metadata.json'
            metadata = {}
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to read metadata for renewal of {domain}: {e}")
            
            cmd = [
                'certbot', 'renew',
                '--cert-name', domain,
                '--quiet',
                # certbot's default `renew` injects a random sleep of up
                # to ~8 minutes before contacting the ACME server, to
                # avoid stampeding Let's Encrypt when run from a flock
                # of crontabs. We're always invoked interactively from
                # the API/UI, so the sleep just makes the POST time out
                # in the browser — and the random delay is reported as
                # a NETWORK_ERROR to the user even though certbot
                # eventually completes the renewal in the background.
                # See issue #171.
                '--no-random-sleep-on-renew',
                '--config-dir', str(domain_dir),
                '--work-dir', str(work_dir),
                '--logs-dir', str(logs_dir)
            ]
            if force:
                cmd.append('--force-renewal')

            # Build per-request environment with DNS provider credentials
            # (fix #112: env vars like AWS_ACCESS_KEY_ID were missing during
            # renewal, causing Route53 and other env-var-based providers to
            # fail with "Unable to locate credentials").
            process_env = os.environ.copy()

            dns_provider = metadata.get('dns_provider')
            challenge_type = metadata.get('challenge_type', 'dns-01')

            domain_alias = metadata.get('domain_alias')
            if domain_alias:
                alias_provider = metadata.get('alias_dns_provider') or dns_provider
                if not alias_provider:
                    raise RuntimeError(f"Cannot renew {domain}: metadata is missing alias DNS provider")

                settings = self.settings_manager.load_settings()
                dns_config, _ = self.dns_manager.get_dns_provider_account_config(
                    alias_provider,
                    metadata.get('account_id'),
                    settings,
                )
                if not dns_config:
                    raise RuntimeError(
                        f"Cannot renew {domain}: DNS alias provider account for {alias_provider} is not configured"
                    )

                strategy = DNSStrategyFactory.get_strategy(alias_provider)
                # Inject provider env vars (e.g. AWS credentials) for alias renewals too
                strategy.prepare_environment(process_env, dns_config)

                propagation_map = settings.get('dns_propagation_seconds', {}) or {}
                try:
                    propagation_time = int(propagation_map.get(alias_provider, strategy.default_propagation_seconds))
                except (ValueError, TypeError):
                    propagation_time = strategy.default_propagation_seconds
                propagation_time = max(1, min(3600, propagation_time))

                alias_hook_config = self._create_dns_alias_hook_config(
                    alias_provider,
                    dns_config,
                    domain_alias,
                    propagation_time,
                )
                self._configure_dns_alias_arguments(cmd, alias_hook_config)
                logger.info(
                    f"Renewing {domain} with DNS alias '{domain_alias}' "
                    f"using {alias_provider} manual hook."
                )
            elif dns_provider and challenge_type != 'http-01':
                # Standard DNS-01 renewal: load DNS config and prepare env vars
                settings = self.settings_manager.load_settings()
                dns_config, _ = self.dns_manager.get_dns_provider_account_config(
                    dns_provider,
                    metadata.get('account_id'),
                    settings,
                )
                if dns_config:
                    strategy = DNSStrategyFactory.get_strategy(dns_provider)
                    strategy.prepare_environment(process_env, dns_config)
                    # Create credentials file for providers that need one.
                    # Pull SANs from metadata so the discovery hook sees
                    # the same FQDN set the cert was originally issued with;
                    # otherwise a wildcard SAN under a parent zone would
                    # be invisible at renew time.
                    renew_sans = metadata.get('san_domains') or None
                    strategy_config = self._dns_config_for_strategy(
                        dns_provider, dns_config, domain, san_domains=renew_sans,
                    )
                    credentials_file = strategy.create_config_file(strategy_config)
                    if dns_provider == 'custom-script':
                        # Mirror the create path: expose the propagation
                        # setting to the hooks certbot replays at renewal.
                        propagation_map = settings.get('dns_propagation_seconds', {}) or {}
                        try:
                            renew_propagation = int(propagation_map.get(dns_provider, strategy.default_propagation_seconds))
                        except (ValueError, TypeError):
                            renew_propagation = strategy.default_propagation_seconds
                        process_env.setdefault(
                            'CERTMATE_DNS_PROPAGATION_SECONDS',
                            str(max(1, min(3600, renew_propagation))))
                    logger.info(f"Prepared DNS environment for renewal of {domain} with {dns_provider}")
                else:
                    logger.warning(
                        f"DNS config for provider '{dns_provider}' not found during "
                        f"renewal of {domain}; certbot may fail if credentials are required"
                    )

            result = self.shell_executor.run(cmd, capture_output=True, text=True, env=process_env)
            
            if result.returncode == 0:
                # Copy renewed certificates from the correct live directory
                src_dir = domain_dir / 'live' / domain
                dest_dir = domain_dir
                
                cert_files = {}
                for file_name in CERTIFICATE_FILES:
                    src_file = src_dir / file_name
                    dest_file = dest_dir / file_name
                    if src_file.exists():
                        self._atomic_binary_copy(src_file, dest_file)
                        with open(dest_file, 'rb') as f:
                            cert_files[file_name] = f.read()
                
                if self.storage_manager:
                    try:
                        storage_success = self.storage_manager.store_certificate(domain, cert_files, metadata)
                        if storage_success:
                            logger.info(f"Certificate stored in {self.storage_manager.get_backend_name()} backend for {domain}")
                        else:
                            logger.warning(f"Failed to store certificate in {self.storage_manager.get_backend_name()} backend for {domain}")
                    except Exception as e:
                        logger.error(f"Error storing certificate in storage backend for {domain}: {e}")

                # Update metadata with renewal timestamp
                if metadata_file.exists():
                    try:
                        metadata['renewed_at'] = utc_now_iso()
                        self._save_metadata(domain, metadata)
                        logger.info(f"Updated renewal timestamp in metadata for {domain}")
                    except Exception as e:
                        logger.warning(f"Failed to update metadata for {domain}: {e}")
                
                logger.info(f"Certificate renewed successfully for {domain}")
                self._invalidate_certificate_info_cache(domain)
                self._write_pfx(domain)
                return {
                    'success': True,
                    'domain': domain,
                    'message': "Certificate renewed successfully"
                }
            else:
                # Mirror the create-path sanitisation: log raw stderr,
                # surface a redacted copy. See sanitize_certbot_stderr
                # docstring for the precise stripping rules.
                error_msg = result.stderr or "Certificate not found"
                logger.error(f"Certificate renewal failed for {domain}: {error_msg}")
                from .utils import sanitize_certbot_stderr
                safe_error = sanitize_certbot_stderr(error_msg) if result.stderr else error_msg
                raise RuntimeError(f"Renewal failed: {safe_error}")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Exception during certificate renewal for {domain}: {error_msg}")
            raise RuntimeError(f"Exception: {error_msg}")
        finally:
            if alias_hook_config:
                try:
                    os.unlink(alias_hook_config)
                except (FileNotFoundError, OSError):
                    pass
            if credentials_file:
                try:
                    os.unlink(credentials_file)
                except (FileNotFoundError, OSError):
                    pass
            domain_lock.release()

    def check_renewals(self):
        """Check and renew certificates that are about to expire"""
        settings = self.settings_manager.load_settings()
            
        if not settings.get('auto_renew', True):
            return
        
        # Migrate settings format if needed
        settings = self.settings_manager.migrate_domains_format(settings)
        
        logger.info("Checking for certificates that need renewal")
        
        for domain_entry in settings.get('domains', []):
            try:
                # Handle both old and new domain formats
                if isinstance(domain_entry, str):
                    domain = domain_entry
                    per_cert_auto_renew = True
                elif isinstance(domain_entry, dict):
                    domain = domain_entry.get('domain')
                    per_cert_auto_renew = domain_entry.get('auto_renew', True)
                else:
                    logger.warning(f"Invalid domain entry format: {domain_entry}")
                    continue

                if not domain:
                    continue

                # Per-certificate opt-out: skip when auto_renew is explicitly
                # disabled on this domain entry. The global auto_renew flag is
                # checked above; this is the per-cert override (issue #111).
                if not per_cert_auto_renew:
                    logger.info(f"Skipping renewal for {domain}: auto_renew disabled for this certificate")
                    continue

                # Pass the once-loaded settings into get_certificate_info so
                # the per-domain disk reload (which the request-scoped cache
                # cannot help with — this is a background job, no flask.g)
                # is avoided. For a 1000-domain renewal job that's 1000
                # redundant settings.json reads collapsed to one.
                # use_cache=False: this loop visits each domain exactly once
                # per run, so populating _certificate_info_cache would only
                # add a deepcopy-on-set with no possible read hit.
                cert_info = self.get_certificate_info(domain, settings=settings, use_cache=False)

                if cert_info and cert_info.get('needs_renewal'):
                    logger.info(f"Renewing certificate for {domain}")
                    try:
                        self.renew_certificate(domain)
                        logger.info(f"Successfully renewed certificate for {domain}")
                    except Exception as e:
                        logger.error(f"Failed to renew certificate for {domain}: {e}")
                        
            except Exception as e:
                logger.error(f"Error checking renewal for domain entry {domain_entry}: {e}")

    def create_certificate_legacy(self, domain, email, cloudflare_token):
        """Legacy function for backward compatibility"""
        dns_config = {'api_token': cloudflare_token}
        # Fallback to direct method call
        return self.create_certificate(domain, email, 'cloudflare', dns_config)
    


    def _get_dns_config(self, dns_provider, account_id):
        """Get DNS provider account config"""
        return self.dns_manager.get_dns_provider_account_config(dns_provider, account_id)

    def create_missing_metadata(self):
        """Create metadata files for existing certificates that don't have them"""
        cert_dir = self.cert_dir
        settings = self.settings_manager.load_settings()
        
        created_count = 0
        
        for domain_dir in cert_dir.iterdir():
            if not domain_dir.is_dir():
                continue
                
            domain = domain_dir.name
            metadata_file = domain_dir / 'metadata.json'
            
            if metadata_file.exists():
                continue  # Skip if metadata already exists
                
            cert_file = domain_dir / 'cert.pem'
            if not cert_file.exists():
                continue  # Skip if no certificate exists
            
            # Infer DNS provider based on domain patterns and current settings
            dns_provider = self._infer_dns_provider(domain, settings)

            # The issuer CN is inspectable on disk, so staging does not have
            # to be assumed: Let's Encrypt staging issuers carry "(STAGING)"
            # (current) or "Fake LE" (historical) markers.
            staging = False
            try:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
                issuer = cert.issuer.rfc4514_string().lower()
                staging = 'staging' in issuer or 'fake le' in issuer
            except Exception as e:
                logger.debug(f"Could not inspect issuer for {domain}, assuming production: {e}")

            metadata = {
                'domain': domain,
                'dns_provider': dns_provider,
                'created_at': 'unknown',  # We don't know the exact creation time
                'email': settings.get('email', 'unknown'),
                'staging': staging,
                'ca_provider': 'letsencrypt_staging' if staging else None,
                'account_id': None,
                'inferred': True  # Mark as inferred for debugging
            }
            
            if self._save_metadata(domain, metadata):
                logger.info(f"Created metadata for {domain} with inferred DNS provider: {dns_provider}")
                created_count += 1
            else:
                logger.error(f"Failed to create metadata for {domain}")
        
        logger.info(f"Created metadata files for {created_count} certificates")
        return created_count
    
    def set_auto_renew(self, domain: str, enabled: bool) -> bool:
        """Enable or disable automatic renewal for a single domain (issue #111).

        Returns True if the domain was found in settings and updated, False
        otherwise. Legacy string-form entries are upgraded to dict form so the
        flag can be persisted.
        """
        settings = self.settings_manager.load_settings()
        # Migrate so every entry is a dict and the flag has somewhere to live.
        settings = self.settings_manager.migrate_domains_format(settings)

        new_domains = []
        found = False
        for entry in settings.get('domains', []):
            if isinstance(entry, dict) and entry.get('domain') == domain:
                entry = {**entry, 'auto_renew': bool(enabled)}
                found = True
            new_domains.append(entry)

        if not found:
            return False

        # atomic_update merges under a lock, avoiding a load/mutate/save race
        # with concurrent settings writes.
        self.settings_manager.atomic_update({'domains': new_domains})
        logger.info(f"auto_renew set to {bool(enabled)} for {domain}")
        return True

    def delete_certificate(self, domain: str) -> bool:
        """Delete a certificate directory, blocking if a create/renew is in progress."""
        domain_lock = self._get_domain_lock(domain)
        # Acquire lock to ensure no create/renew is in progress (non-blocking)
        if not domain_lock.acquire(blocking=False):
            raise RuntimeError(f"Cannot delete certificate for {domain}: an operation is currently in progress")
        try:
            import shutil
            domain_dir = self.cert_dir / domain
            if domain_dir.exists():
                shutil.rmtree(domain_dir)
                logger.info(f"Certificate deleted for {domain}")
                self._invalidate_certificate_info_cache(domain)
                return True
            return False
        finally:
            domain_lock.release()

    def _infer_dns_provider(self, domain, settings):
        """Infer the DNS provider for a domain, preferring its explicit
        per-domain setting over the global default."""
        provider = self.settings_manager.get_domain_dns_provider(domain, settings)
        return provider or settings.get('dns_provider') or 'cloudflare'
