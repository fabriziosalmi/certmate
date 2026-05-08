"""
Certificate operations module for CertMate
Handles certificate creation, renewal, and information retrieval
"""

import os
import json
import shlex
import subprocess
import sys
import tempfile
import time
import logging
import shutil
import threading
from pathlib import Path
from datetime import datetime, timedelta
from .shell import ShellExecutor
from .dns_strategies import DNSStrategyFactory, HTTP01Strategy, check_certbot_plugin_installed
from .constants import CERTIFICATE_FILES, get_domain_name
from .utils import validate_domain, utc_now

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


class CertificateManager:
    """Class to handle certificate operations"""
    
    def __init__(self, cert_dir, settings_manager, dns_manager, storage_manager=None, ca_manager=None, shell_executor=None):
        self.cert_dir = Path(cert_dir)
        self.settings_manager = settings_manager
        self.dns_manager = dns_manager
        self.storage_manager = storage_manager
        self.ca_manager = ca_manager
        self.shell_executor = shell_executor or ShellExecutor()
        # Per-domain locks to prevent concurrent create/renew on the same domain
        self._domain_locks: dict[str, threading.Lock] = {}
        self._domain_locks_mutex = threading.Lock()

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

        fd, path = tempfile.mkstemp(prefix='certmate-dns-alias-', suffix='.json')
        config_path = Path(path)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump({
                    'provider': dns_provider,
                    'domain_alias': domain_alias.strip().rstrip('.'),
                    'propagation_seconds': int(propagation_seconds),
                    'config': dns_config,
                }, f)
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





    def get_certificate_info(self, domain):
        """Get certificate information for a domain"""
        if not domain:
            return None
        
        # First try to get certificate from storage backend if available
        if self.storage_manager:
            try:
                storage_result = self.storage_manager.retrieve_certificate(domain)
                if storage_result:
                    cert_files, metadata = storage_result
                    if 'cert.pem' in cert_files:
                        return self._parse_certificate_info(domain, cert_files['cert.pem'], metadata)
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
        
        # Get DNS provider info from metadata file first, then fall back to settings
        dns_provider = None
        metadata_file = cert_path / "metadata.json"
        metadata = {}
        
        if metadata_file.exists():
            try:
                import json
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    dns_provider = metadata.get('dns_provider')
                    logger.debug(f"Found DNS provider '{dns_provider}' in metadata for {domain}")
            except Exception as e:
                logger.warning(f"Failed to read metadata for {domain}: {e}")
        
        if not dns_provider:
            # Fall back to current settings
            settings = self.settings_manager.load_settings()
            dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)
            logger.debug(f"Using DNS provider '{dns_provider}' from settings for {domain}")
        
        # Read certificate file and parse info
        try:
            with open(cert_file, 'rb') as f:
                cert_content = f.read()
            return self._parse_certificate_info(domain, cert_content, metadata)
        except Exception as e:
            logger.error(f"Failed to read certificate file for {domain}: {e}")
            return self._create_empty_cert_info(domain)
    
    @staticmethod
    def _parse_openssl_date(date_str):
        """Parse openssl date string, trying multiple formats for cross-platform compatibility."""
        formats = [
            '%b %d %H:%M:%S %Y %Z',   # Most common: "Jan  1 00:00:00 2026 GMT"
            '%b  %d %H:%M:%S %Y %Z',  # Double-space variant for single-digit days
            '%b %d %H:%M:%S %Y',       # Without timezone
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        raise ValueError(f"Unable to parse certificate date: {date_str!r}")

    def _parse_certificate_info(self, domain, cert_content, metadata=None):
        """Parse certificate information from certificate content"""
        if metadata is None:
            metadata = {}

        dns_provider = metadata.get('dns_provider')
        settings = self.settings_manager.load_settings()
        if not dns_provider:
            # Fall back to current settings
            dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)

        # Get configurable renewal threshold (default 30 days for backward compatibility)
        renewal_threshold_days = settings.get('renewal_threshold_days', 30)

        try:
            # Write cert content to temporary file for openssl processing
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as temp_cert:
                temp_cert.write(cert_content)
                temp_cert_path = temp_cert.name

            try:
                # Get certificate expiry using openssl — prefer -enddate for simpler parsing
                result = self.shell_executor.run([
                    'openssl', 'x509', '-in', temp_cert_path, '-noout', '-enddate'
                ], capture_output=True, text=True)

                not_after = None
                if result.returncode == 0:
                    output = result.stdout.strip()
                    # Output format: "notAfter=Jan  1 00:00:00 2026 GMT"
                    if '=' in output:
                        not_after = output.split('=', 1)[1]

                if not_after:
                    try:
                        expiry_date = self._parse_openssl_date(not_after)
                        now_utc = utc_now()
                        days_left = (expiry_date - now_utc).days

                        return {
                            'domain': domain,
                            'exists': True,
                            'expiry_date': expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                            'days_left': days_left,
                            'days_until_expiry': days_left,
                            'needs_renewal': days_left < renewal_threshold_days,
                            'dns_provider': dns_provider
                        }
                    except ValueError as e:
                        logger.error(f"Error parsing certificate date for {domain}: {e}")
                else:
                    logger.error(f"openssl returned no expiry for {domain}: rc={result.returncode} stderr={result.stderr}")
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_cert_path)
                except FileNotFoundError:
                    pass
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean up temp cert file {temp_cert_path}: {cleanup_err}")

        except Exception as e:
            logger.error(f"Error getting certificate info for {domain}: {e}")

        # Certificate file exists but we couldn't parse the expiry — still mark exists=True
        return {
            'domain': domain,
            'exists': True,
            'expiry_date': None,
            'days_left': None,
            'days_until_expiry': None,
            'needs_renewal': True,
            'dns_provider': dns_provider
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

    def create_certificate(self, domain, email, dns_provider=None, dns_config=None, account_id=None, staging=False, ca_provider=None, ca_account_id=None, domain_alias=None, san_domains=None, challenge_type=None):
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
            san_domains: Optional list of additional domains for Subject Alternative Names (SAN)
        """
        # Acquire per-domain lock to prevent concurrent create/renew operations
        domain_lock = self._get_domain_lock(domain)
        if not domain_lock.acquire(blocking=False):
            raise RuntimeError(f"A certificate operation for {domain} is already in progress")

        # Track timing for metrics
        start_time = time.time()
        credentials_file = None
        # Initialized early: the finally block reads ca_extra_env to clean up
        # the REQUESTS_CA_BUNDLE temp file, and an exception raised before the
        # ca_manager.build_certbot_command call (e.g. plugin-not-installed)
        # would otherwise surface as UnboundLocalError, masking the real cause.
        ca_extra_env = {}

        try:
            # Return conflict if cert already exists (use renew to refresh it)
            existing_cert = self.cert_dir / domain / 'cert.pem'
            if existing_cert.exists():
                raise FileExistsError(f"Certificate for {domain} already exists. Use renew to refresh it.")

            logger.info(f"Starting certificate creation for domain: {domain}")
            
            # ... (Validation and CA setup remains the same until DNS config)
            
            # Validate inputs
            if not domain or not email:
                raise ValueError("Domain and email are required")
            
            # Get CA provider configuration
            if not ca_provider:
                settings = self.settings_manager.load_settings()
                ca_provider = settings.get('default_ca', 'letsencrypt')
            
            logger.info(f"Using CA provider: {ca_provider}")
            
            # Get CA account configuration if CA manager is available
            ca_account_config = None
            if self.ca_manager:
                try:
                    ca_account_config, used_ca_account_id = self.ca_manager.get_ca_config(ca_provider, ca_account_id)
                    logger.info(f"Using CA account: {used_ca_account_id}")
                except Exception as e:
                    logger.warning(f"Could not get CA config, using default Let's Encrypt: {e}")
                    ca_provider = 'letsencrypt'
            
            # Resolve challenge type from settings if not provided
            if not challenge_type:
                settings = self.settings_manager.load_settings()
                challenge_type = settings.get('challenge_type', 'dns-01')

            # HTTP-01 path: skip DNS config entirely
            if challenge_type == 'http-01':
                strategy = HTTP01Strategy()
                dns_config = dns_config or {}
                dns_provider = dns_provider or 'http-01'
                # Ensure webroot directory exists
                webroot = Path(HTTP01Strategy.WEBROOT_DIR)
                challenge_dir = webroot / '.well-known' / 'acme-challenge'
                challenge_dir.mkdir(parents=True, exist_ok=True)
                logger.info("Using HTTP-01 challenge (webroot)")
            else:
                # DNS-01 path: get DNS configuration
                if not dns_config:
                    if not dns_provider:
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

                if domain_alias and dns_provider not in DNS_ALIAS_SUPPORTED_PROVIDERS:
                    raise RuntimeError(
                        "DNS alias mode does not support this DNS provider yet. "
                        "Use a supported account that controls the alias zone, "
                        "or omit domain_alias for the provider's normal DNS-01 flow."
                    )

                # Alias mode uses CertMate's manual DNS hook instead of the
                # provider certbot authenticator, so the plugin is only needed
                # for the normal non-alias DNS-01 flow.
                if not domain_alias:
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

            # Build certbot command (ca_extra_env was hoisted above the try
            # so the finally block can clean up safely on early failure)
            san_list = all_domains[1:] if len(all_domains) > 1 else None
            if self.ca_manager and ca_account_config:
                try:
                    certbot_cmd, ca_extra_env = self.ca_manager.build_certbot_command(
                        domain, email, ca_provider, dns_provider, dns_config,
                        ca_account_config, staging, cert_dir, san_domains=san_list
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

            # Build per-request environment (avoid race conditions with os.environ)
            process_env = os.environ.copy()
            process_env.update(ca_extra_env)
            strategy.prepare_environment(process_env, dns_config)

            # Set propagation time (DNS-01 only; HTTP-01 has no propagation)
            propagation_time = None
            if challenge_type != 'http-01':
                try:
                    settings = self.settings_manager.load_settings()
                    propagation_map = settings.get('dns_propagation_seconds', {}) or {}
                except Exception:
                    propagation_map = {}

                # Default to strategy default if not in settings map
                default_seconds = strategy.default_propagation_seconds
                try:
                    propagation_time = int(propagation_map.get(dns_provider, default_seconds))
                except (ValueError, TypeError):
                    propagation_time = default_seconds
                # Ensure propagation time is within reasonable bounds (1 second to 1 hour)
                propagation_time = max(1, min(3600, propagation_time))

            use_dns_alias_hook = (
                challenge_type != 'http-01'
                and domain_alias
                and dns_provider in DNS_ALIAS_SUPPORTED_PROVIDERS
            )

            if use_dns_alias_hook:
                logger.info(
                    f"DNS alias '{domain_alias}' requested for {domain}; "
                    f"using {dns_provider} manual hook to create TXT records on the alias zone."
                )
                credentials_file = self._create_dns_alias_hook_config(
                    dns_provider, dns_config, domain_alias, propagation_time or strategy.default_propagation_seconds
                )
                self._configure_dns_alias_arguments(certbot_cmd, credentials_file)
            else:
                # Create Config File
                credentials_file = strategy.create_config_file(dns_config)

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
                logger.error(f"Certbot failed for {domain}: {result.stderr}")
                raise RuntimeError(f"Certificate creation failed: {result.stderr}")
            
            # Move certificates to standard location
            live_dir = cert_output_dir / 'live' / domain
            cert_files = {}
            
            if live_dir.exists():
                for cert_file in CERTIFICATE_FILES:
                    src_file = live_dir / cert_file
                    dst_file = cert_output_dir / cert_file
                    if src_file.exists():
                        shutil.copy(os.path.realpath(src_file), dst_file)
                        logger.info(f"Copied {cert_file} to {dst_file}")
                        with open(dst_file, 'rb') as f:
                            cert_files[cert_file] = f.read()
            
            # Save metadata
            metadata = {
                'domain': domain,
                'san_domains': all_domains[1:] if len(all_domains) > 1 else [],
                'dns_provider': dns_provider,
                'challenge_type': challenge_type,
                'created_at': datetime.now().isoformat(),
                'email': email,
                'staging': staging,
                'account_id': account_id
            }
            if domain_alias:
                metadata['domain_alias'] = domain_alias
                metadata['alias_dns_provider'] = dns_provider
            
            if self.storage_manager:
                try:
                    storage_success = self.storage_manager.store_certificate(domain, cert_files, metadata)
                    if storage_success:
                        logger.info(f"Certificate stored in {self.storage_manager.get_backend_name()} backend for {domain}")
                    else:
                        logger.warning(f"Failed to store certificate in {self.storage_manager.get_backend_name()} backend for {domain}")
                except Exception as e:
                    logger.error(f"Error storing certificate in storage backend for {domain}: {e}")
            
            metadata_file = cert_output_dir / 'metadata.json'
            try:
                self._atomic_json_write(metadata_file, metadata)
                logger.info(f"Saved certificate metadata to {metadata_file}")
            except Exception as e:
                logger.warning(f"Failed to save metadata for {domain}: {e}")
            
            duration = time.time() - start_time
            logger.info(f"Certificate created successfully for {domain} in {duration:.2f} seconds")
            
            return {
                'success': True,
                'domain': domain,
                'dns_provider': dns_provider,
                'duration': duration,
                'staging': staging
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

    def renew_certificate(self, domain):
        """Renew a certificate"""
        domain_lock = self._get_domain_lock(domain)
        if not domain_lock.acquire(blocking=False):
            raise RuntimeError(f"A certificate operation for {domain} is already in progress")
        try:
            # Use the same config/work/log directories as during creation
            cert_dir = self.cert_dir
            domain_dir = cert_dir / domain
            if not domain_dir.exists() or not (domain_dir / 'cert.pem').exists():
                raise FileNotFoundError(f"No certificate found for domain: {domain}")
            work_dir = domain_dir / 'work'
            logs_dir = domain_dir / 'logs'
            
            cmd = [
                'certbot', 'renew',
                '--cert-name', domain,
                '--quiet',
                '--config-dir', str(domain_dir),
                '--work-dir', str(work_dir),
                '--logs-dir', str(logs_dir)
            ]
            result = self.shell_executor.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Copy renewed certificates from the correct live directory
                src_dir = domain_dir / 'live' / domain
                dest_dir = domain_dir
                
                for file_name in CERTIFICATE_FILES:
                    src_file = src_dir / file_name
                    dest_file = dest_dir / file_name
                    if src_file.exists():
                        self._atomic_binary_copy(src_file, dest_file)
                
                # Update metadata with renewal timestamp
                metadata_file = dest_dir / 'metadata.json'
                if metadata_file.exists():
                    try:
                        import json
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        metadata['renewed_at'] = datetime.now().isoformat()
                        self._atomic_json_write(metadata_file, metadata)
                        logger.info(f"Updated renewal timestamp in metadata for {domain}")
                    except Exception as e:
                        logger.warning(f"Failed to update metadata for {domain}: {e}")
                
                logger.info(f"Certificate renewed successfully for {domain}")
                return {
                    'success': True,
                    'domain': domain,
                    'message': "Certificate renewed successfully"
                }
            else:
                error_msg = result.stderr or "Certificate not found"
                logger.error(f"Certificate renewal failed for {domain}: {error_msg}")
                raise RuntimeError(f"Renewal failed: {error_msg}")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Exception during certificate renewal for {domain}: {error_msg}")
            raise RuntimeError(f"Exception: {error_msg}")
        finally:
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

                cert_info = self.get_certificate_info(domain)

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
            
            metadata = {
                'domain': domain,
                'dns_provider': dns_provider,
                'created_at': 'unknown',  # We don't know the exact creation time
                'email': settings.get('email', 'unknown'),
                'staging': False,  # Assume production certificates
                'account_id': None,
                'inferred': True  # Mark as inferred for debugging
            }
            
            try:
                self._atomic_json_write(metadata_file, metadata)
                logger.info(f"Created metadata for {domain} with inferred DNS provider: {dns_provider}")
                created_count += 1
            except Exception as e:
                logger.error(f"Failed to create metadata for {domain}: {e}")
        
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
                return True
            return False
        finally:
            domain_lock.release()

    def _infer_dns_provider(self, domain, settings):
        """Infer the DNS provider for a domain, preferring its explicit
        per-domain setting over the global default."""
        provider = self.settings_manager.get_domain_dns_provider(domain, settings)
        return provider or settings.get('dns_provider') or 'cloudflare'
