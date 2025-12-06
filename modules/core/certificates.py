"""
Certificate operations module for CertMate
Handles certificate creation, renewal, and information retrieval
"""

import os
import subprocess
import tempfile
import time
import logging
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from .shell import ShellExecutor
from .dns_strategies import DNSStrategyFactory

logger = logging.getLogger(__name__)


class CertificateManager:
    """Class to handle certificate operations"""
    
    def __init__(self, cert_dir, settings_manager, dns_manager, storage_manager=None, ca_manager=None, shell_executor=None):
        self.cert_dir = Path(cert_dir)
        self.settings_manager = settings_manager
        self.dns_manager = dns_manager
        self.storage_manager = storage_manager
        self.ca_manager = ca_manager
        self.shell_executor = shell_executor or ShellExecutor()





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
                # Get certificate expiry using openssl
                result = self.shell_executor.run([
                    'openssl', 'x509', '-in', temp_cert_path, '-noout', '-dates'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    not_after = None
                    for line in lines:
                        if line.startswith('notAfter='):
                            not_after = line.split('=', 1)[1]
                            break
                    
                    if not_after:
                        # Parse the date
                        try:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry_date - datetime.now()).days
                            
                            return {
                                'domain': domain,
                                'exists': True,
                                'expiry_date': expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                                'days_left': days_left,
                                'days_until_expiry': days_left,
                                'needs_renewal': days_left < renewal_threshold_days,
                                'dns_provider': dns_provider
                            }
                        except Exception as e:
                            logger.error(f"Error parsing certificate date: {e}")
            finally:
                # Clean up temporary file
                try:
                    import os
                    os.unlink(temp_cert_path)
                except Exception:
                    pass
                    
        except Exception as e:
            logger.error(f"Error getting certificate info: {e}")
        
        return self._create_empty_cert_info(domain)

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

    def create_certificate(self, domain, email, dns_provider=None, dns_config=None, account_id=None, staging=False, ca_provider=None, ca_account_id=None):
        """Create SSL certificate using configurable CA with DNS challenge
        
        Args:
            domain: Domain name for certificate
            email: Contact email for certificate authority
            dns_provider: DNS provider name (e.g., 'cloudflare')
            dns_config: Explicit DNS configuration (overrides account lookup)
            account_id: Specific account ID to use for the DNS provider
            staging: Use staging environment for testing
            ca_provider: Certificate Authority provider (letsencrypt, digicert, private_ca)
            ca_account_id: Specific CA account ID to use
        """
        # Track timing for metrics
        start_time = time.time()
        
        # Track if we set env vars
        env_vars_set = False
        
        try:
            logger.info(f"Starting certificate creation for domain: {domain}")
            
            # ... (Validation and CA setup remains the same until DNS config)
            
            # Validate inputs
            if not domain or not email:
                raise ValueError("Domain and email are required")
            
            # Get CA provider configuration
            if not ca_provider:
                settings = self.settings_manager.load_settings()
                ca_provider = settings.get('default_ca_provider', 'letsencrypt')
            
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
            
            # Get DNS configuration
            if not dns_config:
                if not dns_provider:
                    settings = self.settings_manager.load_settings()
                    dns_provider = self.settings_manager.get_domain_dns_provider(domain, settings)
                
                dns_config, used_account_id = self._get_dns_config(
                    dns_provider, account_id
                )
                
                if not dns_config:
                    raise ValueError(f"DNS provider '{dns_provider}' account '{account_id or 'default'}' not configured")
                
                logger.info(f"Using DNS provider: {dns_provider} with account: {used_account_id}")
            
            # Create output directory
            cert_dir = self.cert_dir
            cert_output_dir = cert_dir / domain
            cert_output_dir.mkdir(parents=True, exist_ok=True)
            
            # Get Strategy
            strategy = DNSStrategyFactory.get_strategy(dns_provider)

            # Build certbot command
            if self.ca_manager and ca_account_config:
                certbot_cmd = self.ca_manager.build_certbot_command(
                    domain, email, ca_provider, dns_provider, dns_config, 
                    ca_account_config, staging, cert_dir
                )
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
                    '-d', domain
                ]
                
                if staging:
                    certbot_cmd.append('--staging')
            
            # Prepare Environment
            strategy.prepare_environment(os.environ, dns_config)
            env_vars_set = True

            # Create Config File
            credentials_file = strategy.create_config_file(dns_config)
            
            # Configure Args
            strategy.configure_certbot_arguments(certbot_cmd, credentials_file)
            
            # Set propagation time
            try:
                settings = self.settings_manager.load_settings()
                propagation_map = settings.get('dns_propagation_seconds', {}) or {}
            except Exception:
                propagation_map = {}
            
            # Default to strategy default if not in settings map
            default_seconds = strategy.default_propagation_seconds
            propagation_time = int(propagation_map.get(dns_provider, default_seconds))
            
            certbot_cmd.extend([f'--{strategy.plugin_name}-propagation-seconds', str(propagation_time)])
            
            logger.info(f"Running certbot command for {domain} with {dns_provider}")
            logger.debug(f"Certbot command: {' '.join(str(item) for item in certbot_cmd)}")
            
            # Run certbot
            result = self.shell_executor.run(
                certbot_cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )
            
            # Clean up credentials file
            if credentials_file:
                try:
                    os.unlink(credentials_file)
                except FileNotFoundError:
                    pass
            
            # Cleanup Environment
            if env_vars_set:
                strategy.cleanup_environment(os.environ)
                env_vars_set = False
            
            if result.returncode != 0:
                logger.error(f"Certbot failed for {domain}: {result.stderr}")
                raise RuntimeError(f"Certificate creation failed: {result.stderr}")
            
            # Move certificates to standard location
            live_dir = cert_output_dir / 'live' / domain
            cert_files = {}
            
            if live_dir.exists():
                for cert_file in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
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
                'dns_provider': dns_provider,
                'created_at': datetime.now().isoformat(),
                'email': email,
                'staging': staging,
                'account_id': account_id
            }
            
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
                import json
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
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
            # Clean up env if still set
            if env_vars_set:
                # We need to access strategy again, but it might not be defined if error happened early
                # Best effort cleanup
                try:
                    strategy = DNSStrategyFactory.get_strategy(dns_provider) if 'dns_provider' in locals() and dns_provider else None
                    if strategy:
                        strategy.cleanup_environment(os.environ)
                except:
                    pass
            
            duration = time.time() - start_time
            logger.error(f"Certificate creation failed for {domain}: {str(e)} (duration: {duration:.2f}s)")
            raise

    def renew_certificate(self, domain):
        """Renew a certificate"""
        try:
            # Use the same config/work/log directories as during creation
            cert_dir = self.cert_dir
            domain_dir = cert_dir / domain
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
                
                files_to_copy = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']
                for file_name in files_to_copy:
                    src_file = src_dir / file_name
                    dest_file = dest_dir / file_name
                    if src_file.exists():
                        with open(src_file, 'rb') as src, open(dest_file, 'wb') as dest:
                            dest.write(src.read())
                
                # Update metadata with renewal timestamp
                metadata_file = dest_dir / 'metadata.json'
                if metadata_file.exists():
                    try:
                        import json
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        metadata['renewed_at'] = datetime.now().isoformat()
                        with open(metadata_file, 'w') as f:
                            json.dump(metadata, f, indent=2)
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
                elif isinstance(domain_entry, dict):
                    domain = domain_entry.get('domain')
                else:
                    logger.warning(f"Invalid domain entry format: {domain_entry}")
                    continue
                
                if not domain:
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
                import json
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
                logger.info(f"Created metadata for {domain} with inferred DNS provider: {dns_provider}")
                created_count += 1
            except Exception as e:
                logger.error(f"Failed to create metadata for {domain}: {e}")
        
        logger.info(f"Created metadata files for {created_count} certificates")
        return created_count
    
    def _infer_dns_provider(self, domain, settings):
        """Infer DNS provider based on domain patterns and settings"""
        # Check domain-specific patterns
        if 'test.certmate.org' in domain:
            return 'route53'
        elif domain.endswith('.audiolibri.org'):
            return 'cloudflare'
        elif domain.startswith('aws-'):
            return 'route53'
        elif domain.startswith('cf-'):
            return 'cloudflare'
        
        # Fall back to current settings default
        return settings.get('dns_provider', 'cloudflare')
