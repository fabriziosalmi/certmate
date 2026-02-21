"""
API endpoints module for CertMate
Defines Flask-RESTX Resource classes for REST API endpoints
"""

import ipaddress
import logging
import re
import socket
import tempfile
import zipfile
import os
from pathlib import Path
from urllib.parse import urlparse
from flask import send_file, after_this_request, current_app
from flask_restx import Resource, fields

from ..core.metrics import generate_metrics_response, get_metrics_summary, is_prometheus_available
from ..core.constants import CERTIFICATE_FILES, get_domain_name

_DOMAIN_RE = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _is_safe_url(url: str) -> tuple:
    """Check if a URL is safe to request (not targeting private/internal networks).
    Returns (is_safe, error_message)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: no hostname"
        # Resolve hostname to IP
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return False, "Could not resolve hostname"
        for family, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, "URL resolves to a private/internal network address"
        return True, None
    except Exception:
        return False, "Invalid URL"


def _validate_domain_path(domain, cert_base_dir):
    """Validate domain name to prevent path traversal. Returns (Path, error_msg)."""
    if not domain or '..' in domain or '/' in domain or '\\' in domain or '\x00' in domain:
        return None, 'Invalid domain name'
    if not _DOMAIN_RE.match(domain):
        return None, 'Invalid domain format'
    cert_dir = Path(cert_base_dir) / domain
    try:
        resolved = cert_dir.resolve()
        base_resolved = Path(cert_base_dir).resolve()
        if not str(resolved).startswith(str(base_resolved) + os.sep) and resolved != base_resolved:
            return None, 'Invalid domain path'
    except (OSError, ValueError):
        return None, 'Invalid domain path'
    return cert_dir, None

logger = logging.getLogger(__name__)


def create_api_resources(api, models, managers):
    """Create and register all API resource classes
    
    Args:
        api: Flask-RESTX Api instance
        models: Dictionary of API models
        managers: Dictionary of manager instances (auth, settings, certificates, etc.)
    """
    
    auth_manager = managers['auth']
    settings_manager = managers['settings']
    certificate_manager = managers['certificates']
    file_ops = managers['file_ops']
    cache_manager = managers['cache']
    dns_manager = managers['dns']
    
    # Health check endpoint
    class HealthCheck(Resource):
        def get(self):
            """Health check endpoint"""
            try:
                # Basic health checks
                settings = settings_manager.load_settings()
                
                return {
                    'status': 'healthy'
                }
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return {'status': 'unhealthy'}, 500

    # Metrics endpoints
    class MetricsList(Resource):
        def get(self):
            """Get available metrics information"""
            try:
                if not is_prometheus_available():
                    return {'error': 'Prometheus metrics not available'}, 503
                    
                summary = get_metrics_summary()
                return {
                    'available': True,
                    'metrics_endpoint': '/metrics',
                    'summary': summary
                }
            except Exception as e:
                logger.error(f"Error getting metrics info: {e}")
                return {'error': 'Failed to get metrics information'}, 500

    # Settings endpoints
    class Settings(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        @api.marshal_with(models['settings_model'])
        def get(self):
            """Get current settings"""
            try:
                settings = settings_manager.load_settings()
                if not settings:
                    return {}, 200
                return settings
            except ValueError as e:
                logger.error(f"Invalid settings format: {e}")
                return {'error': 'Invalid settings data'}, 500
            except Exception as e:
                logger.error(f"Error getting settings: {e}")
                return {'error': 'Failed to load settings'}, 500

        @api.doc(security='Bearer')
        @api.expect(models['settings_model'])
        @auth_manager.require_role('admin')
        def post(self):
            """Update settings"""
            try:
                new_settings = api.payload
                if not isinstance(new_settings, dict):
                    return {'error': 'Invalid settings format'}, 400
                
                # Validate required fields
                required_fields = ['email', 'dns_provider']
                for field in required_fields:
                    if field not in new_settings:
                        return {'error': f'Missing required field: {field}'}, 400
                
                # Save settings
                success = settings_manager.save_settings(new_settings, "api_update")
                
                if success:
                    return {'message': 'Settings updated successfully'}, 200
                else:
                    return {'error': 'Failed to save settings'}, 500
                    
            except Exception as e:
                logger.error(f"Error updating settings: {e}")
                return {'error': 'Failed to update settings'}, 500



    # DNS Providers endpoint
    class DNSProviders(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        @api.marshal_with(models['dns_providers_model'])
        def get(self):
            """Get DNS provider configurations"""
            try:
                settings = settings_manager.load_settings()
                return settings.get('dns_providers', {})
            except Exception as e:
                logger.error(f"Error getting DNS providers: {e}")
                return {'error': 'Failed to load DNS providers'}, 500



    # Cache management endpoints
    class CacheStats(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_stats_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """Get cache statistics"""
            try:
                stats = cache_manager.get_cache_stats()
                return stats
            except Exception as e:
                logger.error(f"Error getting cache stats: {e}")
                return {'error': 'Failed to get cache statistics'}, 500

    class CacheClear(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_clear_response_model'])
        @auth_manager.require_role('admin')
        def post(self):
            """Clear deployment cache"""
            try:
                cleared_count = cache_manager.clear_cache()
                return {
                    'success': True,
                    'message': 'Cache cleared successfully',
                    'cleared_entries': cleared_count
                }
            except Exception as e:
                logger.error(f"Error clearing cache: {e}")
                return {
                    'success': False,
                    'message': 'Failed to clear cache',
                    'cleared_entries': 0
                }, 500

    # Certificate endpoints
    class CertificateList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_list_with(models['certificate_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """List all certificates"""
            try:
                settings = settings_manager.load_settings()
                certificates = []
                
                # Create a set of all domains to check (from settings and disk)
                all_domains = set()
                
                # Add domains from settings
                for domain_entry in settings.get('domains', []):
                    if isinstance(domain_entry, str):
                        domain = domain_entry
                    elif isinstance(domain_entry, dict):
                        domain = domain_entry.get('domain')
                    else:
                        continue
                    if domain:
                        all_domains.add(domain)
                
                # Also check for certificates that exist on disk but might not be in settings
                cert_dir = certificate_manager.cert_dir
                if cert_dir.exists():
                    for cert_dir_path in cert_dir.iterdir():
                        if cert_dir_path.is_dir():
                            all_domains.add(cert_dir_path.name)
                
                # Get certificate info for all domains
                for domain in all_domains:
                    if domain:
                        cert_info = certificate_manager.get_certificate_info(domain)
                        if cert_info:
                            certificates.append(cert_info)
                
                return certificates
            except Exception as e:
                logger.error(f"Error listing certificates: {e}")
                return {'error': 'Failed to list certificates'}, 500

    class CreateCertificate(Resource):
        @api.doc(security='Bearer')
        @api.expect(models['create_cert_model'])
        @auth_manager.require_role('operator')
        def post(self):
            """Create a new certificate"""
            try:
                data = api.payload
                domain = (data.get('domain') or '').strip()
                san_domains = data.get('san_domains', [])  # Optional SAN domains
                dns_provider = data.get('dns_provider')
                account_id = data.get('account_id')
                ca_provider = data.get('ca_provider')
                challenge_type = data.get('challenge_type')  # Optional: 'dns-01' or 'http-01'
                domain_alias = data.get('domain_alias')  # Optional domain alias
                if domain_alias:
                    from ..core.utils import validate_domain
                    alias_valid, alias_msg = validate_domain(domain_alias)
                    if not alias_valid:
                        return {'error': f'Invalid domain_alias: {alias_msg}'}, 400

                # Validate domain
                if not domain:
                    return {
                        'error': 'Domain is required',
                        'hint': 'Please provide a valid domain name (e.g., example.com or *.example.com for wildcard)'
                    }, 400
                
                # Basic domain validation
                if ' ' in domain:
                    return {
                        'error': 'Invalid domain format',
                        'hint': 'Enter only ONE primary domain. Use san_domains array for additional domains.'
                    }, 400
                
                # Check for common domain format issues
                if domain.startswith('http://') or domain.startswith('https://'):
                    return {
                        'error': 'Invalid domain format',
                        'hint': 'Provide domain name only (e.g., example.com), not the full URL.'
                    }, 400
                
                # Validate SAN domains if provided
                if san_domains:
                    if not isinstance(san_domains, list):
                        return {
                            'error': 'Invalid san_domains format',
                            'hint': 'san_domains must be an array of domain strings.'
                        }, 400
                    
                    # Validate each SAN domain
                    for san in san_domains:
                        san = san.strip() if isinstance(san, str) else ''
                        if san and (san.startswith('http://') or san.startswith('https://')):
                            return {
                                'error': f'Invalid SAN domain format: {san}',
                                'hint': 'SAN domains should be domain names only, not URLs.'
                            }, 400
                
                settings = settings_manager.load_settings()
                email = settings.get('email')
                
                if not email:
                    return {
                        'error': 'Email not configured',
                        'hint': 'Configure email in settings first. Required by certificate authorities for important notifications.'
                    }, 400
                
                # Resolve challenge type from settings if not provided
                if not challenge_type:
                    challenge_type = settings.get('challenge_type', 'dns-01')

                # DNS provider validation (skip for HTTP-01)
                if challenge_type != 'http-01':
                    if not dns_provider:
                        dns_provider = settings.get('dns_provider')

                    if not dns_provider:
                        return {
                            'error': 'No DNS provider specified or configured',
                            'hint': 'Either specify dns_provider in request or configure a default DNS provider in settings.'
                        }, 400

                # Create certificate with SAN domains
                result = certificate_manager.create_certificate(
                    domain=domain,
                    email=email,
                    dns_provider=dns_provider,
                    account_id=account_id,
                    ca_provider=ca_provider,
                    domain_alias=domain_alias,
                    san_domains=san_domains,
                    challenge_type=challenge_type
                )
                
                # Ensure domain is in settings for proper listing
                domains_list = settings.get('domains', [])
                domain_exists = any(
                    (d == domain if isinstance(d, str) else d.get('domain') == domain)
                    for d in domains_list
                )
                if not domain_exists:
                    # Add domain with its configuration
                    domain_config = {
                        'domain': domain,
                        'dns_provider': dns_provider or settings.get('dns_provider'),
                        'dns_account_id': account_id
                    }
                    domains_list.append(domain_config)
                    settings['domains'] = domains_list
                    settings_manager.save_settings(settings, "certificate_created")
                    logger.info(f"Added domain {domain} to settings after certificate creation")
                
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_created', {
                        'domain': domain,
                        'san_domains': san_domains,
                        'dns_provider': result.get('dns_provider'),
                        'ca_provider': result.get('ca_provider')
                    })

                return {
                    'message': f'Certificate created successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'ca_provider': result.get('ca_provider'),
                    'duration': result.get('duration')
                }, 201

            except ValueError as e:
                # Validation errors from certificate_manager
                error_msg = str(e)
                hint = None
                if 'not configured' in error_msg.lower():
                    hint = 'Check your DNS provider settings and ensure credentials are properly configured.'
                elif 'domain' in error_msg.lower() and 'email' in error_msg.lower():
                    hint = 'Both domain and email are required. Configure email in settings.'
                return {
                    'error': error_msg,
                    'hint': hint
                }, 400
            except RuntimeError as e:
                # Certbot execution errors
                error_msg = str(e)
                hint = 'Check DNS provider credentials and ensure DNS records can be created.'
                if 'unauthorized' in error_msg.lower() or 'auth' in error_msg.lower():
                    hint = 'DNS provider authentication failed. Verify your API credentials in settings.'
                elif 'timeout' in error_msg.lower():
                    hint = 'DNS propagation timed out. Try increasing DNS propagation time in settings.'
                elif 'rate limit' in error_msg.lower():
                    hint = "You've hit the certificate authority's rate limit. Wait before trying again."
                return {
                    'error': f'Certificate creation failed: {error_msg}',
                    'hint': hint
                }, 500
            except Exception as e:
                logger.error(f"Certificate creation failed: {str(e)}")
                return {
                    'error': 'Certificate creation failed unexpectedly',
                    'hint': 'Check application logs for detailed error information.'
                }, 500

    class DownloadCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self, domain):
            """Download certificate files as ZIP"""
            try:
                cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}'}, 404

                # Create temporary ZIP file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                    tmp_path = tmp_file.name
                    with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for cert_file in CERTIFICATE_FILES:
                            file_path = cert_dir / cert_file
                            if file_path.exists():
                                zipf.write(file_path, cert_file)
                    
                    @after_this_request
                    def remove_file(response):
                        try:
                            os.remove(tmp_path)
                        except Exception as e:
                            logger.debug(f"Could not remove temp file {tmp_path}: {e}")
                        return response
                    
                    return send_file(
                        tmp_path,
                        as_attachment=True,
                        download_name=f'{domain}_certificates.zip',
                        mimetype='application/zip'
                    )
                    
            except Exception as e:
                logger.error(f"Error downloading certificate for {domain}: {e}")
                return {'error': 'Failed to download certificate'}, 500

    class RenewCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        def post(self, domain):
            """Renew an existing certificate"""
            try:
                result = certificate_manager.renew_certificate(domain)

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_renewed', {'domain': domain})

                return {
                    'message': f'Certificate renewed successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'duration': result.get('duration')
                }, 200

            except Exception as e:
                logger.error(f"Certificate renewal failed for {domain}: {str(e)}")
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_failed', {'domain': domain, 'error': str(e)})
                return {'error': 'Certificate renewal failed'}, 500

    # Backup endpoints (Unified backup system for atomic consistency)
    class BackupList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['backup_list_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """List all available backups"""
            try:
                backups = file_ops.list_backups()
                return backups
            except Exception as e:
                logger.error(f"Error listing backups: {e}")
                return {'error': 'Failed to list backups'}, 500

    class BackupCreate(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupCreateRequest', {
            'type': fields.String(required=True, enum=['unified', 'settings', 'certificates', 'both'], 
                                   description='Type of backup to create (unified recommended for data consistency)'),
            'reason': fields.String(description='Reason for backup creation', default='manual')
        }))
        @auth_manager.require_role('admin')
        def post(self):
            """Create a new backup (unified format recommended)"""
            try:
                data = api.payload
                backup_type = data.get('type', 'unified')  # Default to unified
                reason = data.get('reason', 'manual')
                
                created_backups = []
                
                # Only support unified backup (legacy removed)
                settings = settings_manager.load_settings()
                filename = file_ops.create_unified_backup(settings, reason)
                if filename:
                    created_backups.append({'type': 'unified', 'filename': filename})
                    logger.info(f"Created unified backup: {filename}")
                
                if created_backups:
                    return {
                        'message': 'Backup created successfully',
                        'backups': created_backups,
                        'recommendation': 'Use unified backups for data consistency' if backup_type != 'unified' else None
                    }, 201
                else:
                    return {'error': 'Failed to create backup'}, 500
                    
            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                return {'error': 'Failed to create backup'}, 500

    class BackupDownload(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def get(self, backup_type, filename):
            """Download a backup file"""
            try:
                if backup_type != 'unified':
                    return {'error': 'Only unified backup download is supported'}, 400
                
                backup_path = Path(file_ops.backup_dir) / backup_type / filename
                
                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404
                
                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                    return {'error': 'Access denied'}, 403
                
                return send_file(
                    backup_path,
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/octet-stream'
                )
                
            except FileNotFoundError:
                return {'error': 'Backup file not found'}, 404
            except PermissionError:
                return {'error': 'Access denied to backup file'}, 403
            except Exception as e:
                logger.error(f"Error downloading backup: {e}")
                return {'error': 'Failed to download backup'}, 500

    class BackupRestore(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupRestoreRequest', {
            'filename': fields.String(required=True, description='Backup filename to restore from'),
            'create_backup_before_restore': fields.Boolean(description='Create backup before restore', default=True)
        }))
        @auth_manager.require_role('admin')
        def post(self, backup_type):
            """Restore from a unified backup file (only unified backups supported)"""
            try:
                if backup_type != 'unified':
                    return {'error': 'Only unified backup restoration is supported'}, 400
                
                data = api.payload
                filename = data.get('filename')
                create_backup = data.get('create_backup_before_restore', True)
                
                if not filename:
                    return {'error': 'Filename is required'}, 400
                
                # Handle unified backups only
                backup_path = Path(file_ops.backup_dir) / "unified" / filename
                
                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404
                
                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                    return {'error': 'Access denied'}, 403
                
                # Create backup of current state if requested
                pre_restore_backup = None
                if create_backup:
                    current_settings = settings_manager.load_settings()
                    pre_restore_backup = file_ops.create_unified_backup(current_settings, "pre_restore")
                    logger.info(f"Created pre-restore backup: {pre_restore_backup}")
                
                # Restore from unified backup
                success = file_ops.restore_unified_backup(str(backup_path))
                restore_msg = "Settings and certificates restored atomically"
                
                if success:
                    response = {
                        'message': f'{restore_msg} successfully from {filename}',
                        'restored_from': filename,
                        'backup_type': 'unified'
                    }
                    if pre_restore_backup:
                        response['pre_restore_backup'] = pre_restore_backup
                        response['note'] = 'A backup of the previous state was created before restore'
                    
                    return response, 200
                else:
                    return {'error': 'Failed to restore unified backup'}, 500
                    
            except FileNotFoundError:
                return {'error': 'Backup file not found'}, 404
            except ValueError as e:
                logger.warning(f"Backup restore validation error: {e}")
                return {'error': 'Invalid backup data'}, 400
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
                return {'error': 'Failed to restore backup'}, 500

    class BackupDelete(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def delete(self, backup_type, filename):
            """Delete a unified backup file"""
            try:
                file_ops = managers.get('file_ops')
                if not file_ops:
                    return {'error': 'File operations manager not available'}, 500
                
                if backup_type != 'unified':
                    return {'error': 'Only unified backup deletion is supported'}, 400
                
                # Construct backup path
                backup_dir = file_ops.backup_dir / backup_type
                backup_path = backup_dir / filename
                
                # Validate the backup file exists and is within the backup directory
                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                if not str(backup_path.resolve()).startswith(str(backup_dir.resolve())):
                    return {'error': 'Invalid backup path'}, 400
                
                # Delete the backup file
                backup_path.unlink()
                
                logger.info(f"Backup deleted: {backup_type}/{filename}")
                return {
                    'message': f'Backup {filename} deleted successfully',
                    'deleted_file': filename,
                    'backup_type': backup_type
                }, 200
                
            except Exception as e:
                logger.error(f"Error deleting backup: {e}")
                return {'error': 'Failed to delete backup'}, 500

    # Storage Backend Management
    class StorageBackendInfo(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self):
            """Get current storage backend information"""
            try:
                storage_manager = managers.get('storage')
                if not storage_manager:
                    return {'error': 'Storage manager not available'}, 500
                
                backend_name = storage_manager.get_backend_name()
                settings = settings_manager.load_settings()
                storage_config = settings.get('certificate_storage', {})
                
                return {
                    'current_backend': backend_name,
                    'available_backends': [
                        'local_filesystem',
                        'azure_keyvault', 
                        'aws_secrets_manager',
                        'hashicorp_vault',
                        'infisical'
                    ],
                    'configuration': {
                        'backend': storage_config.get('backend', 'local_filesystem'),
                        'cert_dir': storage_config.get('cert_dir', 'certificates')
                    }
                }
            except Exception as e:
                logger.error(f"Error getting storage backend info: {e}")
                return {'error': 'Failed to get storage backend info'}, 500
    
    class StorageBackendConfig(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        @api.expect(models['StorageConfig'])
        def post(self):
            """Update storage backend configuration"""
            try:
                data = api.payload
                backend_type = data.get('backend')
                
                if backend_type not in ['local_filesystem', 'azure_keyvault', 'aws_secrets_manager', 'hashicorp_vault', 'infisical']:
                    return {'error': 'Invalid backend type'}, 400
                
                settings = settings_manager.load_settings()
                
                # Update storage configuration
                if 'certificate_storage' not in settings:
                    settings['certificate_storage'] = {}
                
                settings['certificate_storage']['backend'] = backend_type
                
                # Update backend-specific configuration
                if backend_type == 'local_filesystem':
                    cert_dir = data.get('cert_dir', 'certificates')
                    settings['certificate_storage']['cert_dir'] = cert_dir
                
                elif backend_type == 'azure_keyvault':
                    azure_config = data.get('azure_keyvault', {})
                    settings['certificate_storage']['azure_keyvault'] = azure_config
                
                elif backend_type == 'aws_secrets_manager':
                    aws_config = data.get('aws_secrets_manager', {})
                    settings['certificate_storage']['aws_secrets_manager'] = aws_config
                
                elif backend_type == 'hashicorp_vault':
                    vault_config = data.get('hashicorp_vault', {})
                    settings['certificate_storage']['hashicorp_vault'] = vault_config
                
                elif backend_type == 'infisical':
                    infisical_config = data.get('infisical', {})
                    settings['certificate_storage']['infisical'] = infisical_config
                
                # Save settings
                success = settings_manager.save_settings(settings, backup_reason="storage_backend_update")
                
                if success:
                    return {
                        'success': True,
                        'message': f'Storage backend updated to {backend_type}',
                        'backend': backend_type
                    }
                else:
                    return {'error': 'Failed to save storage configuration'}, 500
                    
            except Exception as e:
                logger.error(f"Error updating storage backend config: {e}")
                return {'error': 'Failed to update storage backend configuration'}, 500
    
    class StorageBackendTest(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        @api.expect(models['StorageTestConfig'])
        def post(self):
            """Test storage backend connection"""
            try:
                data = api.payload
                backend_type = data.get('backend')
                config = data.get('config', {})
                
                # Import storage backends
                from ..core.storage_backends import (
                    LocalFileSystemBackend, AzureKeyVaultBackend, 
                    AWSSecretsManagerBackend, HashiCorpVaultBackend, 
                    InfisicalBackend
                )
                
                # Test connection based on backend type
                try:
                    if backend_type == 'local_filesystem':
                        test_backend = LocalFileSystemBackend(Path(config.get('cert_dir', 'certificates')))
                        
                    elif backend_type == 'azure_keyvault':
                        test_backend = AzureKeyVaultBackend(config)
                        
                    elif backend_type == 'aws_secrets_manager':
                        test_backend = AWSSecretsManagerBackend(config)
                        
                    elif backend_type == 'hashicorp_vault':
                        test_backend = HashiCorpVaultBackend(config)
                        
                    elif backend_type == 'infisical':
                        test_backend = InfisicalBackend(config)
                        
                    else:
                        return {'error': 'Invalid backend type'}, 400
                    
                    # Test by trying to list certificates (should not fail for auth issues)
                    domains = test_backend.list_certificates()
                    
                    return {
                        'success': True,
                        'message': f'Successfully connected to {backend_type}',
                        'backend': backend_type,
                        'certificate_count': len(domains)
                    }
                    
                except Exception as test_error:
                    logger.error(f"Storage backend connection test failed: {test_error}")
                    return {
                        'success': False,
                        'message': 'Connection test failed',
                        'backend': backend_type
                    }

            except Exception as e:
                logger.error(f"Error testing storage backend: {e}")
                return {'error': 'Failed to test storage backend'}, 500
    
    class CAProviderTest(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        @api.expect(models['CATestConfig'])
        def post(self):
            """Test CA provider connection"""
            try:
                data = api.payload
                ca_provider = data.get('ca_provider')
                config = data.get('config', {})
                
                # Import CA manager
                ca_manager = managers.get('ca')
                if not ca_manager:
                    return {'error': 'CA manager not available'}, 500
                
                # Test connection based on CA provider type
                try:
                    if ca_provider == 'letsencrypt':
                        # Test Let's Encrypt connection
                        environment = config.get('environment', 'production')
                        email = config.get('email', '')
                        
                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for Let\'s Encrypt',
                                'ca_provider': ca_provider
                            }
                        
                        # Test by getting the directory URL
                        directory_url = ca_manager._get_letsencrypt_directory_url(environment)
                        
                        return {
                            'success': True,
                            'message': f'Let\'s Encrypt {environment} endpoint is accessible',
                            'ca_provider': ca_provider,
                            'directory_url': directory_url
                        }
                        
                    elif ca_provider == 'digicert':
                        # Test DigiCert ACME connection
                        acme_url = config.get('acme_url', '')
                        eab_kid = config.get('eab_kid', '')
                        eab_hmac = config.get('eab_hmac', '')
                        email = config.get('email', '')
                        
                        if not acme_url:
                            return {
                                'success': False,
                                'message': 'ACME URL is required for DigiCert',
                                'ca_provider': ca_provider
                            }
                        
                        if not eab_kid or not eab_hmac:
                            return {
                                'success': False,
                                'message': 'EAB credentials (Key ID and HMAC Key) are required for DigiCert',
                                'ca_provider': ca_provider
                            }
                        
                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for DigiCert',
                                'ca_provider': ca_provider
                            }
                        
                        # Test by attempting to validate EAB credentials format
                        if len(eab_kid) < 10 or len(eab_hmac) < 32:
                            return {
                                'success': False,
                                'message': 'EAB credentials appear to be invalid (too short)',
                                'ca_provider': ca_provider
                            }
                        
                        return {
                            'success': True,
                            'message': 'DigiCert configuration appears valid',
                            'ca_provider': ca_provider,
                            'acme_url': acme_url
                        }
                        
                    elif ca_provider == 'private_ca':
                        # Test Private CA connection
                        acme_url = config.get('acme_url', '')
                        ca_cert = config.get('ca_cert', '')
                        email = config.get('email', '')
                        
                        if not acme_url:
                            return {
                                'success': False,
                                'message': 'ACME URL is required for Private CA',
                                'ca_provider': ca_provider
                            }
                        
                        if not email:
                            return {
                                'success': False,
                                'message': 'Email is required for Private CA',
                                'ca_provider': ca_provider
                            }
                        
                        # Basic URL validation
                        if not (acme_url.startswith('http://') or acme_url.startswith('https://')):
                            return {
                                'success': False,
                                'message': 'ACME URL must be a valid HTTP/HTTPS URL',
                                'ca_provider': ca_provider
                            }
                        
                        # If CA cert is provided, validate it's PEM format
                        if ca_cert and not (ca_cert.strip().startswith('-----BEGIN CERTIFICATE-----') and 
                                          ca_cert.strip().endswith('-----END CERTIFICATE-----')):
                            return {
                                'success': False,
                                'message': 'CA certificate must be in PEM format',
                                'ca_provider': ca_provider
                            }
                        
                        # Test actual connectivity to the ACME endpoint
                        try:
                            import requests
                            import ssl
                            from urllib.parse import urljoin

                            # SSRF protection: block requests to private/internal networks
                            is_safe, ssrf_msg = _is_safe_url(acme_url)
                            if not is_safe:
                                return {
                                    'success': False,
                                    'message': f'ACME URL rejected: {ssrf_msg}',
                                    'ca_provider': ca_provider
                                }

                            # Test if the ACME directory is accessible
                            timeout = 10

                            # For HTTPS URLs, we might need to handle custom CA certificates
                            verify_ssl = True
                            if ca_cert:
                                # If a custom CA cert is provided, we should use it for verification
                                # For now, we'll warn but still allow the connection
                                logger.info("Custom CA certificate provided for Private CA")

                            response = requests.get(acme_url, timeout=timeout, verify=verify_ssl)
                            
                            if response.status_code == 200:
                                try:
                                    directory_data = response.json()
                                    # Check if it looks like an ACME directory
                                    if 'newAccount' in directory_data or 'keyChange' in directory_data:
                                        return {
                                            'success': True,
                                            'message': f'Private CA ACME endpoint is accessible and appears to be a valid ACME directory',
                                            'ca_provider': ca_provider,
                                            'acme_url': acme_url,
                                            'has_ca_cert': bool(ca_cert),
                                            'directory_urls': list(directory_data.keys()) if isinstance(directory_data, dict) else []
                                        }
                                    else:
                                        return {
                                            'success': False,
                                            'message': 'Endpoint is accessible but does not appear to be a valid ACME directory',
                                            'ca_provider': ca_provider
                                        }
                                except Exception:
                                    return {
                                        'success': False,
                                        'message': 'Endpoint is accessible but returned invalid JSON',
                                        'ca_provider': ca_provider
                                    }
                            else:
                                return {
                                    'success': False,
                                    'message': f'ACME endpoint returned HTTP {response.status_code}',
                                    'ca_provider': ca_provider
                                }
                                
                        except requests.exceptions.Timeout:
                            return {
                                'success': False,
                                'message': 'Connection timeout - ACME endpoint is not accessible',
                                'ca_provider': ca_provider
                            }
                        except requests.exceptions.ConnectionError:
                            return {
                                'success': False,
                                'message': 'Connection failed - ACME endpoint is not accessible',
                                'ca_provider': ca_provider
                            }
                        except requests.exceptions.SSLError as ssl_error:
                            return {
                                'success': False,
                                'message': 'SSL verification failed',
                                'ca_provider': ca_provider
                            }
                        except Exception as conn_error:
                            logger.error(f"CA provider connection test failed: {conn_error}")
                            return {
                                'success': False,
                                'message': 'Connection test failed',
                                'ca_provider': ca_provider
                            }

                    else:
                        return {'error': 'Invalid CA provider type'}, 400

                except Exception as test_error:
                    logger.error(f"CA provider test failed: {test_error}")
                    return {
                        'success': False,
                        'message': 'CA provider test failed',
                        'ca_provider': ca_provider
                    }

            except Exception as e:
                logger.error(f"Error testing CA provider: {e}")
                return {'error': 'Failed to test CA provider'}, 500

    class StorageBackendMigrate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        @api.expect(models['StorageMigrationConfig'])
        def post(self):
            """Migrate certificates between storage backends"""
            try:
                data = api.payload
                source_backend_type = data.get('source_backend')
                target_backend_type = data.get('target_backend')
                source_config = data.get('source_config', {})
                target_config = data.get('target_config', {})
                
                # Import storage backends
                from ..core.storage_backends import (
                    LocalFileSystemBackend, AzureKeyVaultBackend, 
                    AWSSecretsManagerBackend, HashiCorpVaultBackend, 
                    InfisicalBackend
                )
                
                # Create backend instances
                backend_classes = {
                    'local_filesystem': LocalFileSystemBackend,
                    'azure_keyvault': AzureKeyVaultBackend,
                    'aws_secrets_manager': AWSSecretsManagerBackend,
                    'hashicorp_vault': HashiCorpVaultBackend,
                    'infisical': InfisicalBackend
                }
                
                if source_backend_type not in backend_classes or target_backend_type not in backend_classes:
                    return {'error': 'Invalid backend type'}, 400
                
                try:
                    # Initialize backends
                    if source_backend_type == 'local_filesystem':
                        source_backend = LocalFileSystemBackend(Path(source_config.get('cert_dir', 'certificates')))
                    else:
                        source_backend = backend_classes[source_backend_type](source_config)
                    
                    if target_backend_type == 'local_filesystem':
                        target_backend = LocalFileSystemBackend(Path(target_config.get('cert_dir', 'certificates')))
                    else:
                        target_backend = backend_classes[target_backend_type](target_config)
                    
                    # Perform migration using storage manager
                    storage_manager = managers.get('storage')
                    if not storage_manager:
                        return {'error': 'Storage manager not available'}, 500
                    
                    migration_results = storage_manager.migrate_certificates(source_backend, target_backend)
                    
                    successful = sum(1 for success in migration_results.values() if success)
                    total = len(migration_results)
                    
                    return {
                        'success': True,
                        'message': f'Migration completed: {successful}/{total} certificates migrated',
                        'migration_results': migration_results,
                        'source_backend': source_backend_type,
                        'target_backend': target_backend_type
                    }
                    
                except Exception as migration_error:
                    logger.error(f"Storage migration failed: {migration_error}")
                    return {
                        'success': False,
                        'message': 'Migration failed',
                        'source_backend': source_backend_type,
                        'target_backend': target_backend_type
                    }

            except Exception as e:
                logger.error(f"Error during storage migration: {e}")
                return {'error': 'Failed to perform storage migration'}, 500

    # Register storage backend endpoints
    storage_ns = api.namespace('storage', description='Storage Backend Operations')
    storage_ns.add_resource(StorageBackendInfo, '/info')
    storage_ns.add_resource(StorageBackendConfig, '/config')
    storage_ns.add_resource(StorageBackendTest, '/test')
    storage_ns.add_resource(StorageBackendMigrate, '/migrate')

    # Return all resource classes (CA provider test will be registered in app.py)
    return {
        'HealthCheck': HealthCheck,
        'MetricsList': MetricsList,
        'Settings': Settings,
        'DNSProviders': DNSProviders,
        'CacheStats': CacheStats,
        'CacheClear': CacheClear,
        'CertificateList': CertificateList,
        'CreateCertificate': CreateCertificate,
        'DownloadCertificate': DownloadCertificate,
        'RenewCertificate': RenewCertificate,
        'BackupList': BackupList,
        'BackupCreate': BackupCreate,
        'BackupDownload': BackupDownload,
        'BackupRestore': BackupRestore,
        'BackupDelete': BackupDelete,
        'CAProviderTest': CAProviderTest
    }
