"""
API endpoints module for CertMate
Defines Flask-RESTX Resource classes for REST API endpoints
"""

import logging
import tempfile
import zipfile
from pathlib import Path
from flask import send_file
from flask_restx import Resource, fields

from ..core.metrics import generate_metrics_response, get_metrics_summary, is_prometheus_available

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
                    'status': 'healthy',
                    'version': '1.1.15',
                    'services': {
                        'settings': 'ok' if settings else 'error',
                        'cache': 'ok',
                        'metrics': 'ok' if is_prometheus_available() else 'unavailable'
                    }
                }
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return {'status': 'unhealthy', 'error': str(e)}, 500

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
        @auth_manager.require_auth
        def get(self):
            """Get current settings"""
            try:
                settings = settings_manager.load_settings()
                # Don't expose sensitive data in API response
                safe_settings = dict(settings)
                
                # Mask sensitive values
                if 'api_bearer_token' in safe_settings:
                    token = safe_settings['api_bearer_token']
                    if len(token) > 8:
                        safe_settings['api_bearer_token'] = f"{token[:4]}...{token[-4:]}"
                
                # Mask DNS provider credentials
                if 'dns_providers' in safe_settings:
                    for provider, config in safe_settings['dns_providers'].items():
                        if isinstance(config, dict):
                            self._mask_sensitive_dns_config(config)
                
                return safe_settings
            except Exception as e:
                logger.error(f"Error getting settings: {e}")
                return {'error': 'Failed to load settings'}, 500

        @api.doc(security='Bearer')
        @api.expect(models['settings_model'])
        @auth_manager.require_auth
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

        def _mask_sensitive_dns_config(self, config):
            """Mask sensitive values in DNS configuration"""
            sensitive_keys = [
                'api_token', 'secret_access_key', 'client_secret', 'service_account_key',
                'api_key', 'secret_key', 'password', 'consumer_key', 'application_secret'
            ]
            
            for key in sensitive_keys:
                if key in config and config[key]:
                    value = str(config[key])
                    if len(value) > 8:
                        config[key] = f"{value[:4]}...{value[-4:]}"
                    else:
                        config[key] = "***"

    # DNS Providers endpoint
    class DNSProviders(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_auth
        def get(self):
            """Get DNS provider configurations"""
            try:
                settings = settings_manager.load_settings()
                dns_providers = settings.get('dns_providers', {})
                
                # Mask sensitive data
                safe_providers = {}
                for provider, config in dns_providers.items():
                    if isinstance(config, dict):
                        safe_config = dict(config)
                        self._mask_sensitive_dns_config(safe_config)
                        safe_providers[provider] = safe_config
                
                return safe_providers
            except Exception as e:
                logger.error(f"Error getting DNS providers: {e}")
                return {'error': 'Failed to load DNS providers'}, 500

        def _mask_sensitive_dns_config(self, config):
            """Mask sensitive values in DNS configuration (same as Settings class)"""
            sensitive_keys = [
                'api_token', 'secret_access_key', 'client_secret', 'service_account_key',
                'api_key', 'secret_key', 'password', 'consumer_key', 'application_secret'
            ]
            
            if 'accounts' in config:
                for account_id, account_config in config['accounts'].items():
                    if isinstance(account_config, dict):
                        for key in sensitive_keys:
                            if key in account_config and account_config[key]:
                                value = str(account_config[key])
                                if len(value) > 8:
                                    account_config[key] = f"{value[:4]}...{value[-4:]}"
                                else:
                                    account_config[key] = "***"
            else:
                for key in sensitive_keys:
                    if key in config and config[key]:
                        value = str(config[key])
                        if len(value) > 8:
                            config[key] = f"{value[:4]}...{value[-4:]}"
                        else:
                            config[key] = "***"

    # Cache management endpoints
    class CacheStats(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_stats_model'])
        @auth_manager.require_auth
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
        @auth_manager.require_auth
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
        @auth_manager.require_auth
        def get(self):
            """List all certificates"""
            try:
                settings = settings_manager.load_settings()
                certificates = []
                
                for domain_entry in settings.get('domains', []):
                    if isinstance(domain_entry, str):
                        domain = domain_entry
                    elif isinstance(domain_entry, dict):
                        domain = domain_entry.get('domain')
                    else:
                        continue
                    
                    if domain:
                        cert_info = certificate_manager.get_certificate_info(domain)
                        certificates.append(cert_info)
                
                return certificates
            except Exception as e:
                logger.error(f"Error listing certificates: {e}")
                return {'error': 'Failed to list certificates'}, 500

    class CreateCertificate(Resource):
        @api.doc(security='Bearer')
        @api.expect(models['create_cert_model'])
        @auth_manager.require_auth
        def post(self):
            """Create a new certificate"""
            try:
                data = api.payload
                domain = data.get('domain')
                dns_provider = data.get('dns_provider')
                account_id = data.get('account_id')
                
                if not domain:
                    return {'error': 'Domain is required'}, 400
                
                settings = settings_manager.load_settings()
                email = settings.get('email')
                
                if not email:
                    return {'error': 'Email not configured in settings'}, 400
                
                # Create certificate
                result = certificate_manager.create_certificate(
                    domain=domain,
                    email=email,
                    dns_provider=dns_provider,
                    account_id=account_id
                )
                
                return {
                    'message': f'Certificate created successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'duration': result.get('duration')
                }, 201
                
            except Exception as e:
                logger.error(f"Certificate creation failed: {str(e)}")
                return {'error': f'Certificate creation failed: {str(e)}'}, 500

    class DownloadCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_auth
        def get(self, domain):
            """Download certificate files as ZIP"""
            try:
                cert_dir = Path(file_ops.cert_dir) / domain
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}'}, 404
                
                # Create temporary ZIP file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                    with zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for cert_file in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
                            file_path = cert_dir / cert_file
                            if file_path.exists():
                                zipf.write(file_path, cert_file)
                    
                    return send_file(
                        tmp_file.name,
                        as_attachment=True,
                        download_name=f'{domain}_certificates.zip',
                        mimetype='application/zip'
                    )
                    
            except Exception as e:
                logger.error(f"Error downloading certificate for {domain}: {e}")
                return {'error': 'Failed to download certificate'}, 500

    class RenewCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_auth
        def post(self, domain):
            """Renew an existing certificate"""
            try:
                result = certificate_manager.renew_certificate(domain)
                
                return {
                    'message': f'Certificate renewed successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'duration': result.get('duration')
                }, 200
                
            except Exception as e:
                logger.error(f"Certificate renewal failed for {domain}: {str(e)}")
                return {'error': f'Certificate renewal failed: {str(e)}'}, 500

    # Backup endpoints
    class BackupList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['backup_list_model'])
        @auth_manager.require_auth
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
            'type': fields.String(required=True, enum=['settings', 'certificates', 'both'], 
                                   description='Type of backup to create'),
            'reason': fields.String(description='Reason for backup creation', default='manual')
        }))
        @auth_manager.require_auth
        def post(self):
            """Create a new backup"""
            try:
                data = api.payload
                backup_type = data.get('type', 'both')
                reason = data.get('reason', 'manual')
                
                created_backups = []
                
                if backup_type in ['settings', 'both']:
                    settings = settings_manager.load_settings()
                    filename = file_ops.create_settings_backup(settings, reason)
                    if filename:
                        created_backups.append({'type': 'settings', 'filename': filename})
                
                if backup_type in ['certificates', 'both']:
                    filename = file_ops.create_certificates_backup(reason)
                    if filename:
                        created_backups.append({'type': 'certificates', 'filename': filename})
                
                if created_backups:
                    return {
                        'message': 'Backup created successfully',
                        'backups': created_backups
                    }, 201
                else:
                    return {'error': 'Failed to create backup'}, 500
                    
            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                return {'error': 'Failed to create backup'}, 500

    class BackupDownload(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_auth
        def get(self, backup_type, filename):
            """Download a backup file"""
            try:
                if backup_type not in ['settings', 'certificates']:
                    return {'error': 'Invalid backup type'}, 400
                
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
                
            except Exception as e:
                logger.error(f"Error downloading backup: {e}")
                return {'error': 'Failed to download backup'}, 500

    class BackupRestore(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupRestoreRequest', {
            'filename': fields.String(required=True, description='Backup filename to restore from'),
            'create_backup_before_restore': fields.Boolean(description='Create backup before restore', default=True)
        }))
        @auth_manager.require_auth
        def post(self, backup_type):
            """Restore from a backup file"""
            try:
                if backup_type not in ['settings', 'certificates']:
                    return {'error': 'Invalid backup type'}, 400
                
                data = api.payload
                filename = data.get('filename')
                create_backup = data.get('create_backup_before_restore', True)
                
                if not filename:
                    return {'error': 'Filename is required'}, 400
                
                backup_path = Path(file_ops.backup_dir) / backup_type / filename
                
                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404
                
                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                    return {'error': 'Access denied'}, 403
                
                # Create backup of current state if requested
                pre_restore_backup = None
                if create_backup:
                    if backup_type == 'settings':
                        current_settings = settings_manager.load_settings()
                        pre_restore_backup = file_ops.create_settings_backup(current_settings, "pre_restore")
                    elif backup_type == 'certificates':
                        pre_restore_backup = file_ops.create_certificates_backup("pre_restore")
                
                # Restore from backup
                if backup_type == 'settings':
                    success = file_ops.restore_settings_backup(str(backup_path))
                elif backup_type == 'certificates':
                    success = file_ops.restore_certificates_backup(str(backup_path))
                else:
                    success = False
                
                if success:
                    response = {
                        'message': f'{backup_type.title()} restored successfully from {filename}',
                        'restored_from': filename
                    }
                    if pre_restore_backup:
                        response['pre_restore_backup'] = pre_restore_backup
                    return response, 200
                else:
                    return {'error': f'Failed to restore {backup_type}'}, 500
                    
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
                return {'error': f'Failed to restore backup: {str(e)}'}, 500

    # Return all resource classes
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
        'BackupRestore': BackupRestore
    }
