"""
Web routes module for CertMate
Handles web interface routes and form-based endpoints
"""

import logging
import tempfile
import zipfile
import threading
from datetime import datetime
from pathlib import Path
from flask import render_template, request, jsonify, send_file, send_from_directory

from ..core.metrics import generate_metrics_response

logger = logging.getLogger(__name__)


def register_web_routes(app, managers):
    """Register all web interface routes
    
    Args:
        app: Flask app instance
        managers: Dictionary of manager instances
    """
    
    auth_manager = managers['auth']
    settings_manager = managers['settings']
    certificate_manager = managers['certificates']
    file_ops = managers['file_ops']
    cache_manager = managers['cache']
    dns_manager = managers['dns']
    
    # Static file routes
    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon"""
        return send_from_directory(app.static_folder or '.', 'favicon.ico')

    # Main web interface routes
    @app.route('/')
    def index():
        """Main dashboard page"""
        try:
            settings = settings_manager.load_settings()
            certificates = []
            
            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])
            
            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            cert_dir = certificate_manager._get_cert_dir_compat()
            if cert_dir.exists():
                cert_dirs = [d for d in cert_dir.iterdir() if d.is_dir()]
            
            # Create a set of all domains to check (from settings and disk)
            all_domains = set()
            
            # Add domains from settings
            for domain_config in domains_from_settings:
                if isinstance(domain_config, str):
                    domain_name = domain_config
                elif isinstance(domain_config, dict):
                    domain_name = domain_config.get('domain')
                else:
                    continue
                if domain_name:
                    all_domains.add(domain_name)
            
            # Add domains from disk (for backward compatibility with existing certificates)
            for cert_dir_path in cert_dirs:
                all_domains.add(cert_dir_path.name)
            
            # Get certificate info for all domains
            for domain_name in all_domains:
                if domain_name:
                    cert_info = certificate_manager.get_certificate_info(domain_name)
                    if cert_info:
                        certificates.append(cert_info)
            
            api_token = settings.get('api_bearer_token', '')
            return render_template('index.html', certificates=certificates, api_token=api_token)
        except Exception as e:
            logger.error(f"Failed to load settings for index page: {e}")
            return render_template('index.html', certificates=[], api_token='')

    @app.route('/settings')
    def settings_page():
        """Settings configuration page"""
        try:
            settings = settings_manager.load_settings()
            api_token = settings.get('api_bearer_token', '')
            return render_template('settings.html', api_token=api_token)
        except Exception as e:
            logger.error(f"Failed to load settings for settings page: {e}")
            return render_template('settings.html', api_token='')

    @app.route('/help')
    def help_page():
        """Help and documentation page"""
        return render_template('help.html')

    # Health check for Docker
    @app.route('/health')
    def health_check():
        """Simple health check endpoint"""
        try:
            settings = settings_manager.load_settings()
            return jsonify({
                'status': 'healthy',
                'version': '1.2.1',
                'timestamp': str(datetime.now())
            })
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

    # Prometheus metrics endpoint
    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        try:
            return generate_metrics_response()
        except Exception as e:
            logger.error(f"Error generating metrics: {e}")
            return "# Error generating metrics\n", 500

    # Special download endpoint for easy automation
    @app.route('/<string:domain>/tls')
    @auth_manager.require_auth
    def download_tls(domain):
        """Simple TLS certificate download endpoint for automation"""
        try:
            cert_dir = Path(file_ops.cert_dir) / domain
            fullchain_path = cert_dir / "fullchain.pem"
            
            if not fullchain_path.exists():
                return jsonify({'error': f'Certificate not found for domain: {domain}'}), 404
            
            return send_file(
                fullchain_path,
                as_attachment=True,
                download_name=f'{domain}_fullchain.pem',
                mimetype='application/x-pem-file'
            )
            
        except Exception as e:
            logger.error(f"Error downloading TLS certificate for {domain}: {e}")
            return jsonify({'error': 'Failed to download certificate'}), 500

    # Web-specific settings endpoints (no auth required for initial setup)
    @app.route('/api/web/settings', methods=['GET', 'POST'])
    def web_settings():
        """Web interface settings endpoint"""
        if request.method == 'GET':
            try:
                settings = settings_manager.load_settings()
                
                # Check if setup is completed
                setup_completed = settings.get('setup_completed', False)
                
                # For initial setup, return minimal safe settings
                if not setup_completed:
                    return jsonify({
                        'setup_completed': False,
                        'email': settings.get('email', ''),
                        'dns_provider': settings.get('dns_provider', 'cloudflare'),
                        'auto_renew': settings.get('auto_renew', True),
                        'domains': []
                    })
                
                # For completed setup, require auth
                auth_header = request.headers.get('Authorization', '')
                if not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'Authentication required'}), 401
                
                token = auth_header[7:]
                if not auth_manager.validate_api_token(token):
                    return jsonify({'error': 'Invalid token'}), 401
                
                # Return full settings (with sensitive data masked)
                safe_settings = dict(settings)
                if 'api_bearer_token' in safe_settings:
                    token = safe_settings['api_bearer_token']
                    safe_settings['api_bearer_token'] = f"{token[:4]}...{token[-4:]}" if len(token) > 8 else "***"
                
                return jsonify(safe_settings)
                
            except Exception as e:
                logger.error(f"Error getting web settings: {e}")
                return jsonify({'error': 'Failed to load settings'}), 500
        
        elif request.method == 'POST':
            try:
                new_settings = request.json
                if not new_settings:
                    return jsonify({'error': 'No settings provided'}), 400
                
                # For initial setup, no auth required
                current_settings = settings_manager.load_settings()
                setup_completed = current_settings.get('setup_completed', False)
                
                if setup_completed:
                    # Require auth for updates after setup
                    auth_header = request.headers.get('Authorization', '')
                    if not auth_header.startswith('Bearer '):
                        return jsonify({'error': 'Authentication required'}), 401
                    
                    token = auth_header[7:]
                    if not auth_manager.validate_api_token(token):
                        return jsonify({'error': 'Invalid token'}), 401
                
                # Merge with existing settings
                merged_settings = {**current_settings, **new_settings}
                
                # Mark setup as completed if not already
                if not setup_completed and all(key in merged_settings and merged_settings[key] 
                                             for key in ['email', 'dns_provider']):
                    merged_settings['setup_completed'] = True
                
                # Save settings
                success = settings_manager.save_settings(merged_settings, "web_update")
                
                if success:
                    return jsonify({'message': 'Settings updated successfully'})
                else:
                    return jsonify({'error': 'Failed to save settings'}), 500
                    
            except Exception as e:
                logger.error(f"Error updating web settings: {e}")
                return jsonify({'error': 'Failed to update settings'}), 500

    # DNS Provider Account Management endpoints for web interface
    @app.route('/api/dns/<string:provider>/accounts', methods=['GET', 'POST'])
    @auth_manager.require_auth
    def web_dns_provider_accounts(provider):
        """Manage DNS provider accounts"""
        if request.method == 'GET':
            try:
                accounts = dns_manager.list_dns_provider_accounts(provider)
                return jsonify(accounts)
            except Exception as e:
                logger.error(f"Error listing DNS accounts for {provider}: {e}")
                return jsonify({'error': 'Failed to list DNS accounts'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                account_id = data.get('account_id')
                account_config = data.get('config', {})
                
                if not account_id:
                    return jsonify({'error': 'Account ID is required'}), 400
                
                success = dns_manager.create_dns_account(provider, account_id, account_config)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} created/updated successfully'})
                else:
                    return jsonify({'error': 'Failed to create/update DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error creating DNS account for {provider}: {e}")
                return jsonify({'error': 'Failed to create DNS account'}), 500

    @app.route('/api/dns/<string:provider>/accounts/<string:account_id>', methods=['GET', 'PUT', 'DELETE'])
    @auth_manager.require_auth
    def web_dns_provider_account(provider, account_id):
        """Manage specific DNS provider account"""
        if request.method == 'GET':
            try:
                config, _ = dns_manager.get_dns_provider_account_config(provider, account_id)
                if config:
                    return jsonify(config)
                else:
                    return jsonify({'error': 'Account not found'}), 404
            except Exception as e:
                logger.error(f"Error getting DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to get DNS account'}), 500
        
        elif request.method == 'PUT':
            try:
                account_config = request.json
                if not account_config:
                    return jsonify({'error': 'Account configuration is required'}), 400
                
                success = dns_manager.create_dns_account(provider, account_id, account_config)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} updated successfully'})
                else:
                    return jsonify({'error': 'Failed to update DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error updating DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to update DNS account'}), 500
        
        elif request.method == 'DELETE':
            try:
                success = dns_manager.delete_dns_account(provider, account_id)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error deleting DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to delete DNS account'}), 500

    # Web Certificate API Routes (for form-based frontend)
    @app.route('/api/web/certificates')
    @auth_manager.require_auth
    def web_list_certificates():
        """Web interface endpoint to list certificates"""
        try:
            settings = settings_manager.load_settings()
            certificates = []
            
            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])
            
            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            cert_dir = certificate_manager._get_cert_dir_compat()
            if cert_dir.exists():
                cert_dirs = [d for d in cert_dir.iterdir() if d.is_dir()]
            
            # Create a set of all domains to check (from settings and disk)
            all_domains = set()
            
            # Add domains from settings
            for domain_config in domains_from_settings:
                if isinstance(domain_config, str):
                    domain_name = domain_config
                elif isinstance(domain_config, dict):
                    domain_name = domain_config.get('domain')
                else:
                    continue
                if domain_name:
                    all_domains.add(domain_name)
            
            # Add domains from disk (for backward compatibility with existing certificates)
            for cert_dir_path in cert_dirs:
                all_domains.add(cert_dir_path.name)
            
            # Get certificate info for all domains
            for domain_name in all_domains:
                if domain_name:
                    cert_info = certificate_manager.get_certificate_info(domain_name)
                    if cert_info:
                        certificates.append(cert_info)
            
            return jsonify(certificates)
        except Exception as e:
            logger.error(f"Error fetching certificates via web: {e}")
            # Return empty array on error to ensure frontend compatibility
            return jsonify([])

    @app.route('/api/web/certificates/create', methods=['POST'])
    @auth_manager.require_auth
    def web_create_certificate():
        """Web interface endpoint to create certificate"""
        try:
            # Handle both form data and JSON
            if request.is_json:
                data = request.json
            else:
                data = request.form.to_dict()
            
            domain = data.get('domain')
            dns_provider = data.get('dns_provider')  # Optional, uses default from settings
            account_id = data.get('account_id')      # Optional, uses default account
            
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            
            settings = settings_manager.load_settings()
            email = settings.get('email')
            
            if not email:
                return jsonify({'error': 'Email not configured in settings'}), 400
            
            # Determine DNS provider
            if not dns_provider:
                dns_provider = settings_manager.get_domain_dns_provider(domain, settings)
            
            # Validate that the specified account exists (if provided)
            if account_id:
                config, _ = dns_manager.get_dns_provider_account_config(dns_provider, account_id)
                if not config:
                    return jsonify({'error': f'DNS account {account_id} not found for provider {dns_provider}'}), 400
            
            # Create certificate in background
            def create_cert_async():
                try:
                    certificate_manager.create_certificate(domain, email, dns_provider, account_id=account_id)
                    logger.info(f"Background certificate creation completed for {domain}")
                except Exception as e:
                    logger.error(f"Background certificate creation failed for {domain}: {e}")
            
            thread = threading.Thread(target=create_cert_async)
            thread.start()
            
            return jsonify({
                'success': True, 
                'message': f'Certificate creation started for {domain}',
                'domain': domain,
                'dns_provider': dns_provider,
                'account_id': account_id
            })
            
        except Exception as e:
            logger.error(f"Certificate creation failed via web: {str(e)}")
            return jsonify({'error': f'Certificate creation failed: {str(e)}'}), 500

    @app.route('/api/web/certificates/<string:domain>/download')
    @auth_manager.require_auth
    def web_download_certificate(domain):
        """Web interface endpoint to download certificate as ZIP file"""
        try:
            cert_dir = Path(file_ops.cert_dir) / domain
            if not cert_dir.exists():
                return jsonify({'error': f'Certificate not found for domain: {domain}'}), 404
            
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
            logger.error(f"Error downloading certificate via web: {e}")
            return jsonify({'error': 'Failed to download certificate'}), 500

    @app.route('/api/web/certificates/<string:domain>/renew', methods=['POST'])
    @auth_manager.require_auth
    def web_renew_certificate(domain):
        """Web interface endpoint to renew certificate"""
        try:
            settings = settings_manager.load_settings()
            
            # Check if domain exists in settings
            domain_exists = False
            for domain_config in settings.get('domains', []):
                if isinstance(domain_config, str) and domain_config == domain:
                    domain_exists = True
                    break
                elif isinstance(domain_config, dict) and domain_config.get('domain') == domain:
                    domain_exists = True
                    break
            
            if not domain_exists:
                return jsonify({'error': f'Domain {domain} not found in settings'}), 404
            
            # Renew certificate in background
            def renew_cert_async():
                try:
                    certificate_manager.renew_certificate(domain)
                    logger.info(f"Background certificate renewal completed for {domain}")
                except Exception as e:
                    logger.error(f"Background certificate renewal failed for {domain}: {e}")
            
            thread = threading.Thread(target=renew_cert_async)
            thread.start()
            
            return jsonify({'success': True, 'message': f'Certificate renewal started for {domain}'})
            
        except Exception as e:
            logger.error(f"Certificate renewal failed via web: {str(e)}")
            return jsonify({'error': f'Certificate renewal failed: {str(e)}'}), 500

    # Backup management endpoints
    @app.route('/api/web/backups')
    @auth_manager.require_auth
    def web_list_backups():
        """Web interface endpoint to list backups"""
        try:
            backups = file_ops.list_backups()
            return jsonify(backups)
        except Exception as e:
            logger.error(f"Error listing backups via web: {e}")
            return jsonify({'error': 'Failed to list backups'}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    @auth_manager.require_auth
    def web_create_backup():
        """Web interface endpoint to create backup"""
        try:
            data = request.json or {}
            backup_type = data.get('type', 'unified')
            reason = data.get('reason', 'manual')
            
            created_backups = []
            
            # Only create unified backups
            settings = settings_manager.load_settings()
            filename = file_ops.create_unified_backup(settings, reason)
            if filename:
                created_backups.append({'type': 'unified', 'filename': filename})
            
            if created_backups:
                return jsonify({
                    'success': True,
                    'message': 'Backup created successfully',
                    'backups': created_backups
                })
            else:
                return jsonify({'error': 'Failed to create backup'}), 500
                
        except Exception as e:
            logger.error(f"Error creating backup via web: {e}")
            return jsonify({'error': 'Failed to create backup'}), 500

    @app.route('/api/web/backups/download/<backup_type>/<filename>')
    @auth_manager.require_auth
    def web_download_backup(backup_type, filename):
        """Web interface endpoint to download unified backup"""
        try:
            if backup_type != 'unified':
                return jsonify({'error': 'Only unified backup download is supported'}), 400
            
            backup_path = Path(file_ops.backup_dir) / backup_type / filename
            
            if not backup_path.exists():
                return jsonify({'error': 'Backup file not found'}), 404
            
            # Security check
            if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                return jsonify({'error': 'Access denied'}), 403
            
            return send_file(
                backup_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
            
        except Exception as e:
            logger.error(f"Error downloading backup via web: {e}")
            return jsonify({'error': 'Failed to download backup'}), 500

    # Cache management endpoints
    @app.route('/api/web/cache/stats')
    def web_cache_stats():
        """Web interface endpoint to get cache statistics"""
        try:
            stats = cache_manager.get_cache_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error getting cache stats for web: {e}")
            return jsonify({'error': 'Failed to get cache statistics'}), 500

    @app.route('/api/web/cache/clear', methods=['POST'])
    def web_cache_clear():
        """Web interface endpoint to clear cache"""
        try:
            cleared_count = cache_manager.clear_cache()
            return jsonify({
                'success': True,
                'message': 'Cache cleared successfully',
                'cleared_entries': cleared_count
            })
        except Exception as e:
            logger.error(f"Error clearing cache for web: {e}")
            return jsonify({'error': 'Failed to clear cache'}), 500
