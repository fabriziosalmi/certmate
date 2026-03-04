import json
import logging
import os
import re
import tempfile
import zipfile
import concurrent.futures
from datetime import datetime
from functools import wraps
from pathlib import Path
from collections import defaultdict
from time import time
from flask import render_template, request, jsonify, send_file, send_from_directory, redirect, url_for, after_this_request, Response, stream_with_context

logger = logging.getLogger(__name__)

def register_cert_routes(app, managers, require_web_auth, auth_manager, certificate_manager, _sanitize_domain, file_ops, settings_manager, dns_manager, _cert_executor, CERTIFICATE_FILES):
    # Special download endpoint for easy automation
    @app.route('/<string:domain>/tls')
    @auth_manager.require_role('viewer')
    def download_tls(domain):
        """Download all TLS certificate files as a ZIP archive for automation"""
        try:
            cert_path, err = _sanitize_domain(domain, file_ops.cert_dir)
            if err:
                return jsonify({'error': err}), 400

            # Verify at least one certificate file exists
            existing_files = [f for f in CERTIFICATE_FILES if (cert_path / f).exists()]
            if not existing_files:
                return jsonify({'error': f'Certificate not found for domain: {domain}'}), 404

            # Build ZIP file with all certificate components
            import tempfile
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            tmp_path = tmp.name
            tmp.close()

            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for cert_file in CERTIFICATE_FILES:
                    file_path = cert_path / cert_file
                    if file_path.exists():
                        zipf.write(file_path, cert_file)

            return send_file(
                tmp_path,
                as_attachment=True,
                download_name=f'{domain}_certificates.zip',
                mimetype='application/zip'
            )

        except Exception as e:
            logger.error(f"Error downloading TLS certificate for {domain}: {e}")
            return jsonify({'error': 'Failed to download certificate'}), 500

    @app.route('/<string:domain>/tls/<string:component>')
    @auth_manager.require_role('viewer')
    def download_tls_component(domain, component):
        """Download individual TLS certificate component (cert, key, chain, fullchain)"""
        try:
            # Map component names to filenames
            component_map = {
                'cert': 'cert.pem',
                'key': 'privkey.pem',
                'chain': 'chain.pem',
                'fullchain': 'fullchain.pem',
            }

            filename = component_map.get(component)
            if not filename:
                return jsonify({
                    'error': f'Unknown certificate component: {component}',
                    'valid_components': list(component_map.keys())
                }), 400

            cert_path, err = _sanitize_domain(domain, file_ops.cert_dir)
            if err:
                return jsonify({'error': err}), 400

            file_path = cert_path / filename
            if not file_path.exists():
                return jsonify({'error': f'{component} not found for domain: {domain}'}), 404

            return send_file(
                file_path,
                as_attachment=True,
                download_name=f'{domain}_{filename}',
                mimetype='application/x-pem-file'
            )

        except Exception as e:
            logger.error(f"Error downloading TLS {component} for {domain}: {e}")
            return jsonify({'error': f'Failed to download {component}'}), 500

    # Web Certificate API Routes (for form-based frontend)
    @app.route('/api/web/certificates')
    @auth_manager.require_role('viewer')
    def web_list_certificates():
        """Web interface endpoint to list certificates"""
        try:
            settings = settings_manager.load_settings()
            certificates = []
            
            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])
            
            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            cert_dir = certificate_manager.cert_dir
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
    @auth_manager.require_role('operator')
    def web_create_certificate():
        """Web interface endpoint to create certificate"""
        try:
            # Handle both form data and JSON
            if request.is_json:
                data = request.json
            else:
                data = request.form.to_dict()
            
            domain = data.get('domain', '').strip()
            san_domains_raw = data.get('san_domains', '')  # Can be comma-separated string or list
            dns_provider = data.get('dns_provider')  # Optional, uses default from settings
            account_id = data.get('account_id')      # Optional, uses default account
            ca_provider = data.get('ca_provider')    # Optional, uses default from settings
            challenge_type = data.get('challenge_type')  # Optional: 'dns-01' or 'http-01'
            
            # Parse SAN domains (support both comma-separated string and list)
            san_domains = []
            if san_domains_raw:
                if isinstance(san_domains_raw, list):
                    san_domains = [d.strip() for d in san_domains_raw if d.strip()]
                elif isinstance(san_domains_raw, str):
                    san_domains = [d.strip() for d in san_domains_raw.split(',') if d.strip()]
            
            # Validate domain
            if not domain:
                return jsonify({
                    'error': 'Domain is required',
                    'hint': 'Please enter a valid domain name (e.g., example.com or *.example.com for wildcard)'
                }), 400
            
            # Basic domain validation
            if ' ' in domain:
                return jsonify({
                    'error': 'Invalid domain format',
                    'hint': 'Enter the primary domain name only. Use the SAN domains field for additional domains.'
                }), 400
            
            # Check for common domain format issues
            if domain.startswith('http://') or domain.startswith('https://'):
                return jsonify({
                    'error': 'Invalid domain format',
                    'hint': 'Enter domain name only (e.g., example.com), not the full URL.'
                }), 400
            
            settings = settings_manager.load_settings()
            email = settings.get('email')
            
            if not email:
                return jsonify({
                    'error': 'Email not configured',
                    'hint': 'Go to Settings and configure your email address first. This is required by certificate authorities.'
                }), 400
            
            # Resolve challenge type from settings if not provided
            if not challenge_type:
                challenge_type = settings.get('challenge_type', 'dns-01')

            # DNS provider validation (skip for HTTP-01)
            if challenge_type != 'http-01':
                # Determine DNS provider
                if not dns_provider:
                    dns_provider = settings_manager.get_domain_dns_provider(domain, settings)

                if not dns_provider:
                    return jsonify({
                        'error': 'No DNS provider configured',
                        'hint': 'Go to Settings and select a DNS provider. Configure the provider credentials to enable certificate creation.'
                    }), 400

                # Validate DNS provider configuration exists
                dns_providers_config = settings.get('dns_providers', {})
                provider_config = dns_providers_config.get(dns_provider, {})

                # Check if account_id is provided, validate it exists
                if account_id:
                    config, _ = dns_manager.get_dns_provider_account_config(dns_provider, account_id)
                    if not config:
                        available_accounts = list(dns_manager.list_dns_provider_accounts(dns_provider).keys())
                        hint = f"Available accounts: {', '.join(available_accounts)}" if available_accounts else "Configure a DNS account in Settings first."
                        return jsonify({
                            'error': f'DNS account "{account_id}" not found for provider {dns_provider}',
                            'hint': hint
                        }), 400
                else:
                    # Check if default account is configured
                    config, _ = dns_manager.get_dns_provider_account_config(dns_provider, None)
                    if not config:
                        # Check if there are any accounts for this provider
                        accounts = dns_manager.list_dns_provider_accounts(dns_provider)
                        if not accounts:
                            return jsonify({
                                'error': f'No {dns_provider} credentials configured',
                                'hint': f'Go to Settings → DNS Providers → {dns_provider.title()} and add your API credentials.'
                            }), 400
                        else:
                            return jsonify({
                                'error': f'No default account set for {dns_provider}',
                                'hint': f'Select an account or configure a default account in Settings for {dns_provider}.'
                            }), 400
            
            # All validations passed, create certificate in background (bounded pool)
            def create_cert_async():
                try:
                    certificate_manager.create_certificate(
                        domain, email, dns_provider,
                        account_id=account_id,
                        ca_provider=ca_provider if ca_provider else None,
                        san_domains=san_domains if san_domains else None,
                        challenge_type=challenge_type
                    )
                    domains_info = f"{domain}" + (f" (+ {len(san_domains)} SANs)" if san_domains else "")
                    logger.info(f"Background certificate creation completed for {domains_info}")
                except Exception as e:
                    logger.error(f"Background certificate creation failed for {domain}: {e}")
                    evt = managers.get('events')
                    if evt:
                        evt.publish('certificate_failed', {'domain': domain, 'error': str(e)})

            _cert_executor.submit(create_cert_async)
            
            # Build response message
            if san_domains:
                msg = f'Certificate creation started for {domain} with {len(san_domains)} additional SAN(s)'
            else:
                msg = f'Certificate creation started for {domain}'
            
            # Publish SSE event
            event_bus = managers.get('events')
            if event_bus:
                event_bus.publish('certificate_created', {'domain': domain, 'san_domains': san_domains})

            return jsonify({
                'success': True,
                'message': msg,
                'domain': domain,
                'san_domains': san_domains,
                'dns_provider': dns_provider,
                'account_id': account_id
            })
            
        except Exception as e:
            logger.error(f"Certificate creation failed via web: {str(e)}")
            return jsonify({'error': 'Certificate creation failed'}), 500

    @app.route('/api/web/certificates/<string:domain>/download')
    @auth_manager.require_role('viewer')
    def web_download_certificate(domain):
        """Web interface endpoint to download certificate as ZIP file"""
        try:
            cert_dir, err = _sanitize_domain(domain, file_ops.cert_dir)
            if err:
                return jsonify({'error': err}), 400
            if not cert_dir.exists():
                return jsonify({'error': f'Certificate not found for domain: {domain}'}), 404

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
            logger.error(f"Error downloading certificate via web: {e}")
            return jsonify({'error': 'Failed to download certificate'}), 500

    @app.route('/api/web/certificates/<string:domain>/renew', methods=['POST'])
    @auth_manager.require_role('operator')
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
                    evt = managers.get('events')
                    if evt:
                        evt.publish('certificate_failed', {'domain': domain, 'error': str(e)})

            _cert_executor.submit(renew_cert_async)

            event_bus = managers.get('events')
            if event_bus:
                event_bus.publish('certificate_renewed', {'domain': domain})

            return jsonify({'success': True, 'message': f'Certificate renewal started for {domain}'})
            
        except Exception as e:
            logger.error(f"Certificate renewal failed via web: {str(e)}")
            return jsonify({'error': 'Certificate renewal failed'}), 500

