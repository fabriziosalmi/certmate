import logging
import zipfile
import tempfile
import os
from flask import request, jsonify, send_file, after_this_request


logger = logging.getLogger(__name__)


def register_cert_routes(app, managers, require_web_auth, auth_manager,
                         certificate_manager, _sanitize_domain, file_ops,
                         settings_manager, dns_manager, CERTIFICATE_FILES):
    """Register certificate-related routes"""

    @app.route('/api/certificates', methods=['GET'])
    @app.route('/api/web/certificates', methods=['GET'])
    @auth_manager.require_role('viewer')
    def list_certificates_web():
        """List all certificates via web"""
        try:
            certs = certificate_manager.list_certificates()
            return jsonify(certs)
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            return jsonify({'error': 'Failed to list certificates'}), 500

    @app.route('/api/certificates/create', methods=['POST'])
    @app.route('/api/web/certificates/create', methods=['POST'])
    @auth_manager.require_role('operator')
    def create_certificate_web():
        """Create certificate via web"""
        try:
            data = request.json or {}
            domain = (data.get('domain') or '').strip()
            san_domains = data.get('san_domains', [])
            dns_provider = data.get('dns_provider')
            account_id = data.get('account_id')
            ca_provider = data.get('ca_provider')
            challenge_type = data.get('challenge_type')
            domain_alias = data.get('domain_alias')

            if not domain:
                return jsonify({'error': 'Domain is required'}), 400

            settings = settings_manager.load_settings()
            email = settings.get('email')
            if not email:
                return jsonify({'error': 'Email not configured. Set it in Settings first.'}), 400

            if not ca_provider:
                ca_provider = settings.get('default_ca', 'letsencrypt')
            if not challenge_type:
                challenge_type = settings.get('challenge_type', 'dns-01')
            if challenge_type != 'http-01' and not dns_provider:
                dns_provider = settings.get('dns_provider')
                if not dns_provider:
                    return jsonify({'error': 'No DNS provider specified'}), 400

            result = certificate_manager.create_certificate(
                domain=domain,
                email=email,
                dns_provider=dns_provider,
                account_id=account_id,
                ca_provider=ca_provider,
                domain_alias=domain_alias,
                san_domains=san_domains,
                challenge_type=challenge_type,
            )

            # Append the new domain under the settings manager's lock so
            # two parallel cert creations cannot drop one of the entries.
            _resolved_dns_provider = dns_provider or settings.get('dns_provider')

            def _add_domain(s):
                domains_list = s.get('domains', []) or []
                already_present = any(
                    (d == domain if isinstance(d, str) else d.get('domain') == domain)
                    for d in domains_list
                )
                if already_present:
                    return
                domains_list.append({
                    'domain': domain,
                    'dns_provider': _resolved_dns_provider,
                    'dns_account_id': account_id,
                })
                s['domains'] = domains_list

            settings_manager.update(_add_domain, "certificate_created_web")
            logger.info(f"Ensured domain {domain} is in settings after certificate creation")

            return jsonify(result)
        except (ValueError, FileExistsError) as e:
            return jsonify({'error': str(e)}), 400
        except RuntimeError as e:
            logger.error(f"Certificate creation failed: {e}")
            return jsonify({'error': str(e)}), 422
        except Exception as e:
            logger.error(f"Failed to create certificate: {e}")
            return jsonify({'error': 'Failed to create certificate'}), 500

    @app.route('/api/web/certificates/batch', methods=['POST'])
    @auth_manager.require_role('operator')
    def batch_create_web():
        """Batch create certificates"""
        try:
            data = request.json or {}
            domains = data.get('domains', [])
            if not domains:
                return jsonify({'error': 'Domains list required'}), 400
            if len(domains) > 50:
                return jsonify({'error': 'Batch size limit exceeded: maximum 50 domains per request'}), 400

            settings = settings_manager.load_settings()
            email = settings.get('email')
            if not email:
                return jsonify({'error': 'Email not configured. Set it in Settings first.'}), 400

            dns_provider = data.get('dns_provider') or settings.get('dns_provider')
            ca_provider = data.get('ca_provider') or settings.get('default_ca', 'letsencrypt')
            challenge_type = data.get('challenge_type') or settings.get('challenge_type', 'dns-01')

            results = []
            for domain in domains:
                domain = (domain if isinstance(domain, str) else '').strip()
                if not domain:
                    continue
                try:
                    result = certificate_manager.create_certificate(
                        domain=domain, email=email,
                        dns_provider=dns_provider, ca_provider=ca_provider,
                        challenge_type=challenge_type,
                    )
                    results.append({'domain': domain, 'success': True, 'message': 'Certificate created'})
                except Exception as e:
                    results.append({'domain': domain, 'success': False, 'message': str(e)})
            return jsonify(results)
        except Exception as e:
            logger.error(f"Batch creation failed: {e}")
            return jsonify({'error': 'Batch creation failed'}), 500

    @app.route('/api/web/certificates/download/batch', methods=['POST'])
    @auth_manager.require_role('viewer')
    def download_batch_web():
        """Download multiple certificates as zip"""
        try:
            data = request.json
            domains = data.get('domains', [])
            if not domains:
                return jsonify({'error': 'Domains required'}), 400

            temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            temp_zip.close()

            with zipfile.ZipFile(temp_zip.name, 'w') as zf:
                for domain in domains:
                    cert_dir, error = _sanitize_domain(domain, file_ops.cert_dir)
                    if error:
                        continue
                    cert_path = certificate_manager.get_certificate_path(
                        cert_dir.name)
                    if os.path.exists(cert_path):
                        zf.write(cert_path, arcname=f"{cert_dir.name}.crt")

            @after_this_request
            def cleanup(response):
                try:
                    os.remove(temp_zip.name)
                except Exception as e:
                    logger.error(f"Cleanup failed: {e}")
                return response

            return send_file(temp_zip.name, as_attachment=True,
                             download_name='certificates.zip',
                             mimetype='application/zip')
        except Exception as e:
            logger.error(f"Batch download failed: {e}")
            return jsonify({'error': 'Batch download failed'}), 500

    @app.route('/api/web/certificates/dns-providers', methods=['GET'])
    @auth_manager.require_role('viewer')
    def list_dns_providers_web():
        """List available DNS providers"""
        try:
            providers = dns_manager.get_available_providers()
            return jsonify(providers)
        except Exception as e:
            logger.error(f"Failed to list DNS providers: {e}")
            return jsonify({'error': 'Failed to list DNS providers'}), 500

    @app.route('/api/web/certificates/test-provider', methods=['POST'])
    @auth_manager.require_role('admin')
    def test_dns_provider_web():
        """Test DNS provider configuration"""
        try:
            data = request.json
            provider = data.get('provider')
            config = data.get('config', {})
            if not provider:
                return jsonify({'error': 'Provider name required'}), 400

            success, message = dns_manager.test_provider(provider, config)
            if success:
                return jsonify({'message': message})
            return jsonify({'error': message}), 400
        except Exception as e:
            logger.error(f"Provider test failed: {e}")
            return jsonify({'error': 'Provider test failed'}), 500

    @app.route('/api/web/certificates/<string:domain>/renew', methods=['POST'])
    @auth_manager.require_role('operator')
    def renew_certificate_web(domain):
        """Renew certificate via web"""
        try:
            cert_dir, error = _sanitize_domain(domain, file_ops.cert_dir)
            if error:
                return jsonify({'error': error}), 400

            # Use the directory name (domain) for renewal
            domain_name = cert_dir.name
            success, message = certificate_manager.renew_certificate(domain_name)
            if success:
                return jsonify({'message': message})
            return jsonify({'error': message}), 400
        except Exception as e:
            logger.error(f"Certificate renewal failed via web: {str(e)}")
            return jsonify({'error': 'Certificate renewal failed'}), 500
