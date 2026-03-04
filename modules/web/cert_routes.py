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
    def create_certificate_web():
        """Create certificate via web"""
        try:
            data = request.json
            domain = data.get('domain')
            provider = data.get('provider')
            if not domain or not provider:
                return jsonify({'error': 'Domain and provider required'}), 400

            success, message = certificate_manager.create_certificate(
                domain, provider)
            if success:
                return jsonify({'message': message})
            return jsonify({'error': message}), 400
        except Exception as e:
            logger.error(f"Failed to create certificate: {e}")
            return jsonify({'error': 'Failed to create certificate'}), 500

    @app.route('/api/web/certificates/batch', methods=['POST'])
    def batch_create_web():
        """Batch create certificates"""
        try:
            data = request.json
            domains = data.get('domains', [])
            provider = data.get('provider')
            if not domains or not provider:
                return jsonify({'error': 'Domains and provider required'}), 400

            results = []
            for domain in domains:
                success, message = certificate_manager.create_certificate(
                    domain, provider)
                results.append({
                    'domain': domain, 'success': success, 'message': message
                })
            return jsonify(results)
        except Exception as e:
            logger.error(f"Batch creation failed: {e}")
            return jsonify({'error': 'Batch creation failed'}), 500

    @app.route('/api/web/certificates/download/batch', methods=['POST'])
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
                    cert_path = certificate_manager.get_certificate_path(
                        domain)
                    if os.path.exists(cert_path):
                        zf.write(cert_path, arcname=f"{domain}.crt")

            @after_this_request
            def cleanup(response):
                try:
                    os.remove(temp_zip.name)
                except Exception as e:
                    logger.error(f"Cleanup failed: {e}")
                return response

            return send_file(temp_zip.name, as_attachment=True,
                             download_name='certificates.zip')
        except Exception as e:
            logger.error(f"Batch download failed: {e}")
            return jsonify({'error': 'Batch download failed'}), 500

    @app.route('/api/web/certificates/dns-providers', methods=['GET'])
    def list_dns_providers_web():
        """List available DNS providers"""
        try:
            providers = dns_manager.get_available_providers()
            return jsonify(providers)
        except Exception as e:
            logger.error(f"Failed to list DNS providers: {e}")
            return jsonify({'error': 'Failed to list DNS providers'}), 500

    @app.route('/api/web/certificates/test-provider', methods=['POST'])
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
