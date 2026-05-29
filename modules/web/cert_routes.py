import logging
import zipfile
import tempfile
import os
from flask import request, jsonify, send_file, after_this_request

from ..core.certificates import DomainOperationInProgress
from ..core.cert_service import CertificateService, DomainOutOfScope


logger = logging.getLogger(__name__)


def register_cert_routes(app, managers, require_web_auth, auth_manager,
                         certificate_manager, _sanitize_domain, file_ops,
                         settings_manager, dns_manager, CERTIFICATE_FILES):
    """Register certificate-related routes"""
    audit_logger = managers.get('audit')
    # Shared create/renew orchestration; production wires a single instance via
    # the container, the fallback keeps standalone route tests working.
    cert_service = managers.get('cert_service') or CertificateService(
        certificate_manager, settings_manager, auth_manager,
        audit_logger=audit_logger,
    )

    # NOTE: only the /api/web/... path is registered here. The bare
    # /api/certificates/create is owned by the flask-restx CreateCertificate
    # resource (registered first in setup_api, so it always won the duplicate
    # rule anyway); binding it here too was dead, shadowed code.
    @app.route('/api/web/certificates/create', methods=['POST'])
    @auth_manager.require_role('operator')
    def create_certificate_web():
        """Create certificate via web"""
        try:
            data = request.json or {}
            domain = (data.get('domain') or '').strip()
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400

            user = getattr(request, 'current_user', None) or {}
            result = cert_service.create(
                domain=domain,
                san_domains=data.get('san_domains', []),
                dns_provider=data.get('dns_provider'),
                account_id=data.get('account_id'),
                ca_provider=data.get('ca_provider'),
                challenge_type=data.get('challenge_type'),
                domain_alias=data.get('domain_alias'),
                user=user,
                ip_address=request.remote_addr,
            )
            return jsonify(result)
        except DomainOutOfScope as e:
            return jsonify({'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}), 403
        except (ValueError, FileExistsError) as e:
            return jsonify({'error': str(e)}), 400
        except DomainOperationInProgress as e:
            return jsonify({'error': str(e), 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}), 409
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

            user = getattr(request, 'current_user', None) or {}
            scope = user.get('allowed_domains')

            from ..core.utils import validate_domain
            results = []
            for domain in domains:
                domain = (domain if isinstance(domain, str) else '').strip()
                if not domain:
                    continue
                # Structural validation BEFORE scope check so a poisoned
                # entry (e.g. "../escape") never even reaches the cert
                # manager or settings.json. Same gate the single-cert path
                # now applies.
                d_valid, d_msg = validate_domain(domain)
                if not d_valid:
                    results.append({
                        'domain': domain, 'success': False,
                        'message': f'Invalid domain: {d_msg}',
                    })
                    continue
                if not auth_manager.domain_matches_scope(domain, scope):
                    if audit_logger:
                        audit_logger.log_authz_denied(
                            operation='batch_create',
                            resource_type='certificate',
                            resource_id=domain,
                            reason='domain outside scoped key allowed_domains',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    results.append({
                        'domain': domain, 'success': False,
                        'message': 'API key not authorized for this domain',
                    })
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

            user = getattr(request, 'current_user', None) or {}
            scope = user.get('allowed_domains')

            with zipfile.ZipFile(temp_zip.name, 'w') as zf:
                for domain in domains:
                    cert_dir, error = _sanitize_domain(domain, file_ops.cert_dir)
                    if error:
                        continue
                    if not auth_manager.domain_matches_scope(cert_dir.name, scope):
                        if audit_logger:
                            audit_logger.log_authz_denied(
                                operation='batch_download',
                                resource_type='certificate',
                                resource_id=cert_dir.name,
                                reason='domain outside scoped key allowed_domains',
                                user=user.get('username'),
                                ip_address=request.remote_addr,
                            )
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
            force = bool((request.get_json(silent=True) or {}).get('force', False))
            user = getattr(request, 'current_user', None) or {}
            result = cert_service.renew(
                domain=domain_name, force=force,
                user=user, ip_address=request.remote_addr,
            )
            return jsonify({'message': result.get('message', 'Certificate renewed successfully')})
        except DomainOutOfScope as e:
            return jsonify({'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}), 403
        except FileNotFoundError as e:
            return jsonify({'error': str(e)}), 404
        except DomainOperationInProgress as e:
            return jsonify({'error': str(e), 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}), 409
        except RuntimeError as e:
            logger.error(f"Certificate renewal failed: {e}")
            return jsonify({'error': str(e)}), 422
        except Exception as e:
            logger.error(f"Certificate renewal failed via web: {str(e)}")
            return jsonify({'error': 'Certificate renewal failed'}), 500
