import logging
import zipfile
import tempfile
import os
from flask import request, jsonify, send_file, after_this_request

from ..core.certificates import DomainOperationInProgress
from ..core.cert_service import CertificateService, DomainOutOfScope
from ..core.audit_context import audit_context_from_request
from modules.core.auth import not_for_domain_restricted_keys
from modules.core.request_fields import json_booleans
from modules.core.structured_logging import scrub_log_value


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
        audit_logger=audit_logger, event_bus=managers.get('events'),
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
                ca_account_id=data.get('ca_account_id'),
                challenge_type=data.get('challenge_type'),
                domain_alias=data.get('domain_alias'),
                user=user,
                ip_address=request.remote_addr,
                audit_ctx=audit_context_from_request(),
            )
            return jsonify(result)
        except DomainOutOfScope:
            return jsonify({'error': 'API key not authorized for this domain', 'code': 'DOMAIN_OUT_OF_SCOPE'}), 403
        except FileExistsError:
            # "Already exists" is a distinct, expected condition — 409 with a
            # reissue hint, not a generic 400 (matches the flask-restx path).
            return jsonify({'error': 'A certificate already exists for this domain. Use reissue to replace it.', 'code': 'CERTIFICATE_ALREADY_EXISTS'}), 409
        except ValueError as e:
            # Log the specific reason; return a generic message so the caught
            # exception text never reaches the client (CodeQL py/stack-trace-exposure).
            logger.info("Certificate creation rejected: %s", scrub_log_value(e))
            return jsonify({'error': 'Invalid certificate request'}), 400
        except DomainOperationInProgress:
            return jsonify({'error': 'A certificate operation is already in progress for this domain', 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}), 409
        except RuntimeError as e:
            logger.error(f"Certificate creation failed: {e}")
            return jsonify({'error': 'Certificate creation failed'}), 422
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
            if not isinstance(domains, list):
                # A string would be walked character by character.
                return jsonify({'error': 'domains must be a list'}), 400
            if len(domains) > 50:
                return jsonify({'error': 'Batch size limit exceeded: maximum 50 domains per request'}), 400

            settings = settings_manager.load_settings()
            if not settings.get('email'):
                return jsonify({'error': 'Email not configured. Set it in Settings first.'}), 400

            # Each domain through the service's own create steps (account,
            # scope, audit, event), registered in ONE settings write (#666,
            # D9). This route used to call the manager directly and dropped
            # account_id on the way to issuance.
            results = cert_service.create_batch(
                domains=domains,
                dns_provider=data.get('dns_provider'),
                account_id=data.get('account_id'),
                ca_provider=data.get('ca_provider'),
                ca_account_id=data.get('ca_account_id'),
                challenge_type=data.get('challenge_type'),
                user=getattr(request, 'current_user', None) or {},
                ip_address=request.remote_addr,
                audit_ctx=audit_context_from_request(),
            )
            return jsonify(results)
        except Exception as e:
            logger.error(f"Batch creation failed: {e}")
            return jsonify({'error': 'Batch creation failed'}), 500

    @app.route('/api/web/certificates/download/batch', methods=['POST'])
    @auth_manager.require_role('viewer')
    def download_batch_web():
        """Download multiple certificates as zip"""
        try:
            data = request.json or {}
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
                    # Every name the certificate covers, as for the single
                    # download: what it holds is valid for all of them.
                    if scope is not None and not certificate_manager.every_name_matches(
                            cert_dir.name,
                            lambda name: auth_manager.domain_matches_scope(name, scope)):
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
                    # Bundle the full chain (cert + intermediates) as
                    # <domain>.crt. Cert-only by design — a bulk export must not
                    # leak private keys. (Fixes a 500: certificate_manager has no
                    # get_certificate_path(); cert_dir is already the domain dir.)
                    cert_path = cert_dir / 'fullchain.pem'
                    if cert_path.exists():
                        zf.write(str(cert_path), arcname=f"{cert_dir.name}.crt")

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
    @not_for_domain_restricted_keys(audit_logger, 'dns_providers', 'the DNS provider accounts')
    def list_dns_providers_web():
        """List available DNS providers. Refused to a key restricted to
        domains, as the API's twin is: the accounts are the instance's."""
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
            data = request.json or {}
            provider = data.get('provider')
            config = data.get('config', {})
            if not provider:
                return jsonify({'error': 'Provider name required'}), 400

            # An explicit config always wins. Without one, test the stored
            # account (body 'account_id', or the same default-account
            # resolution issuance uses) so a preflight like
            # `certmate dns test cloudflare` can succeed against a
            # configured server instead of always failing on empty config.
            # No stored account leaves config empty -> the usual 400.
            used_account = None
            if not config:
                stored_config, used_account = dns_manager.get_dns_provider_account_config(
                    provider, data.get('account_id'))
                if stored_config:
                    config = stored_config

            success, message = dns_manager.test_provider(provider, config)
            if success:
                response = {'message': message}
                if used_account:
                    response['used_account'] = used_account
                return jsonify(response)
            return jsonify({'error': message}), 400
        except Exception as e:
            logger.error(f"Provider test failed: {e}")
            return jsonify({'error': 'Provider test failed'}), 500

    @app.route('/api/web/certificates/<string:domain>/renew', methods=['POST'])
    @auth_manager.require_role('operator')
    @json_booleans(force=False)
    def renew_certificate_web(domain):
        """Renew certificate via web"""
        try:
            cert_dir, error = _sanitize_domain(domain, file_ops.cert_dir)
            if error:
                return jsonify({'error': error}), 400

            # Use the directory name (domain) for renewal
            domain_name = cert_dir.name
            force = request.json_booleans['force']
            user = getattr(request, 'current_user', None) or {}
            result = cert_service.renew(
                domain=domain_name, force=force,
                user=user, ip_address=request.remote_addr,
                audit_ctx=audit_context_from_request(),
            )
            # 'renewed' distinguishes a real renewal from certbot's "not yet
            # due" no-op; the manager's message already states which happened.
            # Default True preserves the response contract for older results.
            return jsonify({
                'message': result.get('message', 'Certificate renewed successfully'),
                'renewed': bool(result.get('renewed', True)),
            })
        except DomainOutOfScope:
            return jsonify({'error': 'API key not authorized for this domain', 'code': 'DOMAIN_OUT_OF_SCOPE'}), 403
        except FileNotFoundError as e:
            logger.info("Certificate renewal target not found: %s", e)
            return jsonify({'error': 'Certificate not found'}), 404
        except DomainOperationInProgress:
            return jsonify({'error': 'A certificate operation is already in progress for this domain', 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}), 409
        except RuntimeError as e:
            # Surface WHY (and flag the broken-renewal-config case with a reissue
            # hint) instead of an opaque message. See classify_renewal_error.
            logger.error(f"Certificate renewal failed: {e}")
            from ..core.utils import classify_renewal_error
            message, code = classify_renewal_error(str(e))
            return jsonify({'error': message, 'code': code}), 422
        except Exception as e:
            logger.error(f"Certificate renewal failed via web: {str(e)}")
            return jsonify({'error': 'Certificate renewal failed'}), 500
