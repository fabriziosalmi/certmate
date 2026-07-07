import logging
import zipfile
import tempfile
import os
from flask import request, jsonify, send_file, after_this_request

from ..core.certificates import DomainOperationInProgress
from ..core.cert_service import CertificateService, DomainOutOfScope
from ..core.audit_context import audit_context_from_request


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
            logger.info("Certificate creation rejected: %s", e)
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
                    # Log the detail; return a generic per-item message so raw
                    # exception text (non-certbot ValueError/IO) never reaches
                    # the client. Mirrors the single-cert path's non-disclosure.
                    logger.warning("Batch create failed for %s: %s",
                                   str(domain).replace('\n', ' ').replace('\r', ' '),
                                   str(e).replace('\n', ' ').replace('\r', ' '))
                    results.append({'domain': domain, 'success': False, 'message': 'Certificate creation failed'})

            # Register every successfully-created domain for automatic renewal.
            # This path calls certificate_manager.create_certificate directly
            # (fast, no per-domain settings write), but that low-level call does
            # NOT append the domain to settings['domains'] — only
            # CertificateService does. check_renewals iterates ONLY that list,
            # so without this, batch-created certs were never renewed and
            # expired ~90 days later with no warning. One settings.update (not
            # one per domain) avoids running a full pre-save backup 50 times.
            created_domains = [r['domain'] for r in results if r.get('success')]
            if created_domains:
                account_id = data.get('account_id')

                def _register_batch(s):
                    domains_list = s.get('domains', []) or []
                    present = {
                        (d if isinstance(d, str) else d.get('domain'))
                        for d in domains_list
                    }
                    for d in created_domains:
                        if d in present:
                            continue
                        domains_list.append({
                            'domain': d,
                            'dns_provider': dns_provider,
                            'dns_account_id': account_id,
                        })
                        present.add(d)
                    s['domains'] = domains_list

                try:
                    settings_manager.update(_register_batch, 'certificate_created')
                except Exception as e:
                    # Certs exist but tracking failed — surface it loudly rather
                    # than let them silently fall out of the renewal loop.
                    logger.error(
                        "Batch certs created but domain registration for renewal "
                        "failed (%d domains may not auto-renew): %s",
                        len(created_domains), e,
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
            data = request.json or {}
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
