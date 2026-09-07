"""Issuing, renewing and reissuing a certificate, and the jobs that carry it.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as
an explicit `ApiContext`, which is what makes them importable — and
therefore testable — without constructing the whole manager graph.
"""
import logging

from flask import current_app, request
from flask_restx import Resource

from ..core.audit_context import audit_context_from_request
from ..core.cert_service import DomainOutOfScope
from ..core.certificates import DomainOperationInProgress
from ..core.utils import classify_renewal_error
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import (
    ApiContext, check_domain_scope, job_accepted, wants_async,
)

logger = logging.getLogger(__name__)


def create_lifecycle_resources(api, models, ctx: ApiContext) -> dict:
    """Build the lifecycle resources against *ctx*."""

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    def _wants_async(payload):
        return wants_async(payload)

    def _job_accepted(job_id, operation, domain):
        return job_accepted(job_id, operation, domain,
                            f'/api/certificates/jobs/{job_id}')

    class CreateCertificate(Resource):
        @api.doc(security='Bearer')
        @api.expect(models['create_cert_model'])
        @ctx.auth.require_role('operator')
        def post(self):
            """Create a new certificate"""
            try:
                data = api.payload or {}
                domain = (data.get('domain') or '').strip()
                san_domains = data.get('san_domains', [])
                if not domain:
                    return {
                        'error': 'Domain is required',
                        'hint': 'Please provide a valid domain name (e.g., example.com or *.example.com for wildcard)'
                    }, 400

                user = getattr(request, 'current_user', None) or {}
                audit_ctx = audit_context_from_request()

                # Async opt-in: validate + authorize synchronously (immediate
                # 4xx on bad input/scope/config), then defer the blocking
                # certbot issuance to the executor and return 202 + job id.
                if _wants_async(data) and ctx.cert_executor is not None:
                    prepared = ctx.cert_service.prepare_create(
                        domain=domain,
                        san_domains=san_domains,
                        dns_provider=data.get('dns_provider'),
                        account_id=data.get('account_id'),
                        ca_provider=data.get('ca_provider'),
                        challenge_type=data.get('challenge_type'),
                        domain_alias=data.get('domain_alias'),
                        key_type=data.get('key_type'),
                        key_size=data.get('key_size'),
                        elliptic_curve=data.get('elliptic_curve'),
                        user=user,
                        ip_address=request.remote_addr,
                        audit_ctx=audit_ctx,
                    )
                    job_id = ctx.cert_executor.submit(
                        'create', domain,
                        lambda: ctx.cert_service.issue_create(prepared),
                    )
                    return _job_accepted(job_id, 'create', domain), 202

                result = ctx.cert_service.create(
                    domain=domain,
                    san_domains=san_domains,
                    dns_provider=data.get('dns_provider'),
                    account_id=data.get('account_id'),
                    ca_provider=data.get('ca_provider'),
                    challenge_type=data.get('challenge_type'),
                    domain_alias=data.get('domain_alias'),
                    key_type=data.get('key_type'),
                    key_size=data.get('key_size'),
                    elliptic_curve=data.get('elliptic_curve'),
                    user=user,
                    ip_address=request.remote_addr,
                    audit_ctx=audit_ctx,
                )

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

            except DomainOutOfScope as e:
                return {'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
            except FileExistsError as e:
                # Previously fell through to the generic 500. The certificate
                # already exists: 409 with a pointer to the reissue endpoint.
                return {
                    'error': str(e),
                    'code': 'CERTIFICATE_ALREADY_EXISTS',
                    'hint': 'Use renew to refresh it, or POST /api/certificates/<domain>/reissue to change its configuration.'
                }, 409
            except ValueError as e:
                # Validation / configuration errors raised by the service.
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
            except DomainOperationInProgress as e:
                return {'error': str(e), 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}, 409
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
                }, 422
            except Exception as e:
                logger.error(f"Certificate creation failed: {str(e)}")
                return {
                    'error': 'Certificate creation failed unexpectedly',
                    'hint': 'Check application logs for detailed error information.'
                }, 500

    class RenewCertificate(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def post(self, domain):
            """Renew an existing certificate"""
            try:
                payload = request.get_json(silent=True) or {}
                force = bool(payload.get('force', False))
                _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                user = getattr(request, 'current_user', None) or {}
                audit_ctx = audit_context_from_request()

                if _wants_async(payload) and ctx.cert_executor is not None:
                    prepared = ctx.cert_service.prepare_renew(
                        domain=domain, user=user, ip_address=request.remote_addr,
                        audit_ctx=audit_ctx,
                    )
                    job_id = ctx.cert_executor.submit(
                        'renew', domain,
                        lambda: ctx.cert_service.issue_renew(prepared, force=force),
                    )
                    return _job_accepted(job_id, 'renew', domain), 202

                result = ctx.cert_service.renew(
                    domain=domain, force=force,
                    user=user, ip_address=request.remote_addr,
                    audit_ctx=audit_ctx,
                )

                # renewed=False is certbot's "not yet due" no-op: nothing was
                # replaced, so deploy hooks must not fire and the response must
                # not claim a renewal happened. Default True keeps the frozen
                # REST contract for older manager results without the flag.
                renewed = bool(result.get('renewed', True))

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus and renewed:
                    event_bus.publish('certificate_renewed', {'domain': domain})

                return {
                    'message': (f'Certificate renewed successfully for {domain}'
                                if renewed
                                else f'Certificate not yet due for renewal: {domain}'),
                    'domain': domain,
                    'renewed': renewed,
                    'dns_provider': result.get('dns_provider'),
                    'duration': result.get('duration')
                }, 200

            except DomainOutOfScope as e:
                return {'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
            except DomainOperationInProgress as e:
                # Domain busy is not a failure; do not publish a failure event.
                return {'error': str(e), 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}, 409
            except FileNotFoundError:
                # Missing cert on disk is a 404, not a 500 (matches the web route).
                return {'error': 'Certificate not found', 'code': 'NOT_FOUND'}, 404
            except RuntimeError as e:
                # A renewal failure is a certificate-level outcome, not a server
                # fault: return 422 and say WHY (classify_renewal_error flags the
                # broken-renewal-config case with an actionable reissue hint)
                # instead of the old opaque 500 "Certificate renewal failed".
                logger.error("Certificate renewal failed for %s: %s",
                             domain.replace('\n', ' ').replace('\r', ' '),
                             str(e).replace('\n', ' ').replace('\r', ' '))
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_failed', {'domain': domain, 'error': str(e)})
                message, code = classify_renewal_error(str(e))
                return {'error': message, 'code': code}, 422
            except Exception as e:
                logger.error("Certificate renewal failed for %s: %s",
                             domain.replace('\n', ' ').replace('\r', ' '),
                             str(e).replace('\n', ' ').replace('\r', ' '))
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_failed', {'domain': domain, 'error': str(e)})
                return {'error': 'Certificate renewal failed'}, 500

    class CertificateReissue(Resource):
        @api.doc(security='Bearer')
        @api.expect(models['reissue_cert_model'])
        @ctx.auth.require_role('operator')
        def post(self, domain):
            """Edit a certificate's configuration and reissue it in place (#267).

            Omitted fields keep the values the certificate was issued with
            (read from its metadata), so extending or dropping SANs never
            requires re-entering DNS/alias/CA configuration. The old
            certificate keeps being served until certbot succeeds.
            """
            try:
                data = api.payload or {}
                _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                user = getattr(request, 'current_user', None) or {}

                kwargs = dict(
                    domain=domain,
                    san_domains=data.get('san_domains'),
                    dns_provider=data.get('dns_provider'),
                    account_id=data.get('account_id'),
                    ca_provider=data.get('ca_provider'),
                    challenge_type=data.get('challenge_type'),
                    domain_alias=data.get('domain_alias'),
                    alias_dns_provider=data.get('alias_dns_provider'),
                    key_type=data.get('key_type'),
                    key_size=data.get('key_size'),
                    elliptic_curve=data.get('elliptic_curve'),
                    user=user,
                    ip_address=request.remote_addr,
                    audit_ctx=audit_context_from_request(),
                )

                if _wants_async(data) and ctx.cert_executor is not None:
                    prepared = ctx.cert_service.prepare_reissue(**kwargs)
                    job_id = ctx.cert_executor.submit(
                        'reissue', domain,
                        lambda: ctx.cert_service.issue_reissue(prepared),
                    )
                    return _job_accepted(job_id, 'reissue', domain), 202

                result = ctx.cert_service.issue_reissue(
                    ctx.cert_service.prepare_reissue(**kwargs)
                )

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    # A reissue refreshes the domain's certificate: consumers
                    # (deploy hooks, notifications) react as for a renewal.
                    event_bus.publish('certificate_renewed', {'domain': domain})

                return {
                    'message': f'Certificate reissued successfully for {domain}',
                    'domain': domain,
                    'dns_provider': result.get('dns_provider'),
                    'ca_provider': result.get('ca_provider'),
                    'duration': result.get('duration')
                }, 200

            except FileNotFoundError as e:
                return {'error': str(e), 'code': 'CERTIFICATE_NOT_FOUND'}, 404
            except DomainOutOfScope as e:
                return {'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
            except ValueError as e:
                return {'error': str(e)}, 400
            except DomainOperationInProgress as e:
                # Domain busy is not a failure; no failure event.
                return {'error': str(e), 'code': 'DOMAIN_OPERATION_IN_PROGRESS'}, 409
            except RuntimeError as e:
                error_msg = str(e)
                hint = 'Check DNS provider credentials and ensure DNS records can be created.'
                if 'rate limit' in error_msg.lower():
                    hint = "You've hit the certificate authority's rate limit. Wait before trying again."
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_failed', {'domain': domain, 'error': error_msg})
                return {
                    'error': f'Certificate reissue failed: {error_msg}',
                    'hint': hint + ' The previous certificate is still in place.'
                }, 422
            except Exception as e:
                # Scrub CR/LF before logging: domain comes from the URL path
                # and a crafted value could forge log entries (CodeQL
                # py/log-injection; same treatment as cert_service._scrub_log).
                safe_domain = str(domain).replace('\r', '').replace('\n', '')
                logger.error(f"Certificate reissue failed for {safe_domain}: {str(e)}")
                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_failed', {'domain': domain, 'error': str(e)})
                return {
                    'error': 'Certificate reissue failed unexpectedly',
                    'hint': 'Check application logs. The previous certificate is still in place.'
                }, 500

    class CertificateJob(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def get(self, job_id):
            """Poll the status of an async create/renew job."""
            if ctx.cert_executor is None:
                return {'error': 'Async issuance is not enabled'}, 404
            job = ctx.cert_executor.get(job_id)
            if job is None:
                return {'error': 'Job not found'}, 404
            # The caller must be in scope for the job's domain — a scoped key
            # cannot poll a job for a domain it could not have created.
            scope_err = _check_domain_scope(job.get('domain'), 'job_status')
            if scope_err:
                return scope_err
            return job, 200

    class CertificateJobs(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def get(self):
            """List the issuance/renewal jobs still in flight.

            The dashboard builds its "issuing" row from client-side state, so
            a refresh made an in-flight issuance disappear from the list and
            look like it had failed (issue #399). Listing the jobs the server
            already tracks lets any session rediscover them — including one
            opened in a different browser.

            Only queued/running jobs are returned; a finished one is already
            represented by the certificate itself.
            """
            if ctx.cert_executor is None:
                return {'error': 'Async issuance is not enabled'}, 404
            # Same boundary as polling a single job: a scoped key sees only
            # jobs for domains it could have created itself. Filtered rather
            # than refused, so a scoped key still gets its own in-flight work.
            user = getattr(request, 'current_user', None) or {}
            jobs = [
                job for job in ctx.cert_executor.list_active()
                if ctx.auth.user_can_access_domain(user, job.get('domain'))
            ]
            return {'jobs': jobs, 'count': len(jobs)}, 200

    class CertificateAutoRenew(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def put(self, domain):
            """Enable or disable automatic renewal for a single certificate (issue #111).

            Body: {"enabled": true|false}
            """
            scope_err = _check_domain_scope(domain, 'set_auto_renew')
            if scope_err:
                return scope_err
            _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            try:
                data = api.payload or {}
                if 'enabled' not in data:
                    return {'error': 'Missing "enabled" boolean in request body'}, 400
                enabled = bool(data.get('enabled'))

                updated = ctx.certificates.set_auto_renew(domain, enabled)
                if not updated:
                    return {
                        'error': f'Domain {domain} not found in settings',
                        'hint': 'Only domains tracked in settings can have auto-renew toggled.'
                    }, 404

                if ctx.audit:
                    actx = audit_context_from_request()
                    ctx.audit.log_operation(
                        operation='set_auto_renew', resource_type='certificate',
                        resource_id=domain, status='success',
                        details={'auto_renew': enabled},
                        user=actx.get('user'), ip_address=actx.get('ip'),
                        actor=actx.get('actor'), trigger=actx.get('trigger'),
                    )

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_auto_renew_changed', {
                        'domain': domain,
                        'enabled': enabled,
                    })

                return {
                    'message': f'Auto-renew {"enabled" if enabled else "disabled"} for {domain}',
                    'domain': domain,
                    'auto_renew': enabled,
                }, 200
            except Exception as e:
                logger.error(f"Failed to toggle auto-renew for {domain}: {e}")
                return {'error': 'Failed to update auto-renew setting'}, 500

    return {
        'CreateCertificate': CreateCertificate,
        'RenewCertificate': RenewCertificate,
        'CertificateReissue': CertificateReissue,
        'CertificateJob': CertificateJob,
        'CertificateJobs': CertificateJobs,
        'CertificateAutoRenew': CertificateAutoRenew,
    }
