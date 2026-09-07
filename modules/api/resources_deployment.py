"""Is the certificate a host is actually serving the one we issued?

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as
an explicit `ApiContext`, which is what makes them importable — and
therefore testable — without constructing the whole manager graph.
"""
import logging

from pathlib import Path

from flask import current_app, request
from flask_restx import Resource

from ..core.audit_context import audit_context_from_request
from ..core.utils import utc_now_iso
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import ApiContext, check_domain_scope
from .tls_probe import (
    _certificate_fingerprint, _certificate_subject_summary,
    _probe_tls_certificate,
)

logger = logging.getLogger(__name__)


def create_deployment_resources(api, models, ctx: ApiContext) -> dict:
    """Build the deployment resources against *ctx*."""

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    class CertificateDeploymentStatus(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        @api.marshal_with(models['deployment_status_model'])
        def get(self, domain):
            """Check whether the domain is serving the expected certificate."""
            refresh_requested = str(request.args.get('refresh', '')).lower() in {'1', 'true', 'yes', 'on'}
            _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            scope_err = _check_domain_scope(domain, 'deployment_status')
            if scope_err:
                return scope_err

            cert_info = ctx.certificates.get_certificate_info(domain)
            if not cert_info or not cert_info.get('exists'):
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            if refresh_requested:
                ctx.cache.remove_from_cache(domain)
            else:
                cached_result = ctx.cache.get_deployment_status(domain)
                if isinstance(cached_result, dict) and cached_result.get('domain') == domain:
                    return cached_result, 200

            expected_bytes = None
            storage_manager = getattr(ctx.certificates, 'storage_manager', None)
            if storage_manager is not None:
                try:
                    storage_result = storage_manager.retrieve_certificate(domain)
                    if storage_result:
                        cert_files, _metadata = storage_result
                        expected_bytes = cert_files.get('cert.pem')
                except Exception as e:
                    logger.warning(f"Could not read stored certificate for {domain}: {e}")

            if expected_bytes is None:
                cert_path = Path(ctx.file_ops.cert_dir) / domain / 'cert.pem'
                if cert_path.exists():
                    expected_bytes = cert_path.read_bytes()

            if not expected_bytes:
                return {'error': f'Certificate file not found for domain: {domain}'}, 404

            expected_fingerprint = _certificate_fingerprint(expected_bytes)
            if not expected_fingerprint:
                return {'error': f'Could not parse certificate for domain: {domain}'}, 500

            # Read per-cert deployment config from metadata, fall back to
            # defaults. Stored via PATCH /api/certificates/<domain> as
            # ``deployment_port``, ``deployment_protocol`` and (optional)
            # ``deployment_host``.
            metadata = ctx.certificates._load_metadata(domain) if hasattr(ctx.certificates, '_load_metadata') else {}
            raw_port = metadata.get('deployment_port')
            deploy_port = raw_port if raw_port is not None else 0
            deploy_protocol = metadata.get('deployment_protocol') or 'https-tls'
            deploy_host = metadata.get('deployment_host')
            if isinstance(deploy_host, str):
                deploy_host = deploy_host.strip() or None

            is_wildcard = domain.startswith('*.')

            result = {
                'domain': domain,
                'deployed': False,
                'reachable': False,
                'certificate_match': False,
                'method': deploy_protocol,
                'port': deploy_port if deploy_port is not None else None,
                'protocol': deploy_protocol,
                'timestamp': utc_now_iso(),
                # Diagnostic fields (additive, #381): tell the operator WHICH
                # host was probed and, on a mismatch, WHAT was actually served
                # vs expected — so the dashboard error icon can explain itself.
                'probe_host': None,
                'probe_status': None,
                'mismatch_reason': None,
            }

            if is_wildcard and not deploy_host:
                # A wildcard (*.example.com) does NOT cover its own apex
                # (example.com) per RFC 6125, and there is no single covered
                # name we can safely assume is deployed. Probing the apex here
                # produced a permanent false "wrong cert" for every wildcard
                # (#207/#381). With no explicit deployment_host we cannot verify
                # unambiguously, so report a distinct, non-alarming status
                # instead of a red mismatch — and tell the operator how to fix
                # it. certificate_match stays False but the UI keys off
                # probe_status to render a neutral "not verifiable" chip.
                apex = domain[2:]
                result['probe_status'] = 'unverifiable'
                result['mismatch_reason'] = (
                    f"Wildcard certificate {domain} cannot be verified "
                    f"automatically: a wildcard does not cover its apex "
                    f"({apex}), so probing {apex} would compare against the "
                    f"wrong host. Set the probe host to a name this wildcard "
                    f"covers (for example www.{apex}) to enable the check: "
                    f"Settings → Probe in the UI, or deployment_host via "
                    f"PATCH /api/certificates/{domain}."
                )
                persisted_status = ctx.certificates.get_deployment_status_record(domain)
                if isinstance(persisted_status, dict) and persisted_status.get('browser'):
                    result['browser'] = persisted_status.get('browser')
                ctx.certificates.record_backend_deployment_status(domain, result)
                ctx.cache.set_deployment_status(domain, result)
                return result, 200

            # Probe target: an explicit deployment_host wins for any cert;
            # otherwise a non-wildcard probes itself. (A wildcard without a
            # deployment_host is handled above and never reaches here.)
            effective_host = deploy_host or domain
            result['probe_host'] = effective_host

            try:
                probe = _probe_tls_certificate(
                    domain,
                    port=int(deploy_port) if deploy_port else 0,
                    protocol=deploy_protocol,
                    probe_host=deploy_host or None,
                )
                result['reachable'] = True
                result['deployed'] = True
                result['port'] = probe.get('port')
                result['protocol'] = probe.get('protocol')
                served_bytes = probe.get('certificate_bytes')
                served_fingerprint = _certificate_fingerprint(served_bytes)
                match = served_fingerprint == expected_fingerprint
                result['certificate_match'] = match
                if match:
                    result['probe_status'] = 'match'
                else:
                    # Real mismatch: surface exactly what differs so the
                    # operator can troubleshoot from the dashboard tooltip.
                    result['probe_status'] = 'mismatch'
                    served_subject = _certificate_subject_summary(served_bytes)
                    served_fp_prefix = (served_fingerprint or '')[:16]
                    expected_fp_prefix = expected_fingerprint[:16]
                    result['served_subject'] = served_subject
                    result['served_fingerprint'] = served_fp_prefix
                    result['expected_fingerprint'] = expected_fp_prefix
                    served_desc = served_subject or 'an unrecognised certificate'
                    result['mismatch_reason'] = (
                        f"{effective_host}:{result['port']} is serving "
                        f"{served_desc} (fingerprint {served_fp_prefix or 'n/a'}...), "
                        f"which does not match the certificate stored for "
                        f"{domain} (fingerprint {expected_fp_prefix}...)."
                    )
            except Exception as e:
                result['error'] = str(e)
                result['probe_status'] = 'unreachable'
                result['mismatch_reason'] = (
                    f"Could not probe {effective_host}: {e}"
                )

            persisted_status = ctx.certificates.get_deployment_status_record(domain)
            if isinstance(persisted_status, dict) and persisted_status.get('browser'):
                result['browser'] = persisted_status.get('browser')

            ctx.certificates.record_backend_deployment_status(domain, result)
            ctx.cache.set_deployment_status(domain, result)
            return result, 200

    class CertificateDeploymentBrowserReports(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        @api.expect(models['browser_deployment_reports_model'])
        def post(self):
            """Persist browser-reported reachability for one or more domains."""
            payload = request.get_json(silent=True) or {}
            reports = payload.get('reports')
            if not isinstance(reports, list) or not reports:
                return {'error': 'reports must be a non-empty array'}, 400

            updated = []
            skipped = []
            for report in reports:
                if not isinstance(report, dict):
                    skipped.append({'error': 'invalid report payload'})
                    continue

                domain = (report.get('domain') or '').strip()
                if not domain:
                    skipped.append({'error': 'missing domain'})
                    continue

                _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
                if err:
                    skipped.append({'domain': domain, 'error': err})
                    continue
                scope_err = _check_domain_scope(domain, 'browser_report')
                if scope_err:
                    skipped.append({'domain': domain, 'error': 'out of scope'})
                    continue

                browser_status = ctx.certificates.record_browser_deployment_status(domain, report)
                persisted = ctx.certificates.get_deployment_status_record(domain)
                backend = persisted.get('backend') if isinstance(persisted, dict) else None
                merged = {
                    'domain': domain,
                    'deployed': bool(backend.get('deployed')) if isinstance(backend, dict) else False,
                    'reachable': bool(backend.get('reachable')) if isinstance(backend, dict) else False,
                    'certificate_match': backend.get('certificate_match') if isinstance(backend, dict) else False,
                    'method': backend.get('method') if isinstance(backend, dict) else 'browser-report',
                    'timestamp': backend.get('timestamp') if isinstance(backend, dict) else None,
                    'error': backend.get('error') if isinstance(backend, dict) else None,
                    'browser': browser_status.get('browser') if isinstance(browser_status, dict) else None,
                }
                ctx.cache.set_deployment_status(domain, merged)
                updated.append(domain)

            return {
                'updated': updated,
                'skipped': skipped,
                'count': len(updated),
            }, 200

    class CertificateRunDeploy(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self, domain):
            """Manually run all enabled deploy hooks for a domain (issue #109).

            Aligns with the role of /api/deploy/* (admin-only). Hooks run
            with CERTMATE_EVENT=manual; the on_events filter is ignored
            since the user explicitly requested execution.
            """
            scope_err = _check_domain_scope(domain, 'run_deploy')
            if scope_err:
                return scope_err
            if ctx.deployer is None:
                return {'error': 'Deploy manager not available'}, 503

            cert_dir, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            try:
                summary = ctx.deployer.run_manual_deploy(domain)
            except Exception as e:
                logger.error(f"Manual deploy hook run failed for {domain}: {e}")
                if ctx.audit:
                    actx = audit_context_from_request()
                    ctx.audit.log_operation(
                        operation='deploy', resource_type='certificate',
                        resource_id=domain, status='failure', error=str(e)[:500],
                        details={'manual': True},
                        user=actx.get('user'), ip_address=actx.get('ip'),
                        actor=actx.get('actor'), trigger=actx.get('trigger'),
                    )
                return {'error': 'Manual deploy hook run failed'}, 500

            if ctx.audit:
                actx = audit_context_from_request()
                ctx.audit.log_operation(
                    operation='deploy', resource_type='certificate',
                    resource_id=domain,
                    status='success' if summary.get('ok') else 'failure',
                    details={
                        'manual': True,
                        'total': summary.get('total'),
                        'succeeded': summary.get('succeeded'),
                        'failed': summary.get('failed'),
                    },
                    user=actx.get('user'), ip_address=actx.get('ip'),
                    actor=actx.get('actor'), trigger=actx.get('trigger'),
                )

            event_bus = current_app.config.get('EVENT_BUS')
            if event_bus:
                event_bus.publish('certificate_deploy_manual', {
                    'domain': domain,
                    'ok': summary.get('ok'),
                    'total': summary.get('total'),
                    'succeeded': summary.get('succeeded'),
                    'failed': summary.get('failed'),
                })

            # 200 even when ok=False (e.g. no hooks configured) so the
            # client can read the structured summary; the route only
            # returns non-2xx for path validation / server errors.
            return summary, 200

    return {
        'CertificateDeploymentStatus': CertificateDeploymentStatus,
        'CertificateDeploymentBrowserReports': CertificateDeploymentBrowserReports,
        'CertificateRunDeploy': CertificateRunDeploy,
    }
