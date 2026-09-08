"""Listing certificates, and everything known about one of them.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as
an explicit `ApiContext`, which is what makes them importable — and
therefore testable — without constructing the whole manager graph.
"""
import logging

from flask import current_app, request
from flask_restx import Resource

from ..core.certificates import DomainOperationInProgress
from ..core.inventory_sources import (
    auto_renew_for,
    collect_domain_sources,
)
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import ApiContext, check_domain_scope

logger = logging.getLogger(__name__)

# How many per-domain reads a listing runs at once. Matches the gunicorn
# thread count the image ships with (--threads 8): these are IO-bound calls,
# and one request should not be able to occupy more capacity than the whole
# process has for serving.
LISTING_CONCURRENCY = 8

# Below this, threads cost more than they save. A local-filesystem instance
# with a handful of certificates reads four small files per domain from the
# page cache; the pool exists for the instance whose storage backend is Azure
# Key Vault or AWS Secrets Manager, where each read is a network round trip
# and a dashboard load was N of them, one after another.
LISTING_CONCURRENCY_THRESHOLD = 4


def _gather(fetch, items):
    """Apply *fetch* to each item, concurrently, preserving order.

    Order is preserved because the caller zips the results back against the
    input: the dashboard lists certificates in settings order, and a listing
    that reshuffled on every load would be a worse defect than the latency
    this fixes.

    A failure for one item is not allowed to lose the rest. `executor.map`
    raises on the first result that raised, which would turn one unreadable
    certificate into a 500 for the whole listing — so each call is wrapped and
    a failure yields None, exactly as a missing certificate already does.
    """
    if len(items) < LISTING_CONCURRENCY_THRESHOLD:
        return [_guarded(fetch, item) for item in items]

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=LISTING_CONCURRENCY,
                            thread_name_prefix='cert-list') as pool:
        return list(pool.map(lambda item: _guarded(fetch, item), items))


def _guarded(fetch, item):
    try:
        return fetch(item)
    except Exception as e:
        logger.error("Could not read certificate info for %s: %s", item, e)
        return None


def create_certificates_resources(api, models, ctx: ApiContext) -> dict:
    """Build the certificates resources against *ctx*."""

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    class CertificateList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_list_with(models['certificate_model'])
        @ctx.auth.require_role('viewer')
        def get(self):
            """List all certificates.

            Scoped API keys with allowed_domains only see certificates
            within their scope. Unrestricted callers (legacy keys, local
            users) see every certificate.
            """
            try:
                user = getattr(request, 'current_user', None) or {}
                scope = user.get('allowed_domains')
                settings = ctx.settings.load_settings()
                certificates = []

                # One implementation of "what certificates exist" (#670).
                # Both this and the discovery scan rebuilt the union inline,
                # with the same tolerance for a domain entry being a string or
                # a dict, and could disagree about ordering because both
                # iterated a set.
                sources = collect_domain_sources(
                    settings, ctx.certificates.cert_dir)
                auto_renew_by_domain = {
                    name: s.auto_renew for name, s in sources.items()}
                all_domains = list(sources)

                # Get certificate info for all domains, filtered by the
                # caller's API-key scope. domain_matches_scope(d, None) is
                # always True so unrestricted callers see everything.
                visible = [d for d in all_domains
                           if d and ctx.auth.domain_matches_scope(d, scope)]

                # Reuse the once-loaded settings dict so each per-domain call
                # skips its own settings deepcopy — and, with the concurrency
                # below, so that no worker thread calls load_settings at all:
                # that function caches on flask.g behind has_request_context(),
                # and a worker has no request context, so each one would fall
                # back to reading settings.json from disk.
                #
                # use_cache stays at its default True so the storage-backend
                # cert-info cache is still consulted and populated.
                def _info(domain):
                    return ctx.certificates.get_certificate_info(
                        domain, settings=settings)

                for domain, cert_info in zip(visible,
                                             _gather(_info, visible)):
                    if cert_info:
                        cert_info['auto_renew'] = auto_renew_by_domain.get(domain, True)
                        certificates.append(cert_info)

                return certificates
            except Exception as e:
                logger.error(f"Error listing certificates: {e}")
                return {'error': 'Failed to list certificates'}, 500

    class CertificateDetail(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self, domain):
            """Get certificate info for a single domain.

            Scoped API keys may only fetch domains within their
            allowed_domains. CertMate stores one active certificate per
            domain; expired certs are returned so callers can detect
            expiry via days_left / needs_renewal. Returns 404 when no
            certificate directory exists for the domain.
            """
            scope_err = _check_domain_scope(domain, 'get')
            if scope_err:
                return scope_err
            cert_dir, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir or not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404
            try:
                cert_info = ctx.certificates.get_certificate_info(domain)
                if not cert_info:
                    return {'error': f'Certificate not found for domain: {domain}'}, 404
                # Mirror CertificateList.get's per-domain auto_renew enrichment so
                # the single-domain response shape matches the list response.
                cert_info['auto_renew'] = auto_renew_for(
                    ctx.settings.load_settings(), domain)
                return cert_info
            except Exception as e:
                logger.error(f"Error fetching certificate for {domain}: {e}")
                return {'error': 'Failed to fetch certificate'}, 500

        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def patch(self, domain):
            """Update DNS provider or deployment probe config for an existing
            certificate (issue #129 + deployment probe extension).

            DNS changes: ``dns_provider``, ``account_id``, ``alias_dns_provider``.
            Probe changes: ``deployment_port`` (int, 1-65535),
            ``deployment_protocol`` ("https-tls" | "tls" | "smtp-starttls")
            and/or ``deployment_host`` (the hostname the deployment-status
            probe should connect to and SNI). A ``deployment_host`` is the
            supported way to verify a wildcard cert: point it at a name the
            wildcard actually covers, e.g. www.example.com for *.example.com
            (#381). Either category can be used alone or together.

            Body: {"dns_provider": "route53", "deployment_protocol": "smtp-starttls",
                   "deployment_port": 587, "deployment_host": "mail.example.com"}
            """
            scope_err = _check_domain_scope(domain, 'update_dns_provider')
            if scope_err:
                return scope_err
            cert_dir, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir or not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            data = api.payload or {}
            new_dns_provider = data.get('dns_provider')
            new_account_id = data.get('account_id')
            new_alias_dns_provider = data.get('alias_dns_provider')

            # Allow requests that only set deployment probe fields
            # (deployment_port / deployment_protocol / deployment_host) without
            # requiring a DNS provider change.
            has_dns_changes = bool(new_dns_provider or new_alias_dns_provider)
            has_probe_changes = (
                'deployment_port' in data
                or 'deployment_protocol' in data
                or 'deployment_host' in data
            )

            if not has_dns_changes and not has_probe_changes:
                return {
                    'error': 'At least one of dns_provider, alias_dns_provider, '
                             'deployment_port, deployment_protocol, or '
                             'deployment_host is required',
                }, 400

            # Validate the new provider has credentials configured
            if new_dns_provider:
                settings = ctx.settings.load_settings()
                dns_config, _ = ctx.dns.get_dns_provider_account_config(
                    new_dns_provider,
                    new_account_id,
                    settings,
                )
                if not dns_config:
                    return {
                        'error': f"DNS provider '{new_dns_provider}' account "
                                 f"'{new_account_id or 'default'}' is not configured",
                        'hint': 'Configure the DNS provider credentials in Settings first.'
                    }, 400

            # alias_dns_provider was previously accepted unvalidated; an
            # unconfigured value only surfaced at renew time as a baffling
            # failure. Validate it the same way as dns_provider.
            if new_alias_dns_provider:
                settings = ctx.settings.load_settings()
                alias_config, _ = ctx.dns.get_dns_provider_account_config(
                    new_alias_dns_provider,
                    new_account_id,
                    settings,
                )
                if not alias_config:
                    return {
                        'error': f"Alias DNS provider '{new_alias_dns_provider}' is not configured",
                        'hint': 'Configure the DNS provider credentials in Settings first.'
                    }, 400

            try:
                # The read-modify-write, its validation, and the domain
                # lock that serialises it against an in-flight renewal all
                # live in the service now (#672). This is the adapter: shape
                # the request into a change set, map the service's errors onto
                # status codes.
                changes = {
                    'dns_provider': new_dns_provider,
                    'account_id': new_account_id,
                    'alias_dns_provider': new_alias_dns_provider,
                }
                # Probe keys are forwarded only when the caller SENT them:
                # absent means "leave it alone", explicit null means "delete
                # it", and the service depends on telling them apart.
                for key in ('deployment_port', 'deployment_protocol',
                            'deployment_host'):
                    if key in data:
                        changes[key] = data[key]

                try:
                    metadata, old_provider = ctx.cert_service.update_config(
                        domain, changes)
                except ValueError as e:
                    return {'error': str(e)}, 400
                except RuntimeError as e:
                    return {'error': str(e)}, 500
                logger.info(
                    f"Updated DNS provider for {domain}: "
                    f"{old_provider} → {new_dns_provider or old_provider}"
                )

                # 2. Update domain entry in settings
                def _update_domain_provider(s):
                    for entry in s.get('domains', []):
                        if isinstance(entry, dict) and entry.get('domain') == domain:
                            if new_dns_provider:
                                entry['dns_provider'] = new_dns_provider
                            if new_account_id:
                                entry['dns_account_id'] = new_account_id
                            break

                ctx.settings.update(_update_domain_provider, "dns_provider_change")

                response = {
                    'message': f'Certificate config updated for {domain}',
                    'domain': domain,
                    'dns_provider': metadata.get('dns_provider'),
                    'alias_dns_provider': metadata.get('alias_dns_provider'),
                    'account_id': metadata.get('account_id'),
                }
                if has_probe_changes:
                    response['deployment_port'] = metadata.get('deployment_port')
                    response['deployment_protocol'] = metadata.get('deployment_protocol')
                    response['deployment_host'] = metadata.get('deployment_host')
                return response, 200

            except DomainOperationInProgress:
                # A create/renew holds the per-domain lock; the config change
                # cannot safely interleave with it. Same 409 the create/renew
                # routes return, so the client can retry once issuance settles.
                return {
                    'error': f'An operation is in progress for {domain}; '
                             f'retry once it completes'
                }, 409
            except Exception as e:
                logger.error(f"Failed to update certificate config for {domain}: {e}")
                return {'error': 'Failed to update certificate config'}, 500

        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def delete(self, domain):
            """Delete a certificate's files from disk.

            Refuses if a create or renew is currently holding the domain lock.
            Does NOT revoke the certificate at the CA — call the CA's revoke
            endpoint separately if revocation is required.
            """
            scope_err = _check_domain_scope(domain, 'delete')
            if scope_err:
                return scope_err
            # Path is only validated for the side-effect of rejecting
            # traversal attempts; the actual delete is keyed on the domain
            # name and handled by certificate_manager.
            _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            try:
                deleted = ctx.certificates.delete_certificate(domain)
                if not deleted:
                    return {'error': f'Certificate not found for domain: {domain}'}, 404

                # Best-effort: drop the domain from settings so the dashboard
                # stops listing it. Do it as a read-modify-write under the lock
                # (settings_manager.update), NOT load_settings()+atomic_update
                # with a whole 'domains' list: the load here is a request-cache
                # HIT (the rate-limit before_request primed flask.g), and
                # delete_certificate above can span a storage-backend network
                # round-trip, so a concurrent registration that lands in that
                # window is absent from the cached list. atomic_update replaces
                # 'domains' wholesale (it is not a deep-merge key), so the stale
                # list would win and silently drop the freshly-registered
                # domain from renewals. The mutator filters the fresh on-disk
                # list instead, removing only this domain.
                class _AlreadyAbsent(Exception):
                    pass

                def _drop_domain(s):
                    current = s.get('domains', []) or []
                    kept = [
                        d for d in current
                        if (isinstance(d, str) and d != domain)
                        or (isinstance(d, dict) and d.get('domain') != domain)
                    ]
                    # Nothing to remove — do not persist (and do not trigger an
                    # automatic backup) for a no-op, matching the previous
                    # `if len(new_domains) != len(domains)` guard.
                    if len(kept) == len(current):
                        raise _AlreadyAbsent
                    s['domains'] = kept

                try:
                    ctx.settings.update(_drop_domain, reason='certificate_delete')
                except _AlreadyAbsent:
                    pass
                except Exception as e:
                    logger.warning(f"Removed cert for {domain} but failed to update settings: {e}")

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_deleted', {'domain': domain})

                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='delete',
                        resource_type='certificate',
                        resource_id=domain,
                        status='success',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {'message': f'Certificate deleted for {domain}', 'domain': domain}, 200
            except RuntimeError as e:
                return {'error': str(e)}, 409
            except Exception as e:
                logger.error(f"Certificate deletion failed for {domain}: {e}")
                return {'error': 'Certificate deletion failed'}, 500

    return {
        'CertificateList': CertificateList,
        'CertificateDetail': CertificateDetail,
    }
