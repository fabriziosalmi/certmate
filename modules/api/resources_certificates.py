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
from ..core.constants import iter_cert_domain_dirs
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import ApiContext, check_domain_scope
from .tls_probe import _PROBE_PROTOCOLS

logger = logging.getLogger(__name__)


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

                # Map domain -> per-cert auto_renew flag (default True). Domains
                # that exist only on disk and are not in settings get True too.
                auto_renew_by_domain = {}
                all_domains = set()

                # Add domains from settings
                for domain_entry in settings.get('domains', []):
                    if isinstance(domain_entry, str):
                        domain = domain_entry
                        per_cert_auto_renew = True
                    elif isinstance(domain_entry, dict):
                        domain = domain_entry.get('domain')
                        per_cert_auto_renew = domain_entry.get('auto_renew', True)
                    else:
                        continue
                    if domain:
                        all_domains.add(domain)
                        auto_renew_by_domain[domain] = bool(per_cert_auto_renew)

                # Also check for certificates that exist on disk but might not be in settings.
                # Use iter_cert_domain_dirs so FS artifacts (lost+found, hidden dirs,
                # non-cert subdirectories when cert_dir is a volume mount point) don't
                # surface as ghost "Not Found" entries in the dashboard.
                for cert_dir_path in iter_cert_domain_dirs(ctx.certificates.cert_dir):
                    all_domains.add(cert_dir_path.name)

                # Get certificate info for all domains, filtered by the
                # caller's API-key scope. domain_matches_scope(d, None) is
                # always True so unrestricted callers see everything.
                for domain in all_domains:
                    if not domain:
                        continue
                    if not ctx.auth.domain_matches_scope(domain, scope):
                        continue
                    # Reuse the once-loaded settings dict so each per-domain
                    # call skips its own settings deepcopy (load_settings is
                    # already request-cached on flask.g). use_cache stays at
                    # its default True so the storage-backend cert-info cache
                    # is still consulted/populated during listing.
                    cert_info = ctx.certificates.get_certificate_info(domain, settings=settings)
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
                settings = ctx.settings.load_settings()
                auto_renew = True
                for entry in settings.get('domains', []):
                    if isinstance(entry, dict) and entry.get('domain') == domain:
                        auto_renew = bool(entry.get('auto_renew', True))
                        break
                cert_info['auto_renew'] = auto_renew
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
            new_deploy_port = data.get('deployment_port')
            new_deploy_protocol = data.get('deployment_protocol')
            new_deploy_host = data.get('deployment_host')

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
                # Serialise this metadata read-modify-write against an in-flight
                # renewal (which carries a pre-renewal metadata snapshot across
                # its whole certbot run and would otherwise clobber this write).
                with ctx.certificates.domain_lock(domain):
                    # 1. Update on-disk metadata.json. Read through the manager
                    # (which builds the path from the already-validated domain
                    # and quarantines corrupt JSON instead of silently returning
                    # {}) rather than opening cert_dir/'metadata.json' directly.
                    metadata = ctx.certificates._load_metadata(domain)

                    old_provider = metadata.get('dns_provider')
                    if new_dns_provider:
                        metadata['dns_provider'] = new_dns_provider
                    if new_account_id:
                        metadata['account_id'] = new_account_id
                    if new_alias_dns_provider:
                        metadata['alias_dns_provider'] = new_alias_dns_provider

                    # --- deployment probe config ---
                    # Only touch probe config when the caller actually sends the
                    # key: an ABSENT key leaves existing config intact, an explicit
                    # null deletes it. Keying off `is not None` instead would let a
                    # DNS-only PATCH silently wipe a cert's probe config.
                    if 'deployment_port' in data:
                        if new_deploy_port is not None:
                            try:
                                port = int(new_deploy_port)
                                if port < 1 or port > 65535:
                                    return {'error': 'deployment_port must be 1-65535'}, 400
                                metadata['deployment_port'] = port
                            except (TypeError, ValueError):
                                return {'error': 'deployment_port must be an integer'}, 400
                        else:
                            metadata.pop('deployment_port', None)

                    if 'deployment_protocol' in data:
                        if new_deploy_protocol is not None:
                            if new_deploy_protocol not in _PROBE_PROTOCOLS:
                                return {
                                    'error': f"deployment_protocol must be one of {_PROBE_PROTOCOLS!r}"
                                }, 400
                            metadata['deployment_protocol'] = new_deploy_protocol
                        else:
                            metadata.pop('deployment_protocol', None)

                    if 'deployment_host' in data:
                        if new_deploy_host is not None:
                            if not isinstance(new_deploy_host, str):
                                return {'error': 'deployment_host must be a string'}, 400
                            host = new_deploy_host.strip()
                            # A probe target is a bare hostname: no scheme, no path,
                            # no whitespace, and no wildcard label (you deploy a
                            # cert on a concrete name, not on "*.").
                            if (not host or len(host) > 253 or host.startswith('*.')
                                    or any(c in host for c in ' \t/\\')
                                    or '://' in host):
                                return {
                                    'error': 'deployment_host must be a bare hostname '
                                             '(no scheme, path, whitespace, or wildcard)'
                                }, 400
                            metadata['deployment_host'] = host
                        else:
                            metadata.pop('deployment_host', None)

                    if not ctx.certificates._save_metadata(domain, metadata):
                        return {'error': f'Failed to update metadata for domain: {domain}'}, 500
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
