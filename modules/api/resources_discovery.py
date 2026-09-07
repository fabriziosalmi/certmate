"""Finding certificates nobody asked for, and checking DNS alias setup.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as
an explicit `ApiContext`, which is what makes them importable — and
therefore testable — without constructing the whole manager graph.
"""
import logging

from flask import request
from flask_restx import Resource

from ..core.constants import iter_cert_domain_dirs
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import ApiContext, check_domain_scope

logger = logging.getLogger(__name__)


def create_discovery_resources(api, models, ctx: ApiContext) -> dict:
    """Build the discovery resources against *ctx*."""

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    class ZombieScan(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def post(self):
            """Scan active certificates for zombie domains."""
            try:
                from ..core.zombie import ZombieScanner
                
                user = getattr(request, 'current_user', None) or {}
                scope = user.get('allowed_domains')
                settings = ctx.settings.load_settings()
                certificates = []

                all_domains = set()

                # Add domains from settings
                for domain_entry in settings.get('domains', []):
                    if isinstance(domain_entry, str):
                        domain = domain_entry
                    elif isinstance(domain_entry, dict):
                        domain = domain_entry.get('domain')
                    else:
                        continue
                    if domain:
                        all_domains.add(domain)

                # Also check for certificates that exist on disk but might not be in settings
                for cert_dir_path in iter_cert_domain_dirs(ctx.certificates.cert_dir):
                    all_domains.add(cert_dir_path.name)

                # Get certificate info for all domains
                for domain in all_domains:
                    if not domain:
                        continue
                    if not ctx.auth.domain_matches_scope(domain, scope):
                        continue
                    # Reuse the once-loaded settings dict so each per-domain
                    # call skips its own settings deepcopy (load_settings is
                    # already request-cached on flask.g). use_cache stays at
                    # its default True so the storage-backend cert-info cache
                    # is still consulted/populated during the scan.
                    cert_info = ctx.certificates.get_certificate_info(domain, settings=settings)
                    if cert_info:
                        certificates.append(cert_info)

                scanner = ZombieScanner()
                scan_results = scanner.scan_certificates(certificates)
                return scan_results, 200
            except Exception as e:
                logger.error(f"Error scanning certificates for zombies: {e}")
                return {'error': 'Failed to perform zombie scan'}, 500

    class CheckDNSAlias(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def post(self):
            """Check DNS-01 alias CNAME records before creating a certificate."""
            data = api.payload or {}
            domain = (data.get('domain') or '').strip()
            domain_alias = (data.get('domain_alias') or '').strip()
            san_domains = data.get('san_domains') or []
            if not isinstance(san_domains, list):
                return {'error': 'san_domains must be an array'}, 400

            wildcard = bool(data.get('wildcard'))
            if wildcard and domain:
                wildcard_domain = '*.' + domain.lstrip('*.')
                if wildcard_domain not in san_domains:
                    san_domains.append(wildcard_domain)

            if not domain or not domain_alias:
                return {'error': 'domain and domain_alias are required'}, 400

            # Audit M5: the path-style variant
            # `CertificateDNSAliasCheck.get(domain)` already runs
            # `_check_domain_scope`. This body-style variant did not,
            # so a scoped viewer could probe DNS-alias topology for
            # any out-of-scope domain (information disclosure: confirms
            # which `_acme-challenge` alias targets exist). Apply the
            # same scope gate to the primary domain AND every SAN.
            scope_err = _check_domain_scope(domain, 'check_dns_alias')
            if scope_err:
                return scope_err
            for san in (san_domains or []):
                san_clean = san.strip() if isinstance(san, str) else ''
                if san_clean:
                    scope_err = _check_domain_scope(san_clean, 'check_dns_alias_san')
                    if scope_err:
                        return scope_err

            return ctx.certificates.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=san_domains,
            ), 200

    class CertificateDNSAliasCheck(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def get(self, domain):
            """Check DNS-01 alias CNAME records for an existing certificate."""
            _, err = _validate_domain_path(domain, ctx.file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            scope_err = _check_domain_scope(domain, 'dns_alias_check')
            if scope_err:
                return scope_err
            cert_info = ctx.certificates.get_certificate_info(domain)
            if not cert_info or not cert_info.get('exists'):
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            domain_alias = cert_info.get('domain_alias')
            if not domain_alias:
                return {'error': f'Certificate {domain} is not using DNS-01 alias mode'}, 400

            return ctx.certificates.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=cert_info.get('san_domains') or [],
            ), 200

    return {
        'ZombieScan': ZombieScan,
        'CheckDNSAlias': CheckDNSAlias,
        'CertificateDNSAliasCheck': CertificateDNSAliasCheck,
    }
