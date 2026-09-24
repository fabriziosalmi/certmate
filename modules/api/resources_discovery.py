"""Finding certificates nobody asked for, probing one on demand, and checking
DNS before issuance.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as
an explicit `ApiContext`, which is what makes them importable — and
therefore testable — without constructing the whole manager graph.
"""
import logging

from flask import request
from flask_restx import Resource

from ..core.inventory_sources import collect_domain_sources
from ..core.request_fields import json_bool, json_booleans
from .path_validation import validate_domain_path as _validate_domain_path
from .resource_context import ApiContext, check_domain_scope

logger = logging.getLogger(__name__)

# A CAA check resolves every name and climbs its parents, so a request naming
# hundreds of SANs would hold a worker for a long time. The certificate itself
# is capped far lower by every public CA (100 names at Let's Encrypt); this is
# only a bound on one preview request.
MAX_CAA_NAMES = 100

# A probe may be asked for any port: the deployment probe already speaks to
# whatever an operator configured, and refusing 8443 would be arbitrary. What
# keeps this from being a port scanner with CertMate's source address is the
# scope check on the host and the probe's own SSRF guard.
PROBE_PORT_MIN, PROBE_PORT_MAX = 1, 65535


def _probe_resource(api, ctx):
    """Build POST /api/probe.

    Outside create_discovery_resources so the closure's complexity budget — a
    ceiling that only comes down — pays nothing for it.
    """
    class ProbeEndpoint(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def post(self):
            """Read the certificate a host is serving, right now.

            The same deep probe the inventory sweep uses, pointed at a host
            named in the request rather than one in the configuration, with the
            verified revocation answer. It is how another tool asks CertMate
            what is being served: the answer describes the certificate without
            trusting it, and says `unavailable` rather than `good` when
            revocation could not be established.
            """
            data = request.get_json(silent=True) or {}
            raw_host = data.get('host')
            host = raw_host.strip() if isinstance(raw_host, str) else ''
            if not host:
                return {'error': 'host is required', 'code': 'INVALID_REQUEST'}, 400
            port = data.get('port', 443)
            if isinstance(port, bool) or not isinstance(port, int) or not (
                    PROBE_PORT_MIN <= port <= PROBE_PORT_MAX):
                return {'error': 'port must be an integer between 1 and 65535',
                        'code': 'INVALID_REQUEST'}, 400
            server_name = data.get('server_name')
            if server_name is not None and not isinstance(server_name, str):
                return {'error': 'server_name must be a string',
                        'code': 'INVALID_REQUEST'}, 400
            check_revocation, err = json_bool(data, 'check_revocation', default=True)
            if err:
                return {'error': err, 'code': 'INVALID_REQUEST'}, 400

            # A scoped key probes only what its scope covers — the same
            # boundary the inventory and the DNS-alias check enforce. The SNI
            # name counts too: it is what the probe asks the host for.
            for name in filter(None, (host, server_name)):
                scope_err = check_domain_scope(ctx, name, 'probe')
                if scope_err:
                    return scope_err

            from ..core.cert_probe import probe_certificate
            return probe_certificate(host, port=port, server_name=server_name,
                                     check_revocation=check_revocation), 200

    return ProbeEndpoint


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

                # Same single answer the certificate list uses (#670).
                all_domains = list(collect_domain_sources(
                    settings, ctx.certificates.cert_dir))

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
        @json_booleans(wildcard=False)
        def post(self):
            """Check DNS-01 alias CNAME records before creating a certificate."""
            data = api.payload or {}
            domain = (data.get('domain') or '').strip()
            domain_alias = (data.get('domain_alias') or '').strip()
            san_domains = data.get('san_domains') or []
            if not isinstance(san_domains, list):
                return {'error': 'san_domains must be an array'}, 400

            wildcard = request.json_booleans['wildcard']
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

            # Which record to expect depends on who publishes it: acme-dns
            # answers at the bare subdomain, a certbot-style alias under
            # `_acme-challenge.<alias>`. Falls back to the certificate's own
            # provider when no separate alias provider is named.
            return ctx.certificates.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=san_domains,
                alias_provider=(data.get('alias_dns_provider')
                                or data.get('dns_provider')),
            ), 200

    class CheckCAA(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('viewer')
        def post(self):
            """What the CAA records say about issuing these names from this CA.

            A warning, never a gate: CertMate's resolver is not the CA's, and
            the create endpoint does not consult this. The dashboard asks it
            while the form is being filled in, so a CAA record that names a
            different CA is seen before the order rather than after it fails.
            """
            data = api.payload or {}
            domain = (data.get('domain') or '').strip() if isinstance(data.get('domain'), str) else ''
            san_domains = data.get('san_domains') or []
            if not domain:
                return {'error': 'domain is required', 'code': 'INVALID_REQUEST'}, 400
            if not isinstance(san_domains, list) or not all(isinstance(s, str) for s in san_domains):
                return {'error': 'san_domains must be an array of strings',
                        'code': 'INVALID_REQUEST'}, 400
            names = [domain] + [s.strip() for s in san_domains if s.strip()]
            if len(names) > MAX_CAA_NAMES:
                return {'error': f'at most {MAX_CAA_NAMES} names can be checked at once',
                        'code': 'INVALID_REQUEST'}, 400

            # Same boundary as the DNS-alias check (audit M5): a scoped key
            # must not learn anything about names outside its scope.
            for name in names:
                scope_err = _check_domain_scope(name, 'check_caa')
                if scope_err:
                    return scope_err

            settings = ctx.settings.load_settings() or {}
            ca_provider = (data.get('ca_provider') or '').strip() or settings.get('default_ca', 'letsencrypt')
            challenge_type = (data.get('challenge_type') or '').strip() or settings.get('challenge_type', 'dns-01')

            from ..core import caa
            ca_manager = getattr(ctx.certificates, 'ca_manager', None)
            ca_name = ((getattr(ca_manager, 'ca_providers', {}) or {}).get(ca_provider) or {}).get('name')
            from ..core.dns_resolver import configured_nameservers
            return caa.check(ca_provider, names, challenge_type=challenge_type,
                             ca_name=ca_name,
                             nameservers=configured_nameservers(settings)), 200

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
                return {'error': f'Certificate not found for domain: {domain}',
                        'code': 'CERTIFICATE_NOT_FOUND'}, 404

            domain_alias = cert_info.get('domain_alias')
            if not domain_alias:
                return {'error': f'Certificate {domain} is not using DNS-01 alias mode'}, 400

            return ctx.certificates.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=cert_info.get('san_domains') or [],
                alias_provider=(cert_info.get('alias_dns_provider')
                                or cert_info.get('dns_provider')),
            ), 200

    return {
        'ZombieScan': ZombieScan,
        'CheckDNSAlias': CheckDNSAlias,
        'CheckCAA': CheckCAA,
        'ProbeEndpoint': _probe_resource(api, ctx),
        'CertificateDNSAliasCheck': CertificateDNSAliasCheck,
    }
