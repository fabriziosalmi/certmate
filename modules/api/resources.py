"""
API endpoints module for CertMate
Defines Flask-RESTX Resource classes for REST API endpoints
"""

import base64
import http.client
import logging
import re
import socket
import ssl
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
import os
import io
from pathlib import Path
from flask import send_file, after_this_request, current_app, request, jsonify
from flask_restx import Resource

from ..core.constants import CERTIFICATE_FILES, iter_cert_domain_dirs
from .resources_cache import create_cache_resources
from .resources_backup import create_backup_resources
from .resources_inventory import create_inventory_resources
from .resources_ca import create_ca_resources
from .resources_settings import create_settings_resources
from .resources_storage import create_storage_resources
# Re-exported: it moved to resources_backup with the endpoints that use it,
# and tests import it from here.
from .resources_backup import _validate_backup_filename  # noqa: F401
from .resources_health import create_health_resources
from .resource_context import (
    build_context, wants_async, job_accepted, check_domain_scope,
    is_record_in_scope, scope_filter_records, user_has_role,
)
from ..core.utils import utc_now_iso, classify_renewal_error
from ..core.certificates import DomainOperationInProgress
from ..core.cert_service import DomainOutOfScope
from ..core.audit_context import audit_context_from_request

_DOMAIN_RE = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')




def _validate_domain_path(domain, cert_base_dir):
    """Validate domain name to prevent path traversal. Returns (Path, error_msg)."""
    if not domain or '..' in domain or '/' in domain or '\\' in domain or '\x00' in domain:
        return None, 'Invalid domain name'
    if not _DOMAIN_RE.match(domain):
        return None, 'Invalid domain format'
    cert_dir = Path(cert_base_dir) / domain
    try:
        resolved = cert_dir.resolve()
        base_resolved = Path(cert_base_dir).resolve()
        if not str(resolved).startswith(str(base_resolved) + os.sep) and resolved != base_resolved:
            return None, 'Invalid domain path'
    except (OSError, ValueError):
        return None, 'Invalid domain path'
    return cert_dir, None


def _certificate_fingerprint(cert_bytes):
    """Return a stable SHA-256 fingerprint for a PEM or DER certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert_bytes = cert_bytes or b''
    if not cert_bytes:
        return None

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_bytes)
    return cert.fingerprint(hashes.SHA256()).hex()


def _san_dns_names(cert):
    """Return the dNSName SANs of a parsed x509 cert, or [] if it has none."""
    from cryptography import x509

    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        return san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _certificate_subject_summary(cert_bytes):
    """Return a short human-readable identity for a served certificate.

    Emits the subject CN plus the first few SAN dNSNames, e.g.
    ``CN=example.com; SAN=example.com, www.example.com``. Best-effort and
    purely diagnostic: it feeds the deployment-status mismatch reason so an
    operator can see WHICH cert a host is actually serving. Never used for a
    trust decision. Returns '' when the bytes cannot be parsed.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    if not cert_bytes:
        return ''
    try:
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        except ValueError:
            cert = x509.load_der_x509_certificate(cert_bytes)
        parts = []
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            parts.append('CN=' + str(cn[0].value))
        sans = _san_dns_names(cert)
        if sans:
            shown = ', '.join(sans[:3]) + (', ...' if len(sans) > 3 else '')
            parts.append('SAN=' + shown)
        return '; '.join(parts)
    except Exception:
        return ''


def _privkey_to_pkcs1(pem_bytes):
    """Re-serialize a PEM private key into the legacy PKCS#1/SEC1
    ("TraditionalOpenSSL") form for stacks that don't accept the PKCS#8
    that certbot writes (issue #233).

    Raises ValueError/TypeError for key types that have no traditional
    encoding (e.g. Ed25519); the caller maps that to a 422.
    """
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem_bytes, password=None)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _tls_probe_timeout_seconds():
    """Read CERTMATE_TLS_PROBE_TIMEOUT_SECONDS, clamped to [1, 30]. Default 3s.

    Each probe blocks one Flask worker thread for up to this many seconds on
    an unreachable host. Lower = workers free up faster; higher = fewer false
    negatives on legitimately-slow targets. The default of 3s is a deliberate
    drop from the previous 5s — production /api/certificates dashboards that
    surface deployment status for ~50 domains can otherwise stall an
    operator-facing handler for tens of seconds when several targets are
    down.
    """
    raw = os.getenv('CERTMATE_TLS_PROBE_TIMEOUT_SECONDS', '').strip()
    if not raw:
        return 3.0
    try:
        value = float(raw)
    except ValueError:
        return 3.0
    return max(1.0, min(value, 30.0))


_PROBE_PROTOCOLS = ('https-tls', 'tls', 'smtp-starttls')


def _https_proxy_for(host):
    """Return (proxy_host, proxy_port, auth_headers) for tunneling to *host*.

    Honours the standard HTTPS_PROXY/https_proxy env vars and the NO_PROXY
    bypass list (via urllib). Returns None when no proxy applies, so the probe
    falls back to a direct connection. A raw socket ignores these env vars, so
    without this CertMate cannot reach external targets on a machine that
    requires an outbound HTTP proxy (#326).
    """
    proxy = urllib.request.getproxies().get('https')
    if not proxy or urllib.request.proxy_bypass(host):
        return None
    parts = urllib.parse.urlsplit(proxy if '://' in proxy else 'http://' + proxy)
    if not parts.hostname:
        return None
    headers = {}
    if parts.username:
        raw = f"{urllib.parse.unquote(parts.username)}:{urllib.parse.unquote(parts.password or '')}"
        token = base64.b64encode(raw.encode()).decode()
        headers['Proxy-Authorization'] = f'Basic {token}'
    return parts.hostname, parts.port or 8080, headers


def _probe_tls_certificate(domain, port=443, protocol='https-tls', timeout=None,
                           probe_host=None):
    """Return the live TLS certificate for a domain, if reachable.

    Supports three protocol modes:
      - ``https-tls`` (default): direct TLS on the given port (like HTTPS).
      - ``tls``:           same wire format as https-tls, no HTTP assumption.
      - ``smtp-starttls``: plain-text SMTP connection, then STARTTLS upgrade.

    ``timeout=None`` reads ``CERTMATE_TLS_PROBE_TIMEOUT_SECONDS`` (default 3s,
    clamped [1, 30]). ``port`` defaults to 443 for https-tls/tls, 587 for
    smtp-starttls when left at the sentinel 0.

    ``probe_host`` overrides both the TCP target and the SNI server name. The
    caller MUST pass it for a wildcard cert (``*.example.com``): a wildcard does
    NOT cover its own apex per RFC 6125, so the legacy apex-stripping fallback
    below probes the wrong host and reports a false "wrong cert" (#207/#381).
    When omitted, a non-wildcard domain probes itself; a wildcard falls back to
    the (incorrect) apex only for direct/legacy callers.
    """
    if timeout is None:
        timeout = _tls_probe_timeout_seconds()
    if protocol not in _PROBE_PROTOCOLS:
        raise ValueError(f"Unsupported probe protocol: {protocol!r}. "
                         f"Use one of {_PROBE_PROTOCOLS}")

    # Port defaults per protocol
    if port is None or port == 0:
        port = 587 if protocol == 'smtp-starttls' else 443

    if probe_host:
        host = probe_host
    else:
        host = domain[2:] if domain.startswith('*.') else domain
    context = ssl.create_default_context()
    # We intentionally disable PKI validation here. The goal is to compare the
    # served certificate fingerprint against the stored certificate, even when
    # the live cert is invalid or otherwise not trusted.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # create_default_context() already floors at TLS 1.2; pin it explicitly so
    # the fingerprint-comparison probe can never negotiate a dead protocol and
    # to make CodeQL's py/insecure-protocol check provably satisfied.
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    started = time.monotonic()
    try:
        if protocol == 'smtp-starttls':
            cert_bytes = _probe_smtp_starttls(host, port, context, timeout)
        else:
            # Direct TLS (https-tls, tls). When an HTTPS_PROXY applies (and the
            # host isn't in NO_PROXY) tunnel the TCP leg through the proxy with
            # HTTP CONNECT, then run the TLS handshake over that tunnel so we
            # still read the real peer certificate (#326).
            proxy = _https_proxy_for(host)
            if proxy:
                proxy_host, proxy_port, proxy_headers = proxy
                conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
                try:
                    conn.set_tunnel(host, port, headers=proxy_headers)
                    conn.connect()
                    with context.wrap_socket(conn.sock, server_hostname=host) as tls_sock:
                        cert_bytes = tls_sock.getpeercert(binary_form=True)
                finally:
                    conn.close()
            else:
                with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                    with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                        cert_bytes = tls_sock.getpeercert(binary_form=True)

        return {
            'reachable': True,
            'certificate_bytes': cert_bytes,
            'port': port,
            'protocol': protocol,
        }
    finally:
        elapsed = time.monotonic() - started
        # A probe that takes more than 1s is a strong hint the target is slow
        # or unreachable. Surfacing it in the application log lets an operator
        # spot the offending domain without reproducing a multi-second
        # dashboard stall — and lets them tune CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
        # if the slowness is real but expected.
        if elapsed > 1.0:
            logger.warning(
                "Slow %s probe for %s:%d: %.2fs (timeout=%.1fs).",
                protocol, host, port, elapsed, timeout,
            )


def _probe_smtp_starttls(host, port, context, timeout):
    """Connect to an SMTP server and upgrade to TLS via STARTTLS.

    SMTP wire: banner → ``EHLO certmate.local`` → ``STARTTLS`` →
    220 response → ``context.wrap_socket``.
    """

    recv_timeout = max(1.0, timeout * 0.5)
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(recv_timeout)
        f = raw_sock.makefile('rwb')

        # Read banner
        banner = f.readline()
        if not banner:
            raise ConnectionError("SMTP: no banner received")

        # EHLO
        f.write(b'EHLO certmate.local\r\n')
        f.flush()
        _consume_smtp_multiline(f)

        # STARTTLS
        f.write(b'STARTTLS\r\n')
        f.flush()
        response = f.readline()
        if not response or not response.startswith(b'220'):
            raise ConnectionError(
                f"SMTP STARTTLS rejected: {response!r}"
            )

        # Upgrade to TLS
        tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
        return tls_sock.getpeercert(binary_form=True)


def _consume_smtp_multiline(f):
    """Read SMTP multi-line response until a line starting with a digit
    followed by a space (not '-') is seen."""
    while True:
        line = f.readline()
        if not line:
            break
        if len(line) > 3 and line[3:4] == b' ':
            break


logger = logging.getLogger(__name__)


def create_api_resources(api, models, managers):
    """Create and register all API resource classes

    Args:
        api: Flask-RESTX Api instance
        models: Dictionary of API models
        managers: Dictionary of manager instances (auth, settings, certificates, etc.)
    """

    # The manager set and the helpers that used to be captured here now live
    # in modules/api/resource_context.py, so a resource class can be moved into
    # a module of its own without dragging this closure with it (#669). The
    # local names below are aliases kept during the decomposition: call sites
    # move group by group, not all at once.
    ctx = build_context(managers)
    # Groups that have moved into modules of their own build here and
    # are merged into the returned mapping below (#669).
    settings_resources = create_settings_resources(api, models, ctx)
    extracted = {
        # Only the two factory.py registers from the returned mapping; the
        # DNS account resources are bound to a namespace below instead, and
        # adding them here would change what this function hands back.
        'Settings': settings_resources['Settings'],
        'DNSProviders': settings_resources['DNSProviders'],
        **create_cache_resources(api, models, ctx),
        **create_health_resources(api, models, ctx),
        **create_backup_resources(api, models, ctx),
        **create_inventory_resources(api, models, ctx),
        **create_ca_resources(api, models, ctx),
    }
    auth_manager = ctx.auth
    settings_manager = ctx.settings
    certificate_manager = ctx.certificates
    file_ops = ctx.file_ops
    cache_manager = ctx.cache
    dns_manager = ctx.dns
    deploy_manager = ctx.deployer
    audit_logger = ctx.audit
    cert_service = ctx.cert_service
    cert_executor = ctx.cert_executor

    def _wants_async(payload):
        return wants_async(payload)

    def _job_accepted(job_id, operation, domain):
        return job_accepted(job_id, operation, domain,
                            f'/api/certificates/jobs/{job_id}')

    def _check_domain_scope(domain, operation):
        return check_domain_scope(ctx, domain, operation)

    def _record_in_scope(record):
        return is_record_in_scope(ctx, record)

    def _scope_filter_records(records):
        return scope_filter_records(ctx, records)

    # Health check endpoint

    # Metrics endpoints

    # Diagnostic snapshot endpoint — closes #150. Powers the "Report this
    # issue" button in the error toast: when an admin hits a recoverable
    # API error, the UI fetches this snapshot, merges it with the
    # client-side context (browser, page, error envelope), formats the
    # whole thing as Markdown, copies it to the clipboard, and opens
    # github.com/issues/new pre-filled. Operators reading the resulting
    # issue see an actionable bug report instead of "doesn't work".
    #
    # Security stance: admin-only via require_role('admin'). The response
    # is built from a fixed allowlist of scalar fields plus a sanitized
    # tail of the audit log — never the full settings tree, never any
    # secret, never resource identifiers from the audit entries
    # (resource_id / user / ip_address / details / error are stripped).
    # Sanitization is enforced inline in this handler, not deferred to a
    # generic mask helper, so a future contributor adding a field is
    # forced to think about whether to include it.

    # Settings endpoints

    # DNS Providers endpoint

    # Cache management endpoints


    # Certificate endpoints
    class CertificateList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_list_with(models['certificate_model'])
        @auth_manager.require_role('viewer')
        def get(self):
            """List all certificates.

            Scoped API keys with allowed_domains only see certificates
            within their scope. Unrestricted callers (legacy keys, local
            users) see every certificate.
            """
            try:
                user = getattr(request, 'current_user', None) or {}
                scope = user.get('allowed_domains')
                settings = settings_manager.load_settings()
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
                for cert_dir_path in iter_cert_domain_dirs(certificate_manager.cert_dir):
                    all_domains.add(cert_dir_path.name)

                # Get certificate info for all domains, filtered by the
                # caller's API-key scope. domain_matches_scope(d, None) is
                # always True so unrestricted callers see everything.
                for domain in all_domains:
                    if not domain:
                        continue
                    if not auth_manager.domain_matches_scope(domain, scope):
                        continue
                    # Reuse the once-loaded settings dict so each per-domain
                    # call skips its own settings deepcopy (load_settings is
                    # already request-cached on flask.g). use_cache stays at
                    # its default True so the storage-backend cert-info cache
                    # is still consulted/populated during listing.
                    cert_info = certificate_manager.get_certificate_info(domain, settings=settings)
                    if cert_info:
                        cert_info['auto_renew'] = auto_renew_by_domain.get(domain, True)
                        certificates.append(cert_info)

                return certificates
            except Exception as e:
                logger.error(f"Error listing certificates: {e}")
                return {'error': 'Failed to list certificates'}, 500

    # --- Certificate inventory (discovery) -------------------------------- #
    # The inventory is populated by the deep TLS probe (#467), scheduled
    # endpoint discovery (#469) and CT-log monitoring (#470). These endpoints
    # expose it to the dashboard (#471). cert_inventory / cert_discovery /
    # ct_monitor are optional managers (absent in minimal-manager unit setups),
    # so every handler guards for their absence with a 503.





    class CreateCertificate(Resource):
        @api.doc(security='Bearer')
        @api.expect(models['create_cert_model'])
        @auth_manager.require_role('operator')
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
                if _wants_async(data) and cert_executor is not None:
                    prepared = cert_service.prepare_create(
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
                    job_id = cert_executor.submit(
                        'create', domain,
                        lambda: cert_service.issue_create(prepared),
                    )
                    return _job_accepted(job_id, 'create', domain), 202

                result = cert_service.create(
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

    class ZombieScan(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def post(self):
            """Scan active certificates for zombie domains."""
            try:
                from ..core.zombie import ZombieScanner
                
                user = getattr(request, 'current_user', None) or {}
                scope = user.get('allowed_domains')
                settings = settings_manager.load_settings()
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
                for cert_dir_path in iter_cert_domain_dirs(certificate_manager.cert_dir):
                    all_domains.add(cert_dir_path.name)

                # Get certificate info for all domains
                for domain in all_domains:
                    if not domain:
                        continue
                    if not auth_manager.domain_matches_scope(domain, scope):
                        continue
                    # Reuse the once-loaded settings dict so each per-domain
                    # call skips its own settings deepcopy (load_settings is
                    # already request-cached on flask.g). use_cache stays at
                    # its default True so the storage-backend cert-info cache
                    # is still consulted/populated during the scan.
                    cert_info = certificate_manager.get_certificate_info(domain, settings=settings)
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
        @auth_manager.require_role('viewer')
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

            return certificate_manager.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=san_domains,
            ), 200

    class CertificateDNSAliasCheck(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self, domain):
            """Check DNS-01 alias CNAME records for an existing certificate."""
            _, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            scope_err = _check_domain_scope(domain, 'dns_alias_check')
            if scope_err:
                return scope_err
            cert_info = certificate_manager.get_certificate_info(domain)
            if not cert_info or not cert_info.get('exists'):
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            domain_alias = cert_info.get('domain_alias')
            if not domain_alias:
                return {'error': f'Certificate {domain} is not using DNS-01 alias mode'}, 400

            return certificate_manager.check_dns_alias_records(
                domain,
                domain_alias,
                san_domains=cert_info.get('san_domains') or [],
            ), 200

    class CertificateDetail(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
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
            cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir or not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404
            try:
                cert_info = certificate_manager.get_certificate_info(domain)
                if not cert_info:
                    return {'error': f'Certificate not found for domain: {domain}'}, 404
                # Mirror CertificateList.get's per-domain auto_renew enrichment so
                # the single-domain response shape matches the list response.
                settings = settings_manager.load_settings()
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
        @auth_manager.require_role('operator')
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
            cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
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
                settings = settings_manager.load_settings()
                dns_config, _ = dns_manager.get_dns_provider_account_config(
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
                settings = settings_manager.load_settings()
                alias_config, _ = dns_manager.get_dns_provider_account_config(
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
                with certificate_manager.domain_lock(domain):
                    # 1. Update on-disk metadata.json. Read through the manager
                    # (which builds the path from the already-validated domain
                    # and quarantines corrupt JSON instead of silently returning
                    # {}) rather than opening cert_dir/'metadata.json' directly.
                    metadata = certificate_manager._load_metadata(domain)

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

                    if not certificate_manager._save_metadata(domain, metadata):
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

                settings_manager.update(_update_domain_provider, "dns_provider_change")

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
        @auth_manager.require_role('admin')
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
            _, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            try:
                deleted = certificate_manager.delete_certificate(domain)
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
                    settings_manager.update(_drop_domain, reason='certificate_delete')
                except _AlreadyAbsent:
                    pass
                except Exception as e:
                    logger.warning(f"Removed cert for {domain} but failed to update settings: {e}")

                event_bus = current_app.config.get('EVENT_BUS')
                if event_bus:
                    event_bus.publish('certificate_deleted', {'domain': domain})

                if audit_logger:
                    user = getattr(request, 'current_user', None) or {}
                    audit_logger.log_operation(
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

    # Files containing private-key material. A viewer-role caller is
    # permitted to download public certificate material (cert, chain,
    # fullchain) but anything that exposes the private key requires
    # operator role. The default ZIP includes privkey.pem and is
    # therefore also operator-gated. (2026-05-12 API auth audit
    # follow-up: viewer-can-pull-privkey was an information-disclosure
    # surface that the original endpoint exposed.)
    _PRIVATE_KEY_FILES = frozenset({'privkey.pem', 'combined.pem', 'cert.pfx'})
    _PUBLIC_DOWNLOAD_FILES = frozenset({'cert.pem', 'chain.pem', 'fullchain.pem'})

    def _user_has_role(user, min_role):
        return user_has_role(user, min_role)

    class CertificateDeploymentStatus(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        @api.marshal_with(models['deployment_status_model'])
        def get(self, domain):
            """Check whether the domain is serving the expected certificate."""
            refresh_requested = str(request.args.get('refresh', '')).lower() in {'1', 'true', 'yes', 'on'}
            _, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            scope_err = _check_domain_scope(domain, 'deployment_status')
            if scope_err:
                return scope_err

            cert_info = certificate_manager.get_certificate_info(domain)
            if not cert_info or not cert_info.get('exists'):
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            if refresh_requested:
                cache_manager.remove_from_cache(domain)
            else:
                cached_result = cache_manager.get_deployment_status(domain)
                if isinstance(cached_result, dict) and cached_result.get('domain') == domain:
                    return cached_result, 200

            expected_bytes = None
            storage_manager = getattr(certificate_manager, 'storage_manager', None)
            if storage_manager is not None:
                try:
                    storage_result = storage_manager.retrieve_certificate(domain)
                    if storage_result:
                        cert_files, _metadata = storage_result
                        expected_bytes = cert_files.get('cert.pem')
                except Exception as e:
                    logger.warning(f"Could not read stored certificate for {domain}: {e}")

            if expected_bytes is None:
                cert_path = Path(file_ops.cert_dir) / domain / 'cert.pem'
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
            metadata = certificate_manager._load_metadata(domain) if hasattr(certificate_manager, '_load_metadata') else {}
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
                    f"wrong host. Set a deployment_host that this wildcard "
                    f"covers (for example www.{apex}) via "
                    f"PATCH /api/certificates/{domain} to enable the check."
                )
                persisted_status = certificate_manager.get_deployment_status_record(domain)
                if isinstance(persisted_status, dict) and persisted_status.get('browser'):
                    result['browser'] = persisted_status.get('browser')
                certificate_manager.record_backend_deployment_status(domain, result)
                cache_manager.set_deployment_status(domain, result)
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

            persisted_status = certificate_manager.get_deployment_status_record(domain)
            if isinstance(persisted_status, dict) and persisted_status.get('browser'):
                result['browser'] = persisted_status.get('browser')

            certificate_manager.record_backend_deployment_status(domain, result)
            cache_manager.set_deployment_status(domain, result)
            return result, 200

    class CertificateDeploymentBrowserReports(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
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

                _, err = _validate_domain_path(domain, file_ops.cert_dir)
                if err:
                    skipped.append({'domain': domain, 'error': err})
                    continue
                scope_err = _check_domain_scope(domain, 'browser_report')
                if scope_err:
                    skipped.append({'domain': domain, 'error': 'out of scope'})
                    continue

                browser_status = certificate_manager.record_browser_deployment_status(domain, report)
                persisted = certificate_manager.get_deployment_status_record(domain)
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
                cache_manager.set_deployment_status(domain, merged)
                updated.append(domain)

            return {
                'updated': updated,
                'skipped': skipped,
                'count': len(updated),
            }, 200

    class DownloadCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self, domain):
            """Download certificate files as ZIP, JSON, or individual file.

            Role gating is per-file: viewers can pull public material
            (cert.pem, chain.pem, fullchain.pem) and the public-only ZIP
            (?include_private=0); anything that exposes the private key
            (privkey.pem, combined.pem, format=json, default ZIP)
            requires operator role.

            ?file=privkey.pem&key_format=pkcs1 serves the key in legacy
            PKCS#1/SEC1 form for stacks that reject certbot's PKCS#8
            (issue #233); the default is the on-disk PKCS#8.

            ?format=json&key_format=pkcs1 adds private_key_pkcs1_pem to the
            JSON alongside the untouched private_key_pem, so an automation
            can pull everything it needs in one call instead of downloading
            the key a second time as a file (issue #398). The field is named
            for the encoding, not RSA: for an ECDSA key the traditional form
            is SEC1 ("BEGIN EC PRIVATE KEY"), and CertMate issues ECDSA by
            default.

            ?file=cert.pfx serves the encrypted PKCS#12 bundle when a PFX
            export password is configured (issue #230); 404 otherwise. It
            contains the private key, so it requires operator role.
            """
            try:
                scope_err = _check_domain_scope(domain, 'download')
                if scope_err:
                    return scope_err
                cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}'}, 404

                user = getattr(request, 'current_user', None) or {}
                download_format = request.args.get('format')
                # Check for the optional 'file' parameter
                requested_file = request.args.get('file')
                include_private = str(request.args.get('include_private', '1')).lower() not in ('0', 'false', 'no', 'off')

                if download_format and download_format not in ['json']:
                    return {'error': 'Invalid format requested.'}, 400

                # Optional private-key serialization. Certbot stores PKCS#8
                # ("BEGIN PRIVATE KEY"); some older stacks need the legacy
                # PKCS#1 form ("BEGIN RSA PRIVATE KEY"). Convert on download
                # rather than duplicating key material on disk (issue #233).
                key_format = request.args.get('key_format')
                if key_format is not None and key_format not in ('pkcs1', 'pkcs8'):
                    return {'error': "Invalid key_format; use 'pkcs1' or 'pkcs8'."}, 400
                if key_format and download_format != 'json' and requested_file != 'privkey.pem':
                    return {
                        'error': 'key_format applies to ?file=privkey.pem or ?format=json.'
                    }, 400

                def _privkey_denied(file_label):
                    """Emit audit + return 403 for viewer trying to pull privkey."""
                    if audit_logger:
                        audit_logger.log_authz_denied(
                            operation='download',
                            resource_type='certificate',
                            resource_id=domain,
                            reason=f'viewer cannot download private-key material ({file_label})',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'error': 'operator role required to download private key material',
                        'code': 'PRIVKEY_REQUIRES_OPERATOR',
                        'hint': f'Use ?file=fullchain.pem or ?include_private=0 to download public material as a viewer.',
                    }, 403

                if download_format == 'json':
                    # format=json always returns private_key_pem inline.
                    # Restrict to operator+; viewer must use ?file=... for
                    # the specific public-material file they need.
                    if not _user_has_role(user, 'operator'):
                        return _privkey_denied('format=json')
                    if requested_file:
                        return {'error': 'format=json cannot be combined with file.'}, 400

                    required_files = {
                        'cert_pem': 'cert.pem',
                        'chain_pem': 'chain.pem',
                        'fullchain_pem': 'fullchain.pem',
                        'private_key_pem': 'privkey.pem',
                    }

                    try:
                        payload = {'domain': domain}
                        for response_key, filename in required_files.items():
                            file_path = cert_dir / filename
                            if not file_path.exists():
                                return {'error': f'Required cert file not found for domain {domain}: {filename}'}, 404
                            payload[response_key] = file_path.read_text(encoding='utf-8')

                        # ?key_format=pkcs1 adds the legacy/traditional form
                        # ALONGSIDE private_key_pem rather than replacing it,
                        # so an existing consumer of format=json is unaffected
                        # (issue #398). Converted from the bytes just read —
                        # no second file read, no second path to validate.
                        # pkcs8 is what is already on disk, so asking for it
                        # here is a no-op by design.
                        if key_format == 'pkcs1':
                            try:
                                payload['private_key_pkcs1_pem'] = _privkey_to_pkcs1(
                                    payload['private_key_pem'].encode('utf-8')
                                ).decode('utf-8')
                            except (ValueError, TypeError) as e:
                                # The message is included, not just the type:
                                # cryptography emits static, descriptive text
                                # ("Password was not given but private key is
                                # encrypted", "format is invalid with this
                                # key") that carries no key material and tells
                                # an operator which of several very different
                                # problems they have. CR/LF scrubbed like every
                                # other interpolated value here.
                                logger.error(
                                    "Failed to convert private key to PKCS#1: %s: %s",
                                    type(e).__name__,
                                    str(e).replace('\r', ' ').replace('\n', ' '),
                                )
                                return {
                                    'error': 'Could not convert the private key to PKCS#1 '
                                             '(the key type may not support it).'
                                }, 422

                        return jsonify(payload)
                    except FileNotFoundError:
                        return {'error': f'Required cert file not found for domain {domain}'}, 404

                if requested_file:
                    # Security check: only allow specific certificate files
                    allowed_files = _PUBLIC_DOWNLOAD_FILES | _PRIVATE_KEY_FILES
                    if requested_file not in allowed_files:
                        return {'error': 'Invalid file requested.'}, 400

                    # Private-key files require operator+; public files
                    # remain viewer-accessible.
                    if requested_file in _PRIVATE_KEY_FILES and not _user_has_role(user, 'operator'):
                        return _privkey_denied(requested_file)

                    if requested_file == 'combined.pem':
                        try:
                            # Read both files and join them
                            fullchain = (cert_dir / 'fullchain.pem').read_text(encoding='utf-8')
                            privkey = (cert_dir / 'privkey.pem').read_text(encoding='utf-8')
                            combined_data = io.BytesIO(f"{fullchain}{privkey}".encode())

                            return send_file(
                                combined_data,
                                as_attachment=True,
                                download_name=f'{domain}_combined.pem',
                                mimetype='application/x-pem-file'
                            )
                        except FileNotFoundError:
                            return {'error': f'Required cert files not found for domain {domain}'}, 404

                    file_path = cert_dir / requested_file
                    if not file_path.exists():
                        return {'error': f'File {requested_file} not found for domain {domain}'}, 404

                    if requested_file == 'privkey.pem' and key_format == 'pkcs1':
                        # Re-resolve with a constant filename and confirm the
                        # path stays inside the (already validated) domain dir
                        # before reading — defense in depth, and keeps the new
                        # file read off any tainted path component.
                        key_path = os.path.realpath(cert_dir / 'privkey.pem')
                        if not key_path.startswith(os.path.realpath(cert_dir) + os.sep):
                            return {'error': 'Invalid path'}, 400
                        try:
                            with open(key_path, 'rb') as fh:
                                pkcs1_pem = _privkey_to_pkcs1(fh.read())
                        except (ValueError, TypeError) as e:
                            # Same reasoning as the format=json branch above:
                            # the message is safe and diagnostic. Kept identical
                            # so the two conversion sites do not drift.
                            logger.error(
                                "Failed to convert private key to PKCS#1: %s: %s",
                                type(e).__name__,
                                str(e).replace('\r', ' ').replace('\n', ' '),
                            )
                            return {
                                'error': 'Could not convert the private key to PKCS#1 '
                                         '(the key type may not support it).'
                            }, 422
                        return send_file(
                            io.BytesIO(pkcs1_pem),
                            as_attachment=True,
                            download_name=f'{domain}_privkey_pkcs1.pem',
                            mimetype='application/x-pem-file',
                        )

                    file_mimetype = (
                        'application/x-pkcs12' if requested_file.endswith('.pfx')
                        else 'application/x-pem-file'
                    )
                    return send_file(
                        file_path,
                        as_attachment=True,
                        download_name=f'{domain}_{requested_file}',
                        mimetype=file_mimetype
                    )

                # Fallback ZIP. Two flavors:
                #   include_private=1 (default)  -> all 4 PEMs, operator+
                #   include_private=0            -> public material only,
                #                                   safe for viewer
                if include_private and not _user_has_role(user, 'operator'):
                    return _privkey_denied('default ZIP')

                files_to_zip = (
                    CERTIFICATE_FILES if include_private
                    else tuple(f for f in CERTIFICATE_FILES if f not in _PRIVATE_KEY_FILES)
                )
                # The encrypted PKCS#12 bundle (only present when a PFX password
                # is configured, #230/#465) is key-bearing, so it rides only in
                # the private ZIP. The loop below writes it only if it exists.
                if include_private:
                    files_to_zip = files_to_zip + ('cert.pfx',)
                zip_suffix = 'certificates' if include_private else 'certificates_public'

                # Create temporary ZIP file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                    tmp_path = tmp_file.name
                    with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for cert_file in files_to_zip:
                            file_path = cert_dir / cert_file
                            if file_path.exists():
                                zipf.write(file_path, cert_file)

                    @after_this_request
                    def remove_file(response):
                        try:
                            os.remove(tmp_path)
                        except Exception as e:
                            logger.debug(f"Could not remove temp file {tmp_path}: {e}")
                        return response

                    return send_file(
                        tmp_path,
                        as_attachment=True,
                        download_name=f'{domain}_{zip_suffix}.zip',
                        mimetype='application/zip'
                    )

            except Exception as e:
                logger.error(f"Error downloading certificate for {domain}: {e}")
                return {'error': 'Failed to download certificate'}, 500

    class DownloadCertificateFile(Resource):
        # Path-style alias for the query-string form on DownloadCertificate.
        # Documented in discussion #183 as the canonical scripting URL
        # (curl ... /api/certificates/<domain>/download/fullchain). Without
        # this route the documented URL returned 404 (issue #212).
        #
        # Short names map 1:1 to the on-disk filenames. The role gate and
        # path-traversal guards mirror the ?file= branch in
        # DownloadCertificate.get() — keep the two in sync.
        _SHORT_NAME_TO_FILE = {
            'cert': 'cert.pem',
            'chain': 'chain.pem',
            'fullchain': 'fullchain.pem',
            'privkey': 'privkey.pem',
            'combined': 'combined.pem',
        }

        @api.doc(security='Bearer')
        @auth_manager.require_role('viewer')
        def get(self, domain, file_type):
            """Download a single certificate file by short name.

            Path-style equivalent of ``?file=<name>.pem`` on the parent
            ``/download`` route. ``file_type`` is one of ``cert``,
            ``chain``, ``fullchain``, ``privkey``, ``combined``.

            Role gating: viewers can pull public material (cert, chain,
            fullchain); ``privkey`` and ``combined`` require operator+.
            """
            requested_file = self._SHORT_NAME_TO_FILE.get(file_type)
            if requested_file is None:
                return {
                    'error': f'Invalid file type: {file_type}',
                    'hint': f"Allowed: {sorted(self._SHORT_NAME_TO_FILE)}",
                }, 400

            try:
                scope_err = _check_domain_scope(domain, 'download')
                if scope_err:
                    return scope_err
                cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                if not cert_dir.exists():
                    return {'error': f'Certificate not found for domain: {domain}'}, 404

                user = getattr(request, 'current_user', None) or {}

                if requested_file in _PRIVATE_KEY_FILES and not _user_has_role(user, 'operator'):
                    if audit_logger:
                        audit_logger.log_authz_denied(
                            operation='download',
                            resource_type='certificate',
                            resource_id=domain,
                            reason=f'viewer cannot download private-key material ({requested_file})',
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'error': 'operator role required to download private key material',
                        'code': 'PRIVKEY_REQUIRES_OPERATOR',
                        'hint': 'Use /download/fullchain to pull public material as a viewer.',
                    }, 403

                if requested_file == 'combined.pem':
                    try:
                        fullchain = (cert_dir / 'fullchain.pem').read_text(encoding='utf-8')
                        privkey = (cert_dir / 'privkey.pem').read_text(encoding='utf-8')
                        combined_data = io.BytesIO(f"{fullchain}{privkey}".encode())
                        return send_file(
                            combined_data,
                            as_attachment=True,
                            download_name=f'{domain}_combined.pem',
                            mimetype='application/x-pem-file'
                        )
                    except FileNotFoundError:
                        return {'error': f'Required cert files not found for domain {domain}'}, 404

                file_path = cert_dir / requested_file
                if not file_path.exists():
                    return {'error': f'File {requested_file} not found for domain {domain}'}, 404

                return send_file(
                    file_path,
                    as_attachment=True,
                    download_name=f'{domain}_{requested_file}',
                    mimetype='application/x-pem-file'
                )
            except Exception as e:
                logger.error(f"Error downloading {file_type} for {domain}: {e}")
                return {'error': 'Failed to download certificate file'}, 500

    class RenewCertificate(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        def post(self, domain):
            """Renew an existing certificate"""
            try:
                payload = request.get_json(silent=True) or {}
                force = bool(payload.get('force', False))
                _, err = _validate_domain_path(domain, file_ops.cert_dir)
                if err:
                    return {'error': err}, 400
                user = getattr(request, 'current_user', None) or {}
                audit_ctx = audit_context_from_request()

                if _wants_async(payload) and cert_executor is not None:
                    prepared = cert_service.prepare_renew(
                        domain=domain, user=user, ip_address=request.remote_addr,
                        audit_ctx=audit_ctx,
                    )
                    job_id = cert_executor.submit(
                        'renew', domain,
                        lambda: cert_service.issue_renew(prepared, force=force),
                    )
                    return _job_accepted(job_id, 'renew', domain), 202

                result = cert_service.renew(
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
        @auth_manager.require_role('operator')
        def post(self, domain):
            """Edit a certificate's configuration and reissue it in place (#267).

            Omitted fields keep the values the certificate was issued with
            (read from its metadata), so extending or dropping SANs never
            requires re-entering DNS/alias/CA configuration. The old
            certificate keeps being served until certbot succeeds.
            """
            try:
                data = api.payload or {}
                _, err = _validate_domain_path(domain, file_ops.cert_dir)
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

                if _wants_async(data) and cert_executor is not None:
                    prepared = cert_service.prepare_reissue(**kwargs)
                    job_id = cert_executor.submit(
                        'reissue', domain,
                        lambda: cert_service.issue_reissue(prepared),
                    )
                    return _job_accepted(job_id, 'reissue', domain), 202

                result = cert_service.issue_reissue(
                    cert_service.prepare_reissue(**kwargs)
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
        @auth_manager.require_role('operator')
        def get(self, job_id):
            """Poll the status of an async create/renew job."""
            if cert_executor is None:
                return {'error': 'Async issuance is not enabled'}, 404
            job = cert_executor.get(job_id)
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
        @auth_manager.require_role('operator')
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
            if cert_executor is None:
                return {'error': 'Async issuance is not enabled'}, 404
            # Same boundary as polling a single job: a scoped key sees only
            # jobs for domains it could have created itself. Filtered rather
            # than refused, so a scoped key still gets its own in-flight work.
            user = getattr(request, 'current_user', None) or {}
            jobs = [
                job for job in cert_executor.list_active()
                if auth_manager.user_can_access_domain(user, job.get('domain'))
            ]
            return {'jobs': jobs, 'count': len(jobs)}, 200

    class CertificateAutoRenew(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('operator')
        def put(self, domain):
            """Enable or disable automatic renewal for a single certificate (issue #111).

            Body: {"enabled": true|false}
            """
            scope_err = _check_domain_scope(domain, 'set_auto_renew')
            if scope_err:
                return scope_err
            _, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            try:
                data = api.payload or {}
                if 'enabled' not in data:
                    return {'error': 'Missing "enabled" boolean in request body'}, 400
                enabled = bool(data.get('enabled'))

                updated = certificate_manager.set_auto_renew(domain, enabled)
                if not updated:
                    return {
                        'error': f'Domain {domain} not found in settings',
                        'hint': 'Only domains tracked in settings can have auto-renew toggled.'
                    }, 404

                if audit_logger:
                    actx = audit_context_from_request()
                    audit_logger.log_operation(
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

    class CertificateRunDeploy(Resource):
        @api.doc(security='Bearer')
        @auth_manager.require_role('admin')
        def post(self, domain):
            """Manually run all enabled deploy hooks for a domain (issue #109).

            Aligns with the role of /api/deploy/* (admin-only). Hooks run
            with CERTMATE_EVENT=manual; the on_events filter is ignored
            since the user explicitly requested execution.
            """
            scope_err = _check_domain_scope(domain, 'run_deploy')
            if scope_err:
                return scope_err
            if deploy_manager is None:
                return {'error': 'Deploy manager not available'}, 503

            cert_dir, err = _validate_domain_path(domain, file_ops.cert_dir)
            if err:
                return {'error': err}, 400
            if not cert_dir.exists():
                return {'error': f'Certificate not found for domain: {domain}'}, 404

            try:
                summary = deploy_manager.run_manual_deploy(domain)
            except Exception as e:
                logger.error(f"Manual deploy hook run failed for {domain}: {e}")
                if audit_logger:
                    actx = audit_context_from_request()
                    audit_logger.log_operation(
                        operation='deploy', resource_type='certificate',
                        resource_id=domain, status='failure', error=str(e)[:500],
                        details={'manual': True},
                        user=actx.get('user'), ip_address=actx.get('ip'),
                        actor=actx.get('actor'), trigger=actx.get('trigger'),
                    )
                return {'error': 'Manual deploy hook run failed'}, 500

            if audit_logger:
                actx = audit_context_from_request()
                audit_logger.log_operation(
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

    # Backup endpoints (Unified backup system for atomic consistency)


    # DNS Accounts management





    # Storage Backend Management






    # Register storage backend endpoints. Unlike the health, cache and backup
    # groups — which factory.py registers from the returned mapping — these
    # build their namespace here, so the classes are taken from `extracted`
    # rather than from the local scope they no longer occupy (#669).
    # Built here rather than merged into `extracted` above: unlike the health,
    # cache and backup groups, these are registered on a namespace of their own
    # right here instead of by factory.py from the returned mapping. Adding
    # them to that mapping would change what create_api_resources hands back,
    # which the resource contract test pins deliberately (#669).
    storage_resources = create_storage_resources(api, models, ctx)
    storage_ns = api.namespace('storage', description='Storage Backend Operations')
    storage_ns.add_resource(storage_resources['StorageBackendInfo'], '/info')
    storage_ns.add_resource(storage_resources['StorageBackendConfig'], '/config')
    storage_ns.add_resource(storage_resources['StorageBackendTest'], '/test')
    storage_ns.add_resource(storage_resources['StorageBackendMigrate'], '/migrate')
    storage_ns.add_resource(storage_resources['StorageAzureKeyVaultBackfill'],
                            '/azure-keyvault/backfill-certificates')

    # Register DNS management endpoints
    dns_ns = api.namespace('dns', description='DNS Provider Account Management')
    dns_ns.add_resource(settings_resources['DNSAccounts'], '/<string:provider>/accounts', endpoint='dns_accounts_provider')
    dns_ns.add_resource(settings_resources['DNSAccounts'], '/accounts', endpoint='dns_accounts_global')
    dns_ns.add_resource(settings_resources['DNSAccountDetail'], '/<string:provider>/accounts/<string:account_id>')

    # Return all resource classes (CA provider test will be registered in app.py)
    return {
        **extracted,
        'CertificateList': CertificateList,
        'CreateCertificate': CreateCertificate,
        'ZombieScan': ZombieScan,
        'CheckDNSAlias': CheckDNSAlias,
        'CertificateDNSAliasCheck': CertificateDNSAliasCheck,
        'CertificateDetail': CertificateDetail,
        'CertificateDeploymentStatus': CertificateDeploymentStatus,
        'CertificateDeploymentBrowserReports': CertificateDeploymentBrowserReports,
        'DownloadCertificate': DownloadCertificate,
        'DownloadCertificateFile': DownloadCertificateFile,
        'RenewCertificate': RenewCertificate,
        'CertificateReissue': CertificateReissue,
        'CertificateJob': CertificateJob,
        'CertificateJobs': CertificateJobs,
        'CertificateAutoRenew': CertificateAutoRenew,
        'CertificateRunDeploy': CertificateRunDeploy,
    }
