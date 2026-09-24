import logging
from flask import abort as flask_abort, request, send_file, Response
from ..core.client_certificates import DEFAULT_COUNTRY, DEFAULT_STATE
from ..core.domain_paths import IDENTIFIER_RE, is_path_safe_segment
from werkzeug.exceptions import HTTPException
from flask_restx import Resource, fields
from io import BytesIO

logger = logging.getLogger(__name__)

# Typed by hand by whoever means it. See ClientCertificateAuthorityReset.
CA_RESET_CONFIRMATION = 'reset-client-ca'


def abort(status, message, code=None):
    """Refuse in the same envelope as the rest of the API.

    These resources are the only ones in the codebase that answer through
    flask-restx's ``abort``, and its body is ``{"message": ...}`` — no
    ``error``, no ``code``. Everything else returns ``{'error': ..., 'code':
    ...}``, so one API replied in two shapes depending on which file the
    endpoint lived in, and a client could not read a failure the same way
    twice.

    ``abort`` puts its keyword arguments straight onto the exception as
    ``data``, and flask-restx returns that verbatim — which is also why an
    ``@api.errorhandler`` cannot fix this from outside. So the envelope is
    added here. ``message`` is kept alongside ``error`` rather than replaced:
    every existing client of these endpoints reads it, and this is a change
    that only ADDS fields.

    ``code`` defaults to the symbol for the status rather than to a
    per-call-site invention: a uniform, honest answer beats fifty new
    constants nobody has a use for yet. Pass one where it earns its keep.
    """
    from ..core.factory import error_code_for_status
    try:
        flask_abort(status)
    except HTTPException as exc:
        # Exactly what flask_restx.abort does with its kwargs, done here
        # because its own first parameter is named `code`, so it cannot carry a
        # payload key of that name — and `code` is the field this envelope is
        # about.
        exc.data = {
            'error': str(message),
            'message': str(message),
            'code': code or error_code_for_status(
                status, _STATUS_NAMES.get(status, '')),
            'status': status,
        }
        raise


# The werkzeug names for the statuses these resources use, so the symbolic code
# reads NOT_FOUND rather than NotFound.
_STATUS_NAMES = {
    400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found',
    409: 'Conflict', 422: 'Unprocessable Entity', 500: 'Internal Server Error',
    503: 'Service Unavailable',
}

def _validate_identifier(identifier):
    """Validate client certificate identifier to prevent path traversal.

    The character rule and the pattern both live in ``core.domain_paths`` (#672).
    They were written here as a fourth copy, and carried the same `$` anchor the
    other copies had.
    """
    return (is_path_safe_segment(identifier)
            and bool(IDENTIFIER_RE.match(identifier)))


def create_client_certificate_models(api):
    """Create Flask-RESTX models for client certificates."""

    client_cert_model = api.model('ClientCertificate', {
        'identifier': fields.String(required=True, description='Certificate identifier'),
        'common_name': fields.String(required=True, description='Common name'),
        'email': fields.String(description='Email address'),
        'organization': fields.String(description='Organization'),
        'cert_usage': fields.String(description='Usage type (vpn, api-mtls, etc)'),
        'created_at': fields.String(description='Creation date'),
        'expires_at': fields.String(description='Expiration date'),
        'revoked': fields.Boolean(description='Revocation status'),
        'notes': fields.String(description='Additional notes')
    })

    client_cert_request_model = api.model('ClientCertificateRequest', {
        'common_name': fields.String(required=True, description='Common name'),
        'email': fields.String(description='Email address'),
        'organization': fields.String(description='Organization'),
        'organizational_unit': fields.String(description='Organizational unit'),
        'cert_usage': fields.String(description='Usage type'),
        'days_valid': fields.Integer(description='Days until expiration'),
        'generate_key': fields.Boolean(description='Generate private key'),
        'csr': fields.String(
            description=('PEM certificate signing request. Required when '
                         'generate_key is false — the device that made the '
                         'key keeps it and CertMate never sees it.')),
        'country': fields.String(
            description='Subject country (2 letters). Default: CH'),
        'state': fields.String(
            description='Subject state or province. Default: Switzerland'),
        'notes': fields.String(description='Additional notes')
    })

    client_cert_revoke_model = api.model('ClientCertificateRevoke', {
        'reason': fields.String(description='Reason for revocation')
    })

    return {
        'client_cert': client_cert_model,
        'client_cert_request': client_cert_request_model,
        'client_cert_revoke': client_cert_revoke_model
    }


def _client_cert_create_params(data):
    """Validate a client-certificate create payload into manager kwargs.

    Lifted out of `create_client_certificate_resources`, whose complexity is
    pinned by scripts/check_complexity_budget.py at a ceiling that only comes
    down — and every field validated here is a branch that was counting
    against it.
    """
    common_name = data.get('common_name', '')
    if not common_name or len(common_name) > 64:
        abort(400, "common_name must be between 1 and 64 characters")
    email = data.get('email', '')
    if len(email) > 254:
        abort(400, "email must be 254 characters or less")
    organization = data.get('organization', 'CertMate')
    if len(organization) > 64:
        abort(400, "organization must be 64 characters or less")
    organizational_unit = data.get('organizational_unit', 'Users')
    if len(organizational_unit) > 64:
        abort(400, "organizational_unit must be 64 characters or less")
    try:
        days_valid = int(data.get('days_valid', 365))
    except (TypeError, ValueError):
        abort(400, "days_valid must be an integer")
    if days_valid < 1 or days_valid > 3650:
        abort(400, "days_valid must be between 1 and 3650")
    country = data.get('country', '') or DEFAULT_COUNTRY
    if len(country) > 2:
        abort(400, "country must be a 2-letter code")
    state = data.get('state', '') or DEFAULT_STATE
    if len(state) > 128:
        abort(400, "state must be 128 characters or less")

    # The core has taken `csr_pem` since #599; the request model had no field
    # for it, so `generate_key: false` could only ever fail — while the UI's
    # "generate private key" checkbox posts exactly that when unticked. The
    # error was "CSR required when generate_key=False" for a request that had
    # no way to carry one.
    generate_key = data.get('generate_key', True)
    csr = data.get('csr') or data.get('csr_pem')
    if not generate_key and not csr:
        abort(400, "csr is required when generate_key is false")

    return {
        'common_name': common_name,
        'email': email,
        'organization': organization,
        'organizational_unit': organizational_unit,
        'cert_usage': data.get('cert_usage', 'api-mtls'),
        'days_valid': days_valid,
        'generate_key': generate_key,
        'csr_pem': csr.encode('utf-8') if isinstance(csr, str) else csr,
        'country': country,
        'state': state,
        'notes': data.get('notes', ''),
    }


def _build_ca_cert_resource(client_cert_manager):
    """The CA-certificate download, built outside the big closure.

    Same reason as _build_ca_reset_resource below: adding one more class
    inside create_client_certificate_resources raises its complexity past the
    number scripts/check_complexity_budget.py pins, and that number only ever
    comes down.
    """

    class ClientCertificateAuthorityCert(Resource):
        """Serve the CA certificate a relying party has to trust.

        Two comments in private_ca.py explain the 0600 file mode by saying
        the CA cert "is served over HTTP by certmate, not read off disk by
        other local users" — and nothing served it. `get_ca_cert_pem` and
        `export_ca_cert` had no callers outside tests, and the only /ca route
        in the whole url_map was POST /ca/reset.

        So a server that had to verify client certificates could not obtain
        the CA except out of the PKCS#12 bundle, which needs operator rights
        and a configured password and ships a private key with it.

        Public, like the CRL next door: this is the certificate every relying
        party is meant to have, and withholding it protects nothing.
        """

        def get(self):
            """Download the client-certificate CA certificate (PEM)."""
            try:
                if not client_cert_manager:
                    abort(503, "Client certificate manager not available")
                ca_pem = client_cert_manager.private_ca.get_ca_cert_pem()
                if not ca_pem:
                    abort(404, "No CA certificate available")
                if isinstance(ca_pem, str):
                    ca_pem = ca_pem.encode('utf-8')
                return Response(
                    ca_pem,
                    mimetype='application/x-pem-file',
                    headers={'Content-Disposition': 'attachment; filename=ca.crt'}
                )
            except HTTPException:
                raise
            except OSError as e:
                # `get_ca_cert_pem` checks the path exists and then reads it,
                # so the only failure it can hand back is the read: a
                # permission problem, a truncated volume, a mount that went
                # away between the two. Narrow rather than broad, because
                # this is one file read and the budget in
                # scripts/check_exception_budget.py is a ratchet — a `except
                # Exception` here would raise the pinned count for the sake
                # of a call that cannot raise anything else.
                logger.error("Error serving CA certificate: %s", e)
                abort(500, "Failed to serve CA certificate")

    return ClientCertificateAuthorityCert


def _build_ca_reset_resource(auth_manager, client_cert_manager, crl_manager):
    """The CA reset resource, built outside create_client_certificate_resources.

    That function is a 3k-line closure registering every client-certificate
    resource, and scripts/check_complexity_budget.py pins it at a number that
    only comes down. Defining one more class inside it pushed it from 89 to 98;
    taking the dependencies as arguments instead leaves it where it was, and
    this is the shape the rest of those closures should eventually take.
    """
    class ClientCertificateAuthorityReset(Resource):
            # The most destructive action in this namespace: it discards every
            # client identity this instance has ever signed. Admin, and it takes
            # more than a POST to trigger.
            method_decorators = [auth_manager.require_role('admin')]

            def post(self):
                """Rebuild the client CA and remove the certificates it signed."""
                try:
                    data = request.get_json(silent=True) or {}

                    # A typed phrase, not a boolean. `{"confirm": true}` is what a
                    # mis-sent form or a retried request produces; this is not.
                    if data.get('confirm') != CA_RESET_CONFIRMATION:
                        abort(400,
                              f"This destroys every client certificate signed by "
                              f"the current CA and cannot be undone. Send "
                              f'{{"confirm": "{CA_RESET_CONFIRMATION}"}} to proceed.')

                    subject = data.get('subject')
                    if subject is not None and not isinstance(subject, dict):
                        abort(400, "subject must be an object with country, state, "
                                   "organization, organizational_unit and common_name")

                    actor = getattr(getattr(request, 'current_user', None), 'get', lambda *_: None)('username')
                    success, error, summary = client_cert_manager.reset_certificate_authority(
                        subject=subject, actor=actor)
                    if not success:
                        abort(400, error or "Failed to reset the certificate authority")

                    # The CRL is signed by the CA key. The old one cannot be
                    # verified against the new CA, and what it revoked no longer
                    # exists, so republish rather than leave a file nothing can
                    # check. No guard here on purpose: update_crl() already catches
                    # and returns None, so wrapping it would add a handler that can
                    # never fire.
                    if crl_manager:
                        crl_manager.update_crl()

                    return {
                        'message': 'Client certificate authority rebuilt',
                        'certificates_removed': summary.get('certificates_removed', 0),
                        'warning': (
                            'Any CRL or OCSP response published for the previous CA '
                            'can no longer be verified. Distribute the new CA '
                            'certificate to everything that trusted the old one.'
                        ),
                    }, 200

                except HTTPException:
                    raise
                except Exception as e:
                    logger.error(f"Error resetting client CA: {str(e)}")
                    abort(500, "Failed to reset the certificate authority")

    return ClientCertificateAuthorityReset


def create_client_certificate_resources(api, managers):
    """Create and register all client certificate resources."""

    client_cert_manager = managers.get('client_certificates')
    auth_manager = managers.get('auth')
    ocsp_responder = managers.get('ocsp')
    crl_manager = managers.get('crl')
    settings_manager = managers.get('settings')
    event_bus = managers.get('events')

    if not client_cert_manager:
        logger.error("ClientCertificateManager not available")
        return {}

    # Client Certificate List Resource
    class ClientCertificateList(Resource):
        # Internal security audit (May 2026) — H1: `require_auth` only
        # checks identity, not role. Aligning every client-cert Resource
        # with the same role stratification the TLS cert path already
        # uses: viewer reads, operator mints/renews, admin revokes.
        method_decorators = [auth_manager.require_role('viewer')]

        def get(self):
            """Get list of client certificates with optional filtering."""
            try:
                # Get query parameters
                cert_usage = request.args.get('usage')
                revoked = request.args.get('revoked')
                search = request.args.get('search')

                # Convert revoked to boolean
                if revoked:
                    revoked = revoked.lower() == 'true'

                # Get certificates
                certs = client_cert_manager.list_client_certificates(
                    cert_usage=cert_usage,
                    revoked=revoked,
                    search_term=search
                )

                return {'certificates': certs, 'total': len(certs)}, 200

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error listing client certificates: {str(e)}")
                abort(500, "Failed to list certificates")

    # Client Certificate Create Resource
    class ClientCertificateCreate(Resource):
        # Mint a CA-signed identity — operator+ (parity with TLS cert
        # CreateCertificate which is `require_role('operator')`).
        method_decorators = [auth_manager.require_role('operator')]

        def post(self):
            """Create a new client certificate."""
            try:
                data = request.get_json()

                if not data or 'common_name' not in data:
                    abort(400, "common_name is required")

                # Create certificate
                success, error, cert_data = client_cert_manager.create_client_certificate(
                    **_client_cert_create_params(data))

                if not success:
                    abort(400, f"Failed to create certificate: {error}")

                return cert_data, 201

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error creating client certificate: {str(e)}")
                abort(500, "Failed to create certificate")

    # Client Certificate Detail Resource
    class ClientCertificateDetail(Resource):
        method_decorators = [auth_manager.require_role('viewer')]

        def get(self, identifier):
            """Get certificate metadata."""
            try:
                if not _validate_identifier(identifier):
                    abort(400, "Invalid certificate identifier")
                metadata = client_cert_manager.get_certificate_metadata(identifier)

                if not metadata:
                    abort(404, f"Certificate not found: {identifier}")

                return metadata, 200

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error getting certificate metadata: {str(e)}")
                abort(500, "Failed to get certificate metadata")

    # Client Certificate Download Resource
    class ClientCertificateDownload(Resource):
        # Decorator runs at request-time so the role check is enforced
        # uniformly; the per-file_type stratification (private key gates
        # at operator+, public material at viewer) runs inside the handler
        # mirroring DownloadCertificate/DownloadCertificateFile on the TLS
        # path. Viewer is the floor — anything that mints or modifies
        # state lives on other Resources.
        method_decorators = [auth_manager.require_role('viewer')]

        # File types whose download exposes the private key. Caller must
        # hold operator+ regardless of which Resource entry point they
        # use (path-style or otherwise). Mirrors `_PRIVATE_KEY_FILES` on
        # the TLS cert side (modules/api/resources.py).
        # 'pfx' bundles the private key, so it is gated like 'key'.
        _PRIVATE_FILE_TYPES = frozenset({'key', 'pfx'})

        def get(self, identifier, file_type):
            """Download certificate, key, CSR, or a PKCS#12 (.pfx) bundle."""
            try:
                if not _validate_identifier(identifier):
                    abort(400, "Invalid certificate identifier")
                if file_type not in ['crt', 'key', 'csr', 'pfx']:
                    abort(400, "Invalid file type. Must be 'crt', 'key', 'csr', or 'pfx'")

                # Per-file role gate: viewer reads public material only;
                # private key (and the key-bearing .pfx) needs operator+.
                # Mirrors the TLS cert DownloadCertificate pattern.
                if file_type in self._PRIVATE_FILE_TYPES:
                    user = getattr(request, 'current_user', None) or {}
                    role = user.get('role')
                    from ..core.auth import ROLE_HIERARCHY
                    if ROLE_HIERARCHY.get(role, -1) < ROLE_HIERARCHY.get('operator', 999):
                        abort(403, "operator role required to download client certificate private key")

                # PKCS#12 is generated on demand and encrypted with the
                # configured PFX password (same setting as the server-side
                # export). Without a password we refuse rather than emit an
                # unencrypted private key bundle.
                if file_type == 'pfx':
                    settings = settings_manager.load_settings() if settings_manager else {}
                    password = (settings.get('pfx_password') or '').strip()
                    if not password:
                        abort(400, "Set a PFX password in Settings to enable PKCS#12 export")
                    pfx_bytes = client_cert_manager.build_pfx(identifier, password.encode())
                    if not pfx_bytes:
                        abort(404, f"Client certificate not found: {identifier}")
                    return send_file(
                        BytesIO(pfx_bytes),
                        mimetype='application/x-pkcs12',
                        as_attachment=True,
                        download_name=f"{identifier}.pfx"
                    )

                # Get file
                file_content = client_cert_manager.get_certificate_file(
                    identifier,
                    file_type
                )

                if not file_content:
                    abort(404, f"File not found: {identifier}.{file_type}")

                # Return file
                return send_file(
                    BytesIO(file_content),
                    mimetype='application/octet-stream',
                    as_attachment=True,
                    download_name=f"{identifier}.{file_type}"
                )

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error downloading certificate file: {str(e)}")
                abort(500, "Failed to download certificate file")

    # Client Certificate Revoke Resource
    class ClientCertificateRevoke(Resource):
        # Revoking a CA-signed identity is destructive and analogous
        # to deleting a TLS cert (admin). Aligns with the TLS-side
        # `CertificateDelete` admin gating.
        method_decorators = [auth_manager.require_role('admin')]

        def post(self, identifier):
            """Revoke a client certificate."""
            try:
                if not _validate_identifier(identifier):
                    abort(400, "Invalid certificate identifier")
                data = request.get_json() or {}
                reason = data.get('reason', 'unspecified')

                # Revoke certificate
                success, error = client_cert_manager.revoke_certificate(
                    identifier,
                    reason=reason
                )

                if not success:
                    abort(400, error)

                # Lifecycle notification (#474): a revocation is worth alerting
                # on. Best-effort — never turn a successful revoke into a 500.
                if event_bus is not None:
                    try:
                        event_bus.publish('certificate_revoked', {
                            'domain': identifier, 'reason': reason,
                            'resource_type': 'client_certificate',
                        })
                    except Exception as pub_err:
                        logger.warning("certificate_revoked publish failed: %s", pub_err)

                return {'message': f'Certificate revoked: {identifier}'}, 200

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error revoking certificate: {str(e)}")
                abort(500, "Failed to revoke certificate")

    # Client Certificate Renew Resource
    class ClientCertificateRenew(Resource):
        # Renew re-mints a CA-signed identity — operator+ (parity with
        # TLS-side `RenewCertificate`).
        method_decorators = [auth_manager.require_role('operator')]

        def post(self, identifier):
            """Renew a client certificate."""
            try:
                if not _validate_identifier(identifier):
                    abort(400, "Invalid certificate identifier")
                # Renew certificate
                success, error, cert_data = client_cert_manager.renew_certificate(
                    identifier
                )

                if not success:
                    abort(400, error)

                return cert_data, 201

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error renewing certificate: {str(e)}")
                abort(500, "Failed to renew certificate")

    # Client Certificate Statistics Resource
    class ClientCertificateStatistics(Resource):
        method_decorators = [auth_manager.require_role('viewer')]

        def get(self):
            """Get certificate statistics."""
            try:
                stats = client_cert_manager.get_statistics()
                return stats, 200

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error getting statistics: {str(e)}")
                abort(500, "Failed to get certificate statistics")

    # Client Certificate Batch Resource
    class ClientCertificateBatch(Resource):
        # Batch mint up to 100 identities — operator+ (same role as
        # single-cert ClientCertificateCreate).
        method_decorators = [auth_manager.require_role('operator')]

        def post(self):
            """Create multiple certificates from CSV data."""
            try:
                data = request.get_json()

                if not data or 'rows' not in data:
                    abort(400, "CSV rows required")

                rows = data.get('rows', [])
                headers = data.get('headers', [])

                # Limit batch size to prevent resource exhaustion
                max_batch = 100
                if len(rows) > max_batch:
                    abort(400, f"Batch size exceeds maximum of {max_batch} certificates")

                if not headers or 'common_name' not in headers:
                    abort(400, "CSV must have 'common_name' column")

                # Create certificates
                results = {
                    'total': len(rows),
                    'successful': 0,
                    'failed': 0,
                    'errors': [],
                    'certificates': []
                }

                for idx, row in enumerate(rows):
                    try:
                        # Map CSV row to certificate parameters
                        cert_data = {}
                        for i, header in enumerate(headers):
                            if i < len(row):
                                cert_data[header.strip()] = row[i].strip()

                        # Validate and convert days_valid
                        try:
                            batch_days = int(cert_data.get('days_valid', 365))
                        except (TypeError, ValueError):
                            batch_days = 365
                        batch_days = max(1, min(batch_days, 3650))

                        # Create certificate
                        success, error, cert_info = client_cert_manager.create_client_certificate(
                            common_name=cert_data.get('common_name', ''),
                            email=cert_data.get('email', ''),
                            organization=cert_data.get('organization', 'CertMate'),
                            # Parsed out of the CSV column and then dropped:
                            # every row's OU fell back to "Users" while every
                            # other column came through, silently, for the
                            # whole batch.
                            organizational_unit=cert_data.get(
                                'organizational_unit', 'Users'),
                            cert_usage=cert_data.get('cert_usage', 'api-mtls'),
                            days_valid=batch_days,
                            generate_key=True,
                            notes=cert_data.get('notes', '')
                        )

                        if success:
                            results['successful'] += 1
                            results['certificates'].append({
                                'identifier': cert_info['identifier'],
                                'common_name': cert_data.get('common_name')
                            })
                        else:
                            results['failed'] += 1
                            results['errors'].append({
                                'row': idx + 2,  # Account for header row
                                'error': error
                            })

                    except Exception as e:
                        logger.error(f"Batch cert creation error for row {idx + 2}: {str(e)}")
                        results['failed'] += 1
                        results['errors'].append({
                            'row': idx + 2,
                            'error': 'Certificate creation failed'
                        })

                logger.info(f"Batch certificate creation: {results['successful']}/{results['total']} successful")
                return results, 201

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error in batch creation: {str(e)}")
                abort(500, "Failed to process batch certificate creation")

    # OCSP Status Resource
    #
    # Intentionally unauthenticated: RFC 6960 OCSP responders are public
    # endpoints that any relying party can query. The information returned
    # (good / revoked / unknown for a serial number) is exactly what an
    # OCSP responder is supposed to expose, and serial numbers are not
    # operator-secret. Role-gating this endpoint would break the standard
    # client interaction. Pinned here so the internal security audit's
    # "missing decorator" hit lands as Info, not Bug, on future passes.
    class OCSPStatus(Resource):
        def get(self, serial_number):
            """Get OCSP status for certificate."""
            try:
                if not ocsp_responder:
                    abort(503, "OCSP responder not available")

                serial_num = int(serial_number)
                if serial_num < 0 or serial_num > 2**160:
                    abort(400, "Serial number out of valid range")
                cert_status = ocsp_responder.get_cert_status(serial_num)
                response = ocsp_responder.generate_ocsp_response(cert_status)

                return response, 200

            except ValueError:
                abort(400, "Invalid serial number")
            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error getting OCSP status: {str(e)}")
                abort(500, "Failed to get OCSP status")

    # CRL Distribution Resource
    #
    # Intentionally unauthenticated: RFC 5280 §4.2.1.13 (CRLDistributionPoints)
    # expects CRLs to be retrievable by any relying party without
    # authentication — that is the entire point of distribution. Same
    # reasoning as OCSPStatus above.
    class CRLDistribution(Resource):
        def get(self, format_type='pem'):
            """Get Certificate Revocation List."""
            try:
                if not crl_manager:
                    abort(503, "CRL manager not available")

                if format_type == 'pem':
                    crl_data = crl_manager.get_crl_pem()
                    if not crl_data:
                        abort(404, "No CRL available")

                    return Response(
                        crl_data,
                        mimetype='application/x-pem-file',
                        headers={'Content-Disposition': 'attachment; filename=ca.crl'}
                    )

                elif format_type == 'der':
                    crl_data = crl_manager.get_crl_der()
                    if not crl_data:
                        abort(404, "No CRL available")

                    return Response(
                        crl_data,
                        mimetype='application/x-pkix-crl',
                        headers={'Content-Disposition': 'attachment; filename=ca.crl'}
                    )

                elif format_type == 'info':
                    info = crl_manager.get_crl_info()
                    return info, 200

                else:
                    abort(400, "Format must be 'pem', 'der', or 'info'")

            except HTTPException:
                # abort(4xx) above raises HTTPException, a subclass of
                # Exception: without this clause every 400/403/404 the
                # handler meant to send was rewritten to 500 below.
                raise
            except Exception as e:
                logger.error(f"Error getting CRL: {str(e)}")
                abort(500, "Failed to get CRL")

    ClientCertificateAuthorityCert = _build_ca_cert_resource(client_cert_manager)
    ClientCertificateAuthorityReset = _build_ca_reset_resource(
        auth_manager, client_cert_manager, crl_manager)

    # Return dictionary of resource classes
    return {
        'ClientCertificateList': ClientCertificateList,
        'ClientCertificateCreate': ClientCertificateCreate,
        'ClientCertificateDetail': ClientCertificateDetail,
        'ClientCertificateDownload': ClientCertificateDownload,
        'ClientCertificateRevoke': ClientCertificateRevoke,
        'ClientCertificateRenew': ClientCertificateRenew,
        'ClientCertificateStatistics': ClientCertificateStatistics,
        'ClientCertificateBatch': ClientCertificateBatch,
        'ClientCertificateAuthorityCert': ClientCertificateAuthorityCert,
        'ClientCertificateAuthorityReset': ClientCertificateAuthorityReset,
        'OCSPStatus': OCSPStatus,
        'CRLDistribution': CRLDistribution,
    }
