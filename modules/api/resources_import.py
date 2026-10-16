"""Import existing server certificates without contacting an issuing CA, and
replace an external one by upload."""
import logging

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from flask import request
from flask_restx import Resource

from ..core.audit_context import audit_context_from_request
from ..core.cert_import import INVALID_IMPORT_BUNDLE, MAX_IMPORT_PEM_BYTES, CertificateImportError
from ..core.cert_service import CertificateNamesTaken, DomainOutOfScope
from ..core.certificates import DomainOperationInProgress, ExternalCertificate, ReplacementRefused
from ..core.request_fields import json_bool
from .path_validation import validate_domain_path

logger = logging.getLogger(__name__)


def create_import_resources(api, models, ctx):
    class ImportCertificate(Resource):
        @api.doc(security='Bearer', responses={
            201: 'Certificate imported without issuance',
            400: 'Invalid certificate bundle or renewal configuration',
            409: 'Certificate already exists, an operation is in progress, or a name is '
                 'already covered by a managed certificate (NAMES_ALREADY_MANAGED)'})
        @api.expect(models['import_cert_model'])
        @ctx.auth.require_role('operator')
        def post(self):
            """Validate and import certificate, chain and private key PEMs.

            The CA/account/challenge selection applies to the next renewal,
            not to validation of the certificate's current issuer. No ACME
            request is made on import. Existing certificates are not replaced.

            With ``external: true`` the certificate has no CA at all: CertMate
            stores, deploys and watches it and never renews it, and none of the
            renewal fields may be sent.
            """
            if request.content_length and request.content_length > 4 * MAX_IMPORT_PEM_BYTES:
                return {'error': 'Certificate import request is too large', 'code': 'REQUEST_TOO_LARGE'}, 413
            data = api.payload
            if not isinstance(data, dict):
                return {'error': 'A JSON object is required', 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            external, error = json_bool(data, 'external', default=False)
            if error:
                return {'error': error, 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            # Absent means on for a certificate a CA renews, and off for an
            # external one; sent as true with external, the service refuses it.
            auto_renew, error = json_bool(data, 'auto_renew', default=not external)
            if error:
                return {'error': error, 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            config_keys = ('domain', 'dns_provider', 'account_id', 'ca_provider',
                           'ca_account_id', 'challenge_type', 'domain_alias',
                           'alias_dns_provider', 'acme_profile')
            if any(data.get(k) is not None and not isinstance(data[k], str) for k in config_keys):
                return {'error': 'Renewal configuration fields must be strings', 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            try:
                result = ctx.cert_service.import_certificate(
                    certificate=data.get('certificate'), chain=data.get('chain'),
                    private_key=data.get('private_key'),
                    auto_renew=auto_renew, external=external,
                    **{k: data.get(k) for k in config_keys},
                    user=getattr(request, 'current_user', None) or {},
                    ip_address=request.remote_addr, audit_ctx=audit_context_from_request())
                return {**result, 'message': 'Certificate imported; no certificate was issued'}, 201
            except DomainOutOfScope as e:
                return {'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
            except FileExistsError as e:
                return {'error': str(e), 'code': 'CERTIFICATE_ALREADY_EXISTS'}, 409
            except DomainOperationInProgress:
                return {'error': 'An operation is already in progress for this domain',
                        'code': 'DOMAIN_OPERATION_IN_PROGRESS'}, 409
            except CertificateImportError as e:
                return {'error': str(e), 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            except (CertificateNamesTaken, ExternalCertificate) as e:
                return {'error': str(e), 'code': e.code}, 409
            except ValueError as e:
                return {'error': str(e), 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            except (x509.DuplicateExtension, UnsupportedAlgorithm):
                return {'error': INVALID_IMPORT_BUNDLE, 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            except (OSError, RuntimeError):
                # Never log the request or parser exceptions: the upload contains a private key.
                logger.error('Certificate import failed')
                return {'error': 'Could not complete certificate import. Check storage and settings; '
                                 'any certificate files already saved are preserved.',
                        'code': 'CERTIFICATE_IMPORT_FAILED'}, 500

    return {'ImportCertificate': ImportCertificate}


def _replace_refusal(error):
    """The answer to a replacement refused with *error*. Messages are the
    refusals' own text, never a parser's: the upload contains a private key,
    and the service turns every parser error into INVALID_IMPORT_BUNDLE."""
    if isinstance(error, DomainOutOfScope):
        return {'error': str(error), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
    if isinstance(error, FileNotFoundError):
        return {'error': 'Certificate not found', 'code': 'CERTIFICATE_NOT_FOUND'}, 404
    if isinstance(error, DomainOperationInProgress):
        return {'error': 'An operation is already in progress for this domain',
                'code': 'DOMAIN_OPERATION_IN_PROGRESS'}, 409
    if isinstance(error, (ReplacementRefused, CertificateNamesTaken)):
        return {'error': str(error), 'code': error.code}, 409
    # CertificateImportError and the service's own ValueErrors: the request is wrong.
    return {'error': str(error), 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400


def create_replace_resources(api, models, ctx):
    """The replacement of an external certificate by upload (#1159). Its own
    group, so the import's complexity is not its sum with this one."""

    class ReplaceCertificate(Resource):
        @api.doc(security='Bearer', responses={
            200: 'Certificate replaced; deploy hooks run as for a renewal',
            400: 'Invalid certificate bundle, or the bundle does not name the domain',
            404: 'No certificate for this domain',
            409: 'Not an external certificate, the same certificate, an earlier expiry, a name '
                 'already covered by a managed certificate, or an operation in progress'})
        @api.expect(models['replace_cert_model'])
        @ctx.auth.require_role('operator')
        def post(self, domain):
            """Replace an external certificate with an uploaded certificate, chain and key.

            The certificate must name this domain; its other names may change.
            Refused for a certificate CertMate renews through a CA, for the
            certificate already in place, and for one that expires earlier
            unless ``allow_earlier_expiry`` is true.
            """
            if request.content_length and request.content_length > 4 * MAX_IMPORT_PEM_BYTES:
                return {'error': 'Certificate replacement request is too large', 'code': 'REQUEST_TOO_LARGE'}, 413
            _, error = validate_domain_path(domain, ctx.file_ops.cert_dir)
            if error:
                return {'error': error, 'code': 'INVALID_REQUEST'}, 400
            # The model has refused anything but an object, and a flag that is
            # not a JSON boolean, before this runs.
            data = api.payload
            allow_earlier_expiry = data.get('allow_earlier_expiry', False)
            try:
                result = ctx.cert_service.replace_external(
                    domain=domain, certificate=data.get('certificate'), chain=data.get('chain'),
                    private_key=data.get('private_key'), allow_earlier_expiry=allow_earlier_expiry,
                    user=getattr(request, 'current_user', None) or {},
                    ip_address=request.remote_addr, audit_ctx=audit_context_from_request())
                return {**result, 'message': 'Certificate replaced; no certificate was issued'}, 200
            except (DomainOutOfScope, FileNotFoundError, DomainOperationInProgress, ValueError) as e:
                return _replace_refusal(e)
            except (OSError, RuntimeError):
                # Never log the request or parser exceptions: the upload contains a private key.
                logger.error('Certificate replacement failed')
                return {'error': 'Could not complete the replacement. Check storage and settings.',
                        'code': 'CERTIFICATE_REPLACE_FAILED'}, 500

    return {'ReplaceCertificate': ReplaceCertificate}
