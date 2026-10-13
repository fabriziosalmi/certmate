"""Import existing server certificates without contacting an issuing CA."""
import logging

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from flask import request
from flask_restx import Resource

from ..core.audit_context import audit_context_from_request
from ..core.cert_import import MAX_IMPORT_PEM_BYTES
from ..core.cert_service import DomainOutOfScope
from ..core.certificates import DomainOperationInProgress
from ..core.request_fields import json_bool

logger = logging.getLogger(__name__)


def create_import_resources(api, models, ctx):
    class ImportCertificate(Resource):
        @api.doc(security='Bearer', responses={
            201: 'Certificate imported without issuance',
            400: 'Invalid certificate bundle or renewal configuration',
            409: 'Certificate already exists or an operation is in progress'})
        @api.expect(models['import_cert_model'])
        @ctx.auth.require_role('operator')
        def post(self):
            """Validate and import certificate, chain and private key PEMs.

            The CA/account/challenge selection applies to the next renewal,
            not to validation of the certificate's current issuer. No ACME
            request is made on import. Existing certificates are not replaced.
            """
            if request.content_length and request.content_length > 4 * MAX_IMPORT_PEM_BYTES:
                return {'error': 'Certificate import request is too large'}, 413
            data = api.payload
            if not isinstance(data, dict):
                return {'error': 'A JSON object is required'}, 400
            auto_renew, error = json_bool(data, 'auto_renew', default=True)
            if error:
                return {'error': error}, 400
            config_keys = ('domain', 'dns_provider', 'account_id', 'ca_provider',
                           'ca_account_id', 'challenge_type', 'domain_alias',
                           'alias_dns_provider', 'acme_profile')
            if any(data.get(k) is not None and not isinstance(data[k], str) for k in config_keys):
                return {'error': 'Renewal configuration fields must be strings'}, 400
            try:
                result = ctx.cert_service.import_certificate(
                    certificate=data.get('certificate'), chain=data.get('chain'),
                    private_key=data.get('private_key'),
                    auto_renew=auto_renew,
                    **{k: data.get(k) for k in config_keys},
                    user=getattr(request, 'current_user', None) or {},
                    ip_address=request.remote_addr, audit_ctx=audit_context_from_request())
                return {**result, 'message': 'Certificate imported; no certificate was issued'}, 201
            except DomainOutOfScope as e:
                return {'error': str(e), 'code': 'DOMAIN_OUT_OF_SCOPE'}, 403
            except FileExistsError as e:
                return {'error': str(e), 'code': 'CERTIFICATE_ALREADY_EXISTS'}, 409
            except DomainOperationInProgress:
                return {'error': 'An operation is already in progress for this domain'}, 409
            except (ValueError, x509.DuplicateExtension, UnsupportedAlgorithm) as e:
                return {'error': str(e), 'code': 'INVALID_CERTIFICATE_IMPORT'}, 400
            except (OSError, RuntimeError):
                # Never log the request or parser exceptions: the upload contains a private key.
                logger.error('Certificate import failed')
                return {'error': 'Could not complete certificate import. Check storage and settings; '
                                 'any certificate files already saved are preserved.'}, 500

    return {'ImportCertificate': ImportCertificate}
