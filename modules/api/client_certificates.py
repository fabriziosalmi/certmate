"""
Client Certificates API resources for CertMate
Flask-RESTX endpoints for client certificate management
"""

import logging
import re
from flask import request, send_file, Response
from flask_restx import Resource, fields, abort
from io import BytesIO
import json

logger = logging.getLogger(__name__)

# Validation pattern for client certificate identifiers
_SAFE_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$')


def _validate_identifier(identifier):
    """Validate client certificate identifier to prevent path traversal."""
    if not identifier or '..' in identifier or '/' in identifier or '\\' in identifier or '\x00' in identifier:
        return False
    if not _SAFE_IDENTIFIER_RE.match(identifier):
        return False
    return True


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


def create_client_certificate_resources(api, managers):
    """Create and register all client certificate resources."""

    client_cert_manager = managers.get('client_certificates')
    auth_manager = managers.get('auth')
    ocsp_responder = managers.get('ocsp')
    crl_manager = managers.get('crl')

    if not client_cert_manager:
        logger.error("ClientCertificateManager not available")
        return {}

    # Client Certificate List Resource
    class ClientCertificateList(Resource):
        method_decorators = [auth_manager.require_auth]

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

            except Exception as e:
                logger.error(f"Error listing client certificates: {str(e)}")
                abort(500, "Failed to list certificates")

    # Client Certificate Create Resource
    class ClientCertificateCreate(Resource):
        method_decorators = [auth_manager.require_auth]

        def post(self):
            """Create a new client certificate."""
            try:
                data = request.get_json()

                if not data or 'common_name' not in data:
                    abort(400, "common_name is required")

                # Get parameters with length validation
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
                cert_usage = data.get('cert_usage', 'api-mtls')
                days_valid = data.get('days_valid', 365)
                try:
                    days_valid = int(days_valid)
                except (TypeError, ValueError):
                    abort(400, "days_valid must be an integer")
                if days_valid < 1 or days_valid > 3650:
                    abort(400, "days_valid must be between 1 and 3650")
                generate_key = data.get('generate_key', True)
                notes = data.get('notes', '')

                # Create certificate
                success, error, cert_data = client_cert_manager.create_client_certificate(
                    common_name=common_name,
                    email=email,
                    organization=organization,
                    organizational_unit=organizational_unit,
                    cert_usage=cert_usage,
                    days_valid=days_valid,
                    generate_key=generate_key,
                    notes=notes
                )

                if not success:
                    abort(400, f"Failed to create certificate: {error}")

                return cert_data, 201

            except Exception as e:
                logger.error(f"Error creating client certificate: {str(e)}")
                abort(500, "Failed to create certificate")

    # Client Certificate Detail Resource
    class ClientCertificateDetail(Resource):
        method_decorators = [auth_manager.require_auth]

        def get(self, identifier):
            """Get certificate metadata."""
            try:
                if not _validate_identifier(identifier):
                    abort(400, "Invalid certificate identifier")
                metadata = client_cert_manager.get_certificate_metadata(identifier)

                if not metadata:
                    abort(404, f"Certificate not found: {identifier}")

                return metadata, 200

            except Exception as e:
                logger.error(f"Error getting certificate metadata: {str(e)}")
                abort(500, "Failed to get certificate metadata")

    # Client Certificate Download Resource
    class ClientCertificateDownload(Resource):
        method_decorators = [auth_manager.require_auth]

        def get(self, identifier, file_type):
            """Download certificate, key, or CSR."""
            try:
                if not _validate_identifier(identifier):
                    abort(400, "Invalid certificate identifier")
                if file_type not in ['crt', 'key', 'csr']:
                    abort(400, "Invalid file type. Must be 'crt', 'key', or 'csr'")

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

            except Exception as e:
                logger.error(f"Error downloading certificate file: {str(e)}")
                abort(500, "Failed to download certificate file")

    # Client Certificate Revoke Resource
    class ClientCertificateRevoke(Resource):
        method_decorators = [auth_manager.require_auth]

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

                return {'message': f'Certificate revoked: {identifier}'}, 200

            except Exception as e:
                logger.error(f"Error revoking certificate: {str(e)}")
                abort(500, "Failed to revoke certificate")

    # Client Certificate Renew Resource
    class ClientCertificateRenew(Resource):
        method_decorators = [auth_manager.require_auth]

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

            except Exception as e:
                logger.error(f"Error renewing certificate: {str(e)}")
                abort(500, "Failed to renew certificate")

    # Client Certificate Statistics Resource
    class ClientCertificateStatistics(Resource):
        method_decorators = [auth_manager.require_auth]

        def get(self):
            """Get certificate statistics."""
            try:
                stats = client_cert_manager.get_statistics()
                return stats, 200

            except Exception as e:
                logger.error(f"Error getting statistics: {str(e)}")
                abort(500, "Failed to get certificate statistics")

    # Client Certificate Batch Resource
    class ClientCertificateBatch(Resource):
        method_decorators = [auth_manager.require_auth]

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

            except Exception as e:
                logger.error(f"Error in batch creation: {str(e)}")
                abort(500, "Failed to process batch certificate creation")

    # OCSP Status Resource
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
            except Exception as e:
                logger.error(f"Error getting OCSP status: {str(e)}")
                abort(500, "Failed to get OCSP status")

    # CRL Distribution Resource
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

            except Exception as e:
                logger.error(f"Error getting CRL: {str(e)}")
                abort(500, "Failed to get CRL")

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
        'OCSPStatus': OCSPStatus,
        'CRLDistribution': CRLDistribution,
    }
