"""
Client Certificates API resources for CertMate
Flask-RESTX endpoints for client certificate management
"""

import logging
from flask import request, send_file
from flask_restx import Resource, fields, abort
from io import BytesIO
import json

logger = logging.getLogger(__name__)


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


class ClientCertificateListResource(Resource):
    """Resource for listing client certificates."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

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
            certs = self.managers['client_certificates'].list_client_certificates(
                cert_usage=cert_usage,
                revoked=revoked,
                search_term=search
            )

            return {'certificates': certs, 'total': len(certs)}, 200

        except Exception as e:
            logger.error(f"Error listing client certificates: {str(e)}")
            abort(500, f"Error listing certificates: {str(e)}")


class ClientCertificateCreateResource(Resource):
    """Resource for creating new client certificates."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

    def post(self):
        """Create a new client certificate."""
        try:
            data = request.get_json()

            if not data or 'common_name' not in data:
                abort(400, "common_name is required")

            # Get parameters
            common_name = data.get('common_name')
            email = data.get('email', '')
            organization = data.get('organization', 'CertMate')
            organizational_unit = data.get('organizational_unit', 'Users')
            cert_usage = data.get('cert_usage', 'api-mtls')
            days_valid = data.get('days_valid', 365)
            generate_key = data.get('generate_key', True)
            notes = data.get('notes', '')

            # Create certificate
            success, error, cert_data = self.managers['client_certificates'].create_client_certificate(
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
            abort(500, f"Error creating certificate: {str(e)}")


class ClientCertificateDetailResource(Resource):
    """Resource for client certificate details."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

    def get(self, identifier):
        """Get certificate metadata."""
        try:
            metadata = self.managers['client_certificates'].get_certificate_metadata(identifier)

            if not metadata:
                abort(404, f"Certificate not found: {identifier}")

            return metadata, 200

        except Exception as e:
            logger.error(f"Error getting certificate metadata: {str(e)}")
            abort(500, str(e))


class ClientCertificateDownloadResource(Resource):
    """Resource for downloading certificate files."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

    def get(self, identifier, file_type):
        """Download certificate, key, or CSR."""
        try:
            if file_type not in ['crt', 'key', 'csr']:
                abort(400, "Invalid file type. Must be 'crt', 'key', or 'csr'")

            # Get file
            file_content = self.managers['client_certificates'].get_certificate_file(
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
            abort(500, str(e))


class ClientCertificateRevokeResource(Resource):
    """Resource for revoking client certificates."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

    def post(self, identifier):
        """Revoke a client certificate."""
        try:
            data = request.get_json() or {}
            reason = data.get('reason', 'unspecified')

            # Revoke certificate
            success, error = self.managers['client_certificates'].revoke_certificate(
                identifier,
                reason=reason
            )

            if not success:
                abort(400, error)

            return {'message': f'Certificate revoked: {identifier}'}, 200

        except Exception as e:
            logger.error(f"Error revoking certificate: {str(e)}")
            abort(500, str(e))


class ClientCertificateRenewResource(Resource):
    """Resource for renewing client certificates."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

    def post(self, identifier):
        """Renew a client certificate."""
        try:
            # Renew certificate
            success, error, cert_data = self.managers['client_certificates'].renew_certificate(
                identifier
            )

            if not success:
                abort(400, error)

            return cert_data, 201

        except Exception as e:
            logger.error(f"Error renewing certificate: {str(e)}")
            abort(500, str(e))


class ClientCertificateStatisticsResource(Resource):
    """Resource for client certificate statistics."""

    def __init__(self, api, managers):
        super().__init__()
        self.managers = managers

    def get(self):
        """Get certificate statistics."""
        try:
            stats = self.managers['client_certificates'].get_statistics()
            return stats, 200

        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            abort(500, str(e))


def create_client_certificate_resources(api, managers):
    """Create and register all client certificate resources."""

    resources = {
        'ClientCertificateList': ClientCertificateListResource(api, managers),
        'ClientCertificateCreate': ClientCertificateCreateResource(api, managers),
        'ClientCertificateDetail': ClientCertificateDetailResource(api, managers),
        'ClientCertificateDownload': ClientCertificateDownloadResource(api, managers),
        'ClientCertificateRevoke': ClientCertificateRevokeResource(api, managers),
        'ClientCertificateRenew': ClientCertificateRenewResource(api, managers),
        'ClientCertificateStatistics': ClientCertificateStatisticsResource(api, managers),
    }

    return resources
