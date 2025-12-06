"""
OCSP and CRL module for CertMate
Handles OCSP responses and Certificate Revocation List generation/distribution
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List

logger = logging.getLogger(__name__)


class OCSPResponder:
    """
    Basic OCSP (Online Certificate Status Protocol) responder.
    Provides certificate status information (good, revoked, unknown).
    """

    def __init__(self, private_ca, client_cert_manager):
        """
        Initialize OCSP Responder.

        Args:
            private_ca: PrivateCAGenerator instance
            client_cert_manager: ClientCertificateManager instance
        """
        self.private_ca = private_ca
        self.client_cert_manager = client_cert_manager

    def get_cert_status(self, serial_number: int) -> dict:
        """
        Get OCSP status for a certificate.

        Args:
            serial_number: Certificate serial number

        Returns:
            Dictionary with status information
        """
        try:
            # Search through certificates
            certificates = self.client_cert_manager.list_client_certificates()

            for cert in certificates:
                if int(cert.get('serial_number', 0)) == serial_number:
                    # Certificate found
                    if cert.get('revoked'):
                        return {
                            'serial_number': serial_number,
                            'status': 'revoked',
                            'revoked_at': cert.get('revoked_at'),
                            'reason': cert.get('reason_revoked', 'unspecified'),
                            'this_update': datetime.utcnow().isoformat(),
                            'next_update': None  # OCSP responses are generated on-demand
                        }
                    else:
                        return {
                            'serial_number': serial_number,
                            'status': 'good',
                            'this_update': datetime.utcnow().isoformat(),
                            'next_update': None
                        }

            # Certificate not found
            return {
                'serial_number': serial_number,
                'status': 'unknown',
                'this_update': datetime.utcnow().isoformat(),
                'next_update': None
            }

        except Exception as e:
            logger.error(f"Error getting OCSP status: {str(e)}")
            return {
                'serial_number': serial_number,
                'status': 'unknown',
                'error': str(e)
            }

    def generate_ocsp_response(self, cert_status: dict) -> dict:
        """
        Generate an OCSP response for a certificate status.

        Args:
            cert_status: Certificate status dictionary

        Returns:
            OCSP response as dictionary (can be serialized to DER if needed)
        """
        try:
            response = {
                'response_status': 'successful',
                'certificate_status': cert_status['status'],
                'certificate_serial': cert_status['serial_number'],
                'this_update': cert_status.get('this_update'),
                'next_update': cert_status.get('next_update'),
                'responder_name': 'CertMate OCSP Responder',
            }

            if cert_status['status'] == 'revoked':
                response['revocation_time'] = cert_status.get('revoked_at')
                response['revocation_reason'] = cert_status.get('reason', 'unspecified')

            logger.debug(f"Generated OCSP response for serial {cert_status['serial_number']}")
            return response

        except Exception as e:
            logger.error(f"Error generating OCSP response: {str(e)}")
            return {
                'response_status': 'internal_error',
                'error': str(e)
            }


class CRLManager:
    """
    Manages Certificate Revocation List (CRL) generation and distribution.
    """

    def __init__(self, private_ca, client_cert_manager, crl_dir: Path):
        """
        Initialize CRL Manager.

        Args:
            private_ca: PrivateCAGenerator instance
            client_cert_manager: ClientCertificateManager instance
            crl_dir: Directory to store CRL files
        """
        self.private_ca = private_ca
        self.client_cert_manager = client_cert_manager
        self.crl_dir = Path(crl_dir)
        self.crl_dir.mkdir(parents=True, exist_ok=True)

    def get_revoked_serials(self) -> List[int]:
        """
        Get list of revoked certificate serial numbers.

        Returns:
            List of serial numbers
        """
        try:
            certificates = self.client_cert_manager.list_client_certificates(revoked=True)
            serials = []

            for cert in certificates:
                try:
                    serial = int(cert.get('serial_number', 0))
                    if serial > 0:
                        serials.append(serial)
                except (ValueError, TypeError):
                    continue

            logger.debug(f"Found {len(serials)} revoked certificates for CRL")
            return serials

        except Exception as e:
            logger.error(f"Error getting revoked serials: {str(e)}")
            return []

    def update_crl(self) -> Optional[bytes]:
        """
        Update and generate CRL.

        Returns:
            CRL as PEM bytes or None if error
        """
        try:
            revoked_serials = self.get_revoked_serials()
            crl_pem = self.private_ca.generate_crl(revoked_serials)

            if crl_pem:
                logger.info(f"Updated CRL with {len(revoked_serials)} revoked certificates")
                return crl_pem
            else:
                logger.warning("Failed to generate CRL")
                return None

        except Exception as e:
            logger.error(f"Error updating CRL: {str(e)}")
            return None

    def get_crl_pem(self) -> Optional[bytes]:
        """
        Get current CRL in PEM format.

        Returns:
            CRL as PEM bytes or None
        """
        try:
            crl_pem = self.private_ca.get_crl_pem()
            if crl_pem:
                return crl_pem

            # If no CRL exists, generate one
            return self.update_crl()

        except Exception as e:
            logger.error(f"Error getting CRL: {str(e)}")
            return None

    def get_crl_der(self) -> Optional[bytes]:
        """
        Get CRL in DER format (for binary distribution).

        Returns:
            CRL as DER bytes or None
        """
        try:
            from cryptography.hazmat.primitives import serialization

            crl_pem = self.get_crl_pem()
            if not crl_pem:
                return None

            # Convert PEM to DER
            from cryptography import x509
            crl = x509.load_pem_x509_crl(crl_pem)

            if crl:
                return crl.public_bytes(serialization.Encoding.DER)

            return None

        except Exception as e:
            logger.error(f"Error converting CRL to DER: {str(e)}")
            return None

    def get_crl_info(self) -> dict:
        """
        Get information about the current CRL.

        Returns:
            Dictionary with CRL information
        """
        try:
            from cryptography import x509

            crl_pem = self.get_crl_pem()
            if not crl_pem:
                return {'status': 'no_crl', 'message': 'No CRL available'}

            crl = x509.load_pem_x509_crl(crl_pem)

            revoked_serials = self.get_revoked_serials()

            return {
                'status': 'available',
                'issuer': str(crl.issuer),
                'last_update': crl.last_update_utc.isoformat() if crl.last_update_utc else None,
                'next_update': crl.next_update_utc.isoformat() if crl.next_update_utc else None,
                'revoked_count': len(revoked_serials),
                'revoked_serials': revoked_serials
            }

        except Exception as e:
            logger.error(f"Error getting CRL info: {str(e)}")
            return {'status': 'error', 'error': str(e)}
