"""
CSR Handler module for CertMate
Handles Certificate Signing Request parsing, validation, and creation
"""

import logging
from typing import Optional, Tuple, Dict, Any
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CSRHandler:
    """
    Handles CSR (Certificate Signing Request) operations.
    Provides validation, creation, and parsing of CSRs.
    """

    @staticmethod
    def validate_csr_pem(csr_pem: bytes) -> Tuple[bool, Optional[str], Optional[x509.CertificateSigningRequest]]:
        """
        Validate a PEM-encoded CSR.

        Args:
            csr_pem: PEM bytes of CSR

        Returns:
            Tuple of (is_valid, error_message, csr_object)
        """
        try:
            if not csr_pem:
                return False, "CSR is empty", None

            # Load CSR
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())

            # Validate signature
            try:
                csr.public_key()  # This validates the signature implicitly
            except Exception as e:
                logger.error(f"Invalid CSR signature: {str(e)}")
                return False, "Invalid CSR signature", None

            # Check subject is present
            if not csr.subject:
                return False, "CSR has no subject", None

            # Check common name is present
            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn:
                return False, "CSR has no Common Name", None

            logger.info(f"CSR validation successful for CN={cn[0].value}")
            return True, None, csr

        except Exception as e:
            logger.error(f"CSR validation error: {str(e)}")
            return False, "CSR validation failed", None

    @staticmethod
    def get_csr_info(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
        """
        Extract information from a CSR.

        Args:
            csr: X.509 CSR object

        Returns:
            Dictionary with CSR details
        """
        try:
            subject = csr.subject

            # Extract common name
            cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attrs[0].value if cn_attrs else "Unknown"

            # Extract organization
            org_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            organization = org_attrs[0].value if org_attrs else ""

            # Extract organizational unit
            ou_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
            organizational_unit = ou_attrs[0].value if ou_attrs else ""

            # Extract email
            email_attrs = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
            email = email_attrs[0].value if email_attrs else ""

            # Extract country
            country_attrs = subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            country = country_attrs[0].value if country_attrs else ""

            # Extract state
            state_attrs = subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
            state = state_attrs[0].value if state_attrs else ""

            # Extract locality
            locality_attrs = subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
            locality = locality_attrs[0].value if locality_attrs else ""

            # Get key size
            public_key = csr.public_key()
            key_size = public_key.key_size if hasattr(public_key, 'key_size') else None

            # Extract SAN extension
            san_list = []
            try:
                san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        san_list.append(('DNS', name.value))
                    elif isinstance(name, x509.RFC822Name):
                        san_list.append(('Email', name.value))
                    elif isinstance(name, x509.IPAddress):
                        san_list.append(('IP', str(name.value)))
            except x509.ExtensionNotFound:
                pass

            return {
                'common_name': common_name,
                'organization': organization,
                'organizational_unit': organizational_unit,
                'email': email,
                'country': country,
                'state': state,
                'locality': locality,
                'key_size': key_size,
                'subject_alt_names': san_list,
                'signature_algorithm': csr.signature_algorithm_oid._name if csr.signature_algorithm_oid else "Unknown"
            }

        except Exception as e:
            logger.error(f"Error extracting CSR info: {str(e)}")
            return {}

    @staticmethod
    def create_csr(
        common_name: str,
        organization: str = "CertMate",
        organizational_unit: str = "Users",
        country: str = "CH",
        state: str = "Switzerland",
        locality: str = "",
        email: str = "",
        alternative_names: list = None,
        key_size: int = 2048
    ) -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
        """
        Create a new CSR with private key.

        Args:
            common_name: Common name for the certificate
            organization: Organization name
            organizational_unit: Organizational unit
            country: Country code (default CH)
            state: State/province
            locality: City/locality
            email: Email address
            alternative_names: List of alternative names (e.g., ['example.com', 'www.example.com'])
            key_size: RSA key size (default 2048)

        Returns:
            Tuple of (csr_pem, private_key_pem, error_message)
        """
        try:
            # Validate common name
            if not common_name or len(common_name) > 64:
                return None, None, "Common name must be 1-64 characters"

            # Reject control characters and null bytes in CN
            import re
            if re.search(r'[\x00-\x1f\x7f]', common_name):
                return None, None, "Common name contains invalid control characters"

            # Validate key size
            if key_size not in [2048, 4096]:
                return None, None, "Key size must be 2048 or 4096"

            logger.info(f"Creating CSR for CN={common_name} with {key_size}-bit key")

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

            # Build subject
            subject_attrs = [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]

            if locality:
                subject_attrs.insert(2, x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

            if email:
                subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

            subject = x509.Name(subject_attrs)

            # Build CSR
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(subject)

            # Add Subject Alternative Names if provided (limit to 100)
            if alternative_names:
                if len(alternative_names) > 100:
                    return None, None, "Too many SANs (maximum 100)"
                san_list = [x509.DNSName(name) for name in alternative_names]
                csr_builder = csr_builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )

            # Add key usage extension
            csr_builder = csr_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )

            # Sign CSR with private key
            csr = csr_builder.sign(
                private_key,
                hashes.SHA256(),
                backend=default_backend()
            )

            # Export CSR as PEM
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)

            # Export private key as PEM
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            logger.info(f"Successfully created CSR for {common_name}")
            return csr_pem, private_key_pem, None

        except Exception as e:
            logger.error(f"Error creating CSR: {str(e)}")
            return None, None, "CSR creation failed"

    @staticmethod
    def save_csr_and_key(
        csr_pem: bytes,
        private_key_pem: bytes,
        output_dir: Path,
        identifier: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Save CSR and private key to files.

        Args:
            csr_pem: CSR PEM bytes
            private_key_pem: Private key PEM bytes
            output_dir: Directory to save files
            identifier: Identifier for the certificate

        Returns:
            Tuple of (success, csr_path, key_path) or (False, error_message, None)
        """
        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            csr_path = output_dir / f"{identifier}.csr"
            key_path = output_dir / f"{identifier}.key"

            # Save CSR
            with open(csr_path, 'wb') as f:
                f.write(csr_pem)
            logger.debug(f"Saved CSR to {csr_path}")

            # Save private key
            with open(key_path, 'wb') as f:
                f.write(private_key_pem)

            # Restrict key permissions
            import os
            os.chmod(key_path, 0o600)
            logger.debug(f"Saved private key to {key_path}")

            return True, str(csr_path), str(key_path)

        except Exception as e:
            logger.error(f"Error saving CSR and key: {str(e)}")
            return False, "Failed to save CSR and key", None

    @staticmethod
    def load_csr_from_file(csr_path: Path) -> Tuple[bool, Optional[str], Optional[x509.CertificateSigningRequest]]:
        """
        Load CSR from file.

        Args:
            csr_path: Path to CSR file

        Returns:
            Tuple of (success, error_message, csr_object)
        """
        try:
            if not csr_path.exists():
                return False, f"CSR file not found: {csr_path}", None

            csr_pem = csr_path.read_bytes()
            return CSRHandler.validate_csr_pem(csr_pem)

        except Exception as e:
            logger.error(f"Error loading CSR: {str(e)}")
            return False, "Failed to load CSR", None
