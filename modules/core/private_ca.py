"""
Private CA module for CertMate
Handles self-signed Certificate Authority generation and client certificate signing
"""

import logging
import os
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class PrivateCAGenerator:
    """
    Generates and manages a self-signed Certificate Authority for CertMate.
    Used for issuing client certificates.
    """

    def __init__(self, ca_dir: Path):
        """
        Initialize Private CA Generator.

        Args:
            ca_dir: Directory to store CA private key and certificate
        """
        self.ca_dir = Path(ca_dir)
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cert_path = self.ca_dir / "ca.crt"
        self.ca_metadata_path = self.ca_dir / "ca_metadata.json"
        self.crl_path = self.ca_dir / "crl.pem"

        self._ca_key = None
        self._ca_cert = None
        self._ca_loaded = False

    def initialize(self, force: bool = False) -> bool:
        """
        Initialize CA if it doesn't exist.

        Args:
            force: Force regeneration even if CA exists

        Returns:
            True if CA was initialized/exists, False if error
        """
        try:
            # Create CA directory if it doesn't exist
            self.ca_dir.mkdir(parents=True, exist_ok=True)

            # Check if CA already exists
            if self.ca_cert_path.exists() and self.ca_key_path.exists() and not force:
                logger.info("CA already exists, loading from disk")
                return self._load_ca()

            # Generate new CA
            if force:
                logger.warning("Force regenerating CA - backing up existing CA")
                self._backup_existing_ca()

            logger.info("Generating new self-signed Certificate Authority")
            return self._generate_ca()

        except Exception as e:
            logger.error(f"Error initializing CA: {e}")
            return False

    def _generate_ca(self) -> bool:
        """
        Generate a new self-signed CA certificate and private key.

        Returns:
            True if successful
        """
        try:
            # Generate RSA private key (4096 bits for CA)
            logger.debug("Generating RSA 4096 private key for CA")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )

            # Create CA subject and issuer (same for self-signed)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Switzerland"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertMate"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "CertMate CA"),
            ])

            # Build CA certificate
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(issuer)
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())

            # Validity: 10 years for CA
            not_valid_before = datetime.utcnow()
            not_valid_after = not_valid_before + timedelta(days=3650)
            cert_builder = cert_builder.not_valid_before(not_valid_before)
            cert_builder = cert_builder.not_valid_after(not_valid_after)

            # Add CA extensions
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )

            # Self-sign the certificate
            ca_cert = cert_builder.sign(
                private_key,
                hashes.SHA256(),
                backend=default_backend()
            )

            # Save private key (PEM format)
            logger.debug(f"Saving CA private key to {self.ca_key_path}")
            with open(self.ca_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Restrict permissions on private key (Unix-like systems)
            try:
                os.chmod(self.ca_key_path, 0o600)
                logger.debug("Set CA private key permissions to 0600")
            except Exception as e:
                logger.warning(f"Could not set key permissions: {e}")

            # Save certificate (PEM format)
            logger.debug(f"Saving CA certificate to {self.ca_cert_path}")
            with open(self.ca_cert_path, 'wb') as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

            # Save metadata
            self._save_ca_metadata(ca_cert, private_key)

            # Load into memory
            self._ca_key = private_key
            self._ca_cert = ca_cert
            self._ca_loaded = True

            logger.info(f"Successfully generated CA (valid until {not_valid_after.isoformat()})")
            return True

        except Exception as e:
            logger.error(f"Error generating CA: {e}")
            return False

    def _load_ca(self) -> bool:
        """
        Load CA certificate and private key from disk.

        Returns:
            True if successful
        """
        try:
            if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
                logger.warning("CA files not found")
                return False

            # Load private key
            with open(self.ca_key_path, 'rb') as f:
                self._ca_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            # Load certificate
            with open(self.ca_cert_path, 'rb') as f:
                cert_data = f.read()
                self._ca_cert = x509.load_pem_x509_certificate(
                    cert_data,
                    backend=default_backend()
                )

            self._ca_loaded = True
            logger.info("CA loaded successfully")
            return True

        except Exception as e:
            logger.error(f"Error loading CA: {e}")
            return False

    def _save_ca_metadata(self, cert: x509.Certificate, key) -> bool:
        """
        Save CA metadata to JSON file.

        Args:
            cert: X.509 certificate
            key: Private key

        Returns:
            True if successful
        """
        try:
            # Extract certificate details
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn[0].value if cn else "CertMate CA"

            metadata = {
                "type": "ca",
                "common_name": common_name,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": cert.not_valid_after.isoformat(),
                "serial_number": str(cert.serial_number),
                "key_size": key.key_size,
                "issuer": {
                    "country": "CH",
                    "organization": "CertMate",
                    "common_name": common_name
                }
            }

            with open(self.ca_metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.debug(f"Saved CA metadata to {self.ca_metadata_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving CA metadata: {e}")
            return False

    def _backup_existing_ca(self) -> bool:
        """
        Backup existing CA files before regeneration.

        Returns:
            True if successful
        """
        try:
            if not self.ca_cert_path.exists():
                return True

            # Create backup directory
            backup_dir = self.ca_dir / "backups"
            backup_dir.mkdir(exist_ok=True)

            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

            # Backup files
            import shutil
            if self.ca_key_path.exists():
                shutil.copy(self.ca_key_path, backup_dir / f"ca_{timestamp}.key")
            if self.ca_cert_path.exists():
                shutil.copy(self.ca_cert_path, backup_dir / f"ca_{timestamp}.crt")
            if self.ca_metadata_path.exists():
                shutil.copy(self.ca_metadata_path, backup_dir / f"ca_metadata_{timestamp}.json")

            logger.info(f"Backed up existing CA to {backup_dir}")
            return True

        except Exception as e:
            logger.error(f"Error backing up CA: {e}")
            return False

    def is_ca_loaded(self) -> bool:
        """Check if CA is loaded in memory."""
        return self._ca_loaded and self._ca_key is not None and self._ca_cert is not None

    def get_ca_certificate(self) -> Optional[x509.Certificate]:
        """Get loaded CA certificate."""
        if not self._ca_loaded:
            self._load_ca()
        return self._ca_cert

    def get_ca_private_key(self):
        """Get loaded CA private key."""
        if not self._ca_loaded:
            self._load_ca()
        return self._ca_key

    def get_ca_cert_pem(self) -> Optional[bytes]:
        """Get CA certificate as PEM bytes."""
        if not self.ca_cert_path.exists():
            return None
        return self.ca_cert_path.read_bytes()

    def get_ca_metadata(self) -> Optional[Dict[str, Any]]:
        """Get CA metadata from file."""
        if not self.ca_metadata_path.exists():
            return None
        try:
            with open(self.ca_metadata_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading CA metadata: {e}")
            return None

    def export_ca_cert(self, output_path: Path) -> bool:
        """
        Export CA certificate to a file.

        Args:
            output_path: Where to save the certificate

        Returns:
            True if successful
        """
        try:
            if not self.ca_cert_path.exists():
                logger.error("CA certificate not found")
                return False

            import shutil
            shutil.copy(self.ca_cert_path, output_path)
            logger.info(f"Exported CA certificate to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error exporting CA certificate: {e}")
            return False

    def sign_certificate_request(
        self,
        csr: x509.CertificateSigningRequest,
        days_valid: int = 365,
        extended_key_usage: list = None
    ) -> Optional[x509.Certificate]:
        """
        Sign a Certificate Signing Request (CSR).

        Args:
            csr: X.509 CSR to sign
            days_valid: Days until certificate expires (default 365)
            extended_key_usage: List of extended key usage strings (e.g., ['clientAuth'])

        Returns:
            Signed X.509 certificate or None if error
        """
        try:
            if not self.is_ca_loaded():
                logger.error("CA not loaded")
                return None

            # Create certificate from CSR
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(csr.subject)
            cert_builder = cert_builder.issuer_name(self._ca_cert.issuer)
            cert_builder = cert_builder.public_key(csr.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())

            # Validity
            not_valid_before = datetime.utcnow()
            not_valid_after = not_valid_before + timedelta(days=days_valid)
            cert_builder = cert_builder.not_valid_before(not_valid_before)
            cert_builder = cert_builder.not_valid_after(not_valid_after)

            # Copy extensions from CSR
            for extension in csr.extensions:
                cert_builder = cert_builder.add_extension(
                    extension.value,
                    critical=extension.critical
                )

            # Add extended key usage if specified
            if extended_key_usage:
                try:
                    eku_list = []
                    for oid_string in extended_key_usage:
                        if oid_string == "clientAuth":
                            eku_list.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
                        elif oid_string == "serverAuth":
                            eku_list.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)
                        elif oid_string == "codeSigning":
                            sku_list.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)
                        elif oid_string == "timeStamping":
                            eku_list.append(x509.oid.ExtendedKeyUsageOID.TIME_STAMPING)

                    if eku_list:
                        # Remove any existing EKU extension
                        try:
                            cert_builder._extensions = [
                                ext for ext in cert_builder._extensions
                                if ext.oid != x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
                            ]
                        except:
                            pass

                        cert_builder = cert_builder.add_extension(
                            x509.ExtendedKeyUsage(eku_list),
                            critical=True
                        )
                except Exception as e:
                    logger.warning(f"Error adding extended key usage: {e}")

            # Add subject key identifier
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False
            )

            # Add authority key identifier
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_cert.public_key()),
                critical=False
            )

            # Sign the certificate
            signed_cert = cert_builder.sign(
                self._ca_key,
                hashes.SHA256(),
                backend=default_backend()
            )

            logger.info(f"Successfully signed certificate (serial: {signed_cert.serial_number})")
            return signed_cert

        except Exception as e:
            logger.error(f"Error signing certificate: {e}")
            return None

    def generate_crl(self, revoked_serials: list = None) -> Optional[bytes]:
        """
        Generate a Certificate Revocation List (CRL).

        Args:
            revoked_serials: List of serial numbers to revoke

        Returns:
            CRL as PEM bytes or None if error
        """
        try:
            if not self.is_ca_loaded():
                logger.error("CA not loaded")
                return None

            # Build CRL
            crl_builder = x509.CertificateRevocationListBuilder()
            crl_builder = crl_builder.issuer_name(self._ca_cert.issuer)
            crl_builder = crl_builder.last_update(datetime.utcnow())
            crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=7))

            # Add revoked certificates
            if revoked_serials:
                for serial in revoked_serials:
                    revoked_cert = x509.RevokedCertificateBuilder()
                    revoked_cert = revoked_cert.serial_number(serial)
                    revoked_cert = revoked_cert.revocation_date(datetime.utcnow())
                    crl_builder = crl_builder.add_revoked_certificate(revoked_cert.build())

            # Sign CRL
            crl = crl_builder.sign(
                private_key=self._ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )

            # Save CRL
            crl_pem = crl.public_bytes(serialization.Encoding.PEM)
            with open(self.crl_path, 'wb') as f:
                f.write(crl_pem)

            logger.info(f"Generated CRL with {len(revoked_serials or [])} revoked certificates")
            return crl_pem

        except Exception as e:
            logger.error(f"Error generating CRL: {e}")
            return None

    def get_crl_pem(self) -> Optional[bytes]:
        """Get CRL as PEM bytes."""
        if not self.crl_path.exists():
            return None
        return self.crl_path.read_bytes()
