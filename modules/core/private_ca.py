"""
Private CA module for CertMate
Handles self-signed Certificate Authority generation and client certificate signing
"""

import logging
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


# Map persisted revocation-reason strings (see ClientCertificateManager
# metadata `reason_revoked`, which is free-form and may be camelCase from the
# API or snake_case) onto the x509 CRLReason flags. RFC 5280 says an
# "unspecified" reason SHOULD be omitted from the CRL entry, so it is
# deliberately absent here and treated as "no reason extension".
_REASON_TO_FLAG = {
    "keycompromise": x509.ReasonFlags.key_compromise,
    "cacompromise": x509.ReasonFlags.ca_compromise,
    "affiliationchanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
    "certificatehold": x509.ReasonFlags.certificate_hold,
    "privilegewithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aacompromise": x509.ReasonFlags.aa_compromise,
    "removefromcrl": x509.ReasonFlags.remove_from_crl,
}


def _reason_to_flag(reason) -> Optional[x509.ReasonFlags]:
    """Resolve a persisted reason string to a CRLReason flag, or None when no
    meaningful reason applies (unknown / empty / 'unspecified')."""
    if not reason:
        return None
    key = str(reason).replace("_", "").replace("-", "").replace(" ", "").lower()
    return _REASON_TO_FLAG.get(key)


def _parse_revoked_at(revoked_at) -> datetime:
    """Parse a persisted revoked_at timestamp into an aware UTC datetime.

    Metadata stores revoked_at via utc_now().isoformat() (naive, no offset),
    but callers/tests may also pass a trailing-'Z' form. A naive value is
    interpreted as UTC. On any parse failure we fall back to now() so a
    malformed record still lands in the CRL rather than crashing the whole
    regeneration."""
    if isinstance(revoked_at, datetime):
        dt = revoked_at
    elif revoked_at:
        try:
            text = str(revoked_at).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        except (ValueError, TypeError):
            logger.warning("Unparseable revoked_at %r; using now()", revoked_at)
            return datetime.now(timezone.utc)
    else:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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

    @staticmethod
    def _atomic_write_bytes(path: Path, content: bytes, mode: int) -> None:
        """Write bytes atomically at the given mode: create a temp sibling
        (mkstemp creates it 0600, before any content is written), set the final
        mode, fsync, then rename over the destination.

        The previous open()-write-then-chmod pattern had two defects for the CA
        private key: a crash / SIGKILL / disk-full mid-write left a truncated,
        unrecoverable ca.key (corrupting the root of trust); and the file
        existed under the process umask (often 0644) for the window between
        create and chmod, briefly exposing the root CA private key to any local
        user. mkstemp is 0600 from the first byte and the rename is atomic, so a
        reader sees either the whole old file or the whole new one — never a
        partial write, and never a world-readable key. Mirrors
        LocalFileSystemBackend._atomic_write_bytes."""
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=path.name)
        try:
            os.chmod(tmp_name, mode)
            with os.fdopen(fd, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

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
            not_valid_before = datetime.now(timezone.utc)
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

            # Save private key (PEM format) atomically at 0600. The key is
            # 0600 from the first byte on disk (never world-readable under the
            # umask) and a crash mid-write cannot corrupt the root of trust.
            logger.debug(f"Saving CA private key to {self.ca_key_path}")
            self._atomic_write_bytes(
                self.ca_key_path,
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ),
                0o600,
            )
            logger.debug("Wrote CA private key at 0600 (atomic)")

            # Save certificate (PEM format) atomically so a crash never leaves a
            # half-written CA cert. 0600: the CA cert is served over HTTP by
            # certmate, not read off disk by other local users, so there is no
            # reason to make the CA's own directory world-readable (defence in
            # depth; also unlike leaf certs which a co-located web server reads).
            logger.debug(f"Saving CA certificate to {self.ca_cert_path}")
            self._atomic_write_bytes(
                self.ca_cert_path,
                ca_cert.public_bytes(serialization.Encoding.PEM),
                0o600,
            )

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

            # Check CA certificate expiry
            if datetime.now(timezone.utc) > self._ca_cert.not_valid_after_utc:
                logger.error("CA certificate has expired — cannot sign new certificates")
                self._ca_loaded = False
                return False

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
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": cert.not_valid_after_utc.isoformat(),
                "serial_number": str(cert.serial_number),
                "key_size": key.key_size,
                "issuer": {
                    "country": "CH",
                    "organization": "CertMate",
                    "common_name": common_name
                }
            }

            # Non-secret metadata, but the whole CA dir is certmate-internal
            # (certmate is the only on-disk reader; the CA cert is served over
            # HTTP, not read off disk by other users), so keep it 0600 like the
            # rest of the CA material. Written atomically so a crash never
            # leaves a truncated / unparseable JSON file behind.
            self._atomic_write_bytes(
                self.ca_metadata_path,
                json.dumps(metadata, indent=2).encode("utf-8"),
                0o600,
            )

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

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

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
        """Check if CA is loaded in memory and not expired."""
        if self._ca_loaded and self._ca_cert is not None:
            if datetime.now(timezone.utc) > self._ca_cert.not_valid_after_utc:
                logger.error("CA certificate has expired at runtime — marking as unloaded")
                self._ca_loaded = False
                return False
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
            not_valid_before = datetime.now(timezone.utc)
            not_valid_after = not_valid_before + timedelta(days=days_valid)
            cert_builder = cert_builder.not_valid_before(not_valid_before)
            cert_builder = cert_builder.not_valid_after(not_valid_after)

            # Do NOT copy BasicConstraints / KeyUsage verbatim from the CSR.
            # A CSR carrying BasicConstraints(ca=True) + KeyUsage(keyCertSign)
            # would otherwise mint a CA-capable certificate under CertMate's
            # root, letting the holder issue trusted certs for any name. Pin a
            # leaf profile instead: ca=False (critical) and a fixed leaf
            # KeyUsage. Only SubjectAlternativeName is carried over from the CSR.
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            cert_builder = cert_builder.add_extension(
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
                critical=True,
            )
            try:
                san = csr.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                cert_builder = cert_builder.add_extension(
                    san.value, critical=san.critical
                )
            except x509.ExtensionNotFound:
                pass

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
                            eku_list.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)
                        elif oid_string == "timeStamping":
                            eku_list.append(x509.oid.ExtendedKeyUsageOID.TIME_STAMPING)

                    if eku_list:
                        # Remove any existing EKU extension
                        try:
                            cert_builder._extensions = [
                                ext for ext in cert_builder._extensions
                                if ext.oid != x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
                            ]
                        except (AttributeError, TypeError) as eku_error:
                            logger.debug(f"Could not remove existing EKU extension: {eku_error}")

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
            revoked_serials: List of revoked entries. Each entry may be either:
                * an int serial number (revocation_date defaults to now, no
                  reason) — the legacy shape, kept for backward compatibility;
                * a dict carrying the persisted revocation record, e.g.
                  ``{"serial_number": <int|str>, "revoked_at": <iso str>,
                  "reason_revoked": <str>}`` (the ``reason`` key is also
                  accepted). The entry's revocation_date is taken from
                  ``revoked_at`` and a CRLReason extension is added when a
                  meaningful reason is present. Threading the persisted date
                  through is what keeps a later regeneration from rewriting
                  every older entry's revocation_date to "now" (which breaks
                  date-sensitive validation).

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
            crl_builder = crl_builder.last_update(datetime.now(timezone.utc))
            crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(days=7))

            # Add revoked certificates, preserving each entry's persisted
            # revocation date and reason.
            count = 0
            if revoked_serials:
                for entry in revoked_serials:
                    if isinstance(entry, dict):
                        raw_serial = entry.get("serial_number", 0)
                        revoked_at = entry.get("revoked_at")
                        reason = entry.get("reason_revoked", entry.get("reason"))
                    else:
                        raw_serial = entry
                        revoked_at = None
                        reason = None

                    try:
                        serial = int(raw_serial)
                    except (ValueError, TypeError):
                        logger.warning("Skipping unparseable revoked serial %r", raw_serial)
                        continue
                    if serial <= 0:
                        continue

                    revoked_cert = x509.RevokedCertificateBuilder()
                    revoked_cert = revoked_cert.serial_number(serial)
                    revoked_cert = revoked_cert.revocation_date(_parse_revoked_at(revoked_at))
                    flag = _reason_to_flag(reason)
                    if flag is not None:
                        revoked_cert = revoked_cert.add_extension(
                            x509.CRLReason(flag), critical=False
                        )
                    crl_builder = crl_builder.add_revoked_certificate(revoked_cert.build())
                    count += 1

            # Sign CRL
            crl = crl_builder.sign(
                private_key=self._ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )

            # Save CRL atomically so a crash mid-write cannot leave relying
            # parties fetching a truncated CRL. 0600: certmate serves the CRL
            # over HTTP (get_crl_pem reads it as its own user), so the CA dir
            # stays fully non-world-readable.
            crl_pem = crl.public_bytes(serialization.Encoding.PEM)
            self._atomic_write_bytes(self.crl_path, crl_pem, 0o600)

            logger.info(f"Generated CRL with {count} revoked certificates")
            return crl_pem

        except Exception as e:
            logger.error(f"Error generating CRL: {e}")
            return None

    def get_crl_pem(self) -> Optional[bytes]:
        """Get CRL as PEM bytes."""
        if not self.crl_path.exists():
            return None
        return self.crl_path.read_bytes()
