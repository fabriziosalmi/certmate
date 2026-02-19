"""
Client Certificate Manager for CertMate
Handles creation, management, renewal, and revocation of client certificates
"""

import logging
import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from .private_ca import PrivateCAGenerator
from .csr_handler import CSRHandler
from .constants import MIN_CERTIFICATE_VALIDITY_DAYS, MAX_CERTIFICATE_VALIDITY_DAYS

logger = logging.getLogger(__name__)


class ClientCertificateManager:
    """
    Manages client certificates for mTLS, VPN, and user authentication.
    """

    def __init__(self, client_certs_dir: Path, private_ca: PrivateCAGenerator):
        """
        Initialize Client Certificate Manager.

        Args:
            client_certs_dir: Directory to store client certificates
            private_ca: PrivateCAGenerator instance for signing
        """
        self.client_certs_dir = Path(client_certs_dir)
        self.private_ca = private_ca

        # Create subdirectories for different cert types
        self.vpn_certs_dir = self.client_certs_dir / "vpn"
        self.api_certs_dir = self.client_certs_dir / "api"
        self.other_certs_dir = self.client_certs_dir / "other"

        self._ensure_directories()

    def _ensure_directories(self):
        """Create all required directories."""
        for cert_dir in [self.vpn_certs_dir, self.api_certs_dir, self.other_certs_dir]:
            cert_dir.mkdir(parents=True, exist_ok=True)

    def _get_cert_subdir(self, cert_usage: str) -> Path:
        """Get subdirectory based on certificate usage."""
        cert_usage_lower = cert_usage.lower() if cert_usage else "other"

        if "vpn" in cert_usage_lower:
            return self.vpn_certs_dir
        elif "api" in cert_usage_lower or "mtls" in cert_usage_lower:
            return self.api_certs_dir
        else:
            return self.other_certs_dir

    def create_client_certificate(
        self,
        common_name: str,
        email: str = "",
        organization: str = "CertMate",
        organizational_unit: str = "Users",
        cert_usage: str = "api-mtls",
        days_valid: int = 365,
        generate_key: bool = True,
        csr_pem: Optional[bytes] = None,
        notes: str = ""
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Create a new client certificate.

        Args:
            common_name: Common name for the certificate
            email: Email address
            organization: Organization name
            organizational_unit: Organizational unit
            cert_usage: Certificate usage type (vpn, api-mtls, user-auth, etc)
            days_valid: Days until expiration (default 365)
            generate_key: If True, CertMate generates private key; if False, use CSR
            csr_pem: PEM-encoded CSR (if generate_key=False)
            notes: Additional notes

        Returns:
            Tuple of (success, error_message, certificate_data)
        """
        try:
            # Validate common_name
            if not common_name or not common_name.strip():
                return False, "Common name is required", None
            if len(common_name) > 64:
                return False, "Common name must be 64 characters or less", None
            
            # Validate days_valid
            if not isinstance(days_valid, int) or days_valid < MIN_CERTIFICATE_VALIDITY_DAYS or days_valid > MAX_CERTIFICATE_VALIDITY_DAYS:
                return False, f"days_valid must be between {MIN_CERTIFICATE_VALIDITY_DAYS} and {MAX_CERTIFICATE_VALIDITY_DAYS}", None
            
            # Generate unique identifier
            identifier = f"{common_name.lower().replace(' ', '-')}-{uuid4().hex[:8]}"

            # Determine storage directory
            cert_dir = self._get_cert_subdir(cert_usage)
            cert_subdir = cert_dir / identifier
            cert_subdir.mkdir(parents=True, exist_ok=True)

            # Handle CSR or generate CSR + key
            if generate_key:
                # Generate CSR and private key
                csr_pem, key_pem, error = CSRHandler.create_csr(
                    common_name=common_name,
                    organization=organization,
                    organizational_unit=organizational_unit,
                    email=email,
                    country="CH",
                    state="Switzerland"
                )

                if error:
                    logger.error(f"Failed to create CSR: {error}")
                    return False, error, None

                # Save CSR and key
                csr_path = cert_subdir / f"{identifier}.csr"
                key_path = cert_subdir / f"{identifier}.key"

                with open(csr_path, 'wb') as f:
                    f.write(csr_pem)
                with open(key_path, 'wb') as f:
                    f.write(key_pem)

                os.chmod(key_path, 0o600)
                logger.debug(f"Generated and saved CSR/key for {identifier}")

            else:
                # Validate provided CSR
                if not csr_pem:
                    return False, "CSR required when generate_key=False", None

                is_valid, error, csr_obj = CSRHandler.validate_csr_pem(csr_pem)
                if not is_valid:
                    return False, f"Invalid CSR: {error}", None

                # Save provided CSR
                csr_path = cert_subdir / f"{identifier}.csr"
                with open(csr_path, 'wb') as f:
                    f.write(csr_pem)

            # Load CSR from saved file
            success, error, csr_obj = CSRHandler.load_csr_from_file(
                cert_subdir / f"{identifier}.csr"
            )

            if not success:
                logger.error(f"Failed to load CSR: {error}")
                return False, f"Failed to load CSR: {error}", None

            # Sign the certificate with CA
            signed_cert = self.private_ca.sign_certificate_request(
                csr=csr_obj,
                days_valid=days_valid,
                extended_key_usage=["clientAuth"]
            )

            if not signed_cert:
                logger.error("Failed to sign certificate")
                return False, "Failed to sign certificate with CA", None

            # Save signed certificate
            cert_path = cert_subdir / f"{identifier}.crt"
            with open(cert_path, 'wb') as f:
                f.write(signed_cert.public_bytes(serialization.Encoding.PEM))

            # Create metadata
            metadata = {
                "type": "client",
                "identifier": identifier,
                "common_name": common_name,
                "email": email,
                "organization": organization,
                "organizational_unit": organizational_unit,
                "cert_usage": cert_usage,
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "extended_key_usage": ["clientAuth"],
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(days=days_valid)).isoformat(),
                "serial_number": str(signed_cert.serial_number),
                "renewal_enabled": True,
                "renewal_threshold_days": 30,
                "csr_required": not generate_key,
                "ca_used": "internal",
                "revoked": False,
                "revoked_at": None,
                "reason_revoked": None,
                "crl_entry_serial": None,
                "notes": notes
            }

            # Save metadata
            metadata_path = cert_subdir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Successfully created client certificate: {identifier}")

            # Return certificate data
            cert_data = {
                "identifier": identifier,
                "paths": {
                    "certificate": str(cert_path),
                    "private_key": str(cert_subdir / f"{identifier}.key") if generate_key else None,
                    "csr": str(cert_subdir / f"{identifier}.csr"),
                    "metadata": str(metadata_path)
                },
                "metadata": metadata
            }

            return True, None, cert_data

        except Exception as e:
            logger.error(f"Error creating client certificate: {str(e)}")
            return False, "An internal error occurred while creating the certificate", None

    def list_client_certificates(
        self,
        cert_usage: Optional[str] = None,
        revoked: Optional[bool] = None,
        search_term: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List client certificates with optional filtering.

        Args:
            cert_usage: Filter by usage type
            revoked: Filter by revocation status
            search_term: Search by common name or email

        Returns:
            List of certificate metadata dictionaries
        """
        try:
            certificates = []

            # Determine which directories to scan
            if cert_usage:
                dirs_to_scan = [self._get_cert_subdir(cert_usage)]
            else:
                dirs_to_scan = [self.vpn_certs_dir, self.api_certs_dir, self.other_certs_dir]

            # Scan directories
            for cert_dir in dirs_to_scan:
                if not cert_dir.exists():
                    continue

                for metadata_file in cert_dir.glob("*/metadata.json"):
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)

                        # Apply filters
                        if revoked is not None:
                            if metadata.get("revoked") != revoked:
                                continue

                        if search_term:
                            search_lower = search_term.lower()
                            cn = metadata.get("common_name", "").lower()
                            email = metadata.get("email", "").lower()
                            if search_lower not in cn and search_lower not in email:
                                continue

                        certificates.append(metadata)

                    except Exception as e:
                        logger.warning(f"Error reading metadata {metadata_file}: {e}")
                        continue

            # Sort by creation date (newest first)
            certificates.sort(
                key=lambda x: x.get("created_at", ""),
                reverse=True
            )

            return certificates

        except Exception as e:
            logger.error(f"Error listing client certificates: {str(e)}")
            return []

    def get_certificate_metadata(self, identifier: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific certificate.

        Args:
            identifier: Certificate identifier

        Returns:
            Metadata dictionary or None
        """
        try:
            # Search for metadata file
            for metadata_file in self.client_certs_dir.glob(f"*/{identifier}/metadata.json"):
                with open(metadata_file, 'r') as f:
                    return json.load(f)

            logger.warning(f"Certificate not found: {identifier}")
            return None

        except Exception as e:
            logger.error(f"Error getting certificate metadata: {str(e)}")
            return None

    def revoke_certificate(self, identifier: str, reason: str = "unspecified") -> Tuple[bool, Optional[str]]:
        """
        Revoke a client certificate.

        Args:
            identifier: Certificate identifier
            reason: Reason for revocation

        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Get metadata
            metadata = self.get_certificate_metadata(identifier)
            if not metadata:
                return False, f"Certificate not found: {identifier}"

            # Update metadata
            metadata["revoked"] = True
            metadata["revoked_at"] = datetime.utcnow().isoformat()
            metadata["reason_revoked"] = reason

            # Save updated metadata
            for metadata_file in self.client_certs_dir.glob(f"*/{identifier}/metadata.json"):
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)

                logger.info(f"Revoked certificate: {identifier} (reason: {reason})")

                # Update CRL with ALL revoked serials (not just the current one)
                all_revoked = self.list_client_certificates(revoked=True)
                revoked_serials = []
                for cert in all_revoked:
                    try:
                        sn = int(cert.get('serial_number', 0))
                        if sn > 0:
                            revoked_serials.append(sn)
                    except (ValueError, TypeError):
                        continue
                if revoked_serials:
                    self.private_ca.generate_crl(revoked_serials)

                return True, None

            return False, f"Metadata file not found for: {identifier}"

        except Exception as e:
            logger.error(f"Error revoking certificate: {str(e)}")
            return False, "An internal error occurred while revoking the certificate"

    def renew_certificate(self, identifier: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Renew a client certificate (create new one with same identity).

        Args:
            identifier: Certificate identifier

        Returns:
            Tuple of (success, error_message, new_cert_data)
        """
        try:
            # Get original metadata
            old_metadata = self.get_certificate_metadata(identifier)
            if not old_metadata:
                return False, f"Certificate not found: {identifier}", None

            # Prevent renewal if revoked
            if old_metadata.get("revoked"):
                return False, "Cannot renew a revoked certificate", None

            # Create new certificate with same parameters
            success, error, cert_data = self.create_client_certificate(
                common_name=old_metadata.get("common_name", ""),
                email=old_metadata.get("email", ""),
                organization=old_metadata.get("organization", "CertMate"),
                organizational_unit=old_metadata.get("organizational_unit", "Users"),
                cert_usage=old_metadata.get("cert_usage", "api-mtls"),
                generate_key=True,  # Always generate new key on renewal
                notes=f"Renewal of {identifier}"
            )

            if success:
                # Update old metadata to mark as superseded
                old_metadata["superseded_by"] = cert_data["identifier"]
                old_metadata["superseded_at"] = datetime.utcnow().isoformat()

                for metadata_file in self.client_certs_dir.glob(f"*/{identifier}/metadata.json"):
                    with open(metadata_file, 'w') as f:
                        json.dump(old_metadata, f, indent=2)

                logger.info(f"Renewed certificate: {identifier} -> {cert_data['identifier']}")
                return True, None, cert_data

            return False, error, None

        except Exception as e:
            logger.error(f"Error renewing certificate: {str(e)}")
            return False, "An internal error occurred while renewing the certificate", None

    def get_certificate_file(self, identifier: str, file_type: str = "crt") -> Optional[bytes]:
        """
        Get a certificate file (crt, key, or csr).

        Args:
            identifier: Certificate identifier
            file_type: Type of file (crt, key, csr)

        Returns:
            File contents or None
        """
        try:
            for cert_dir in self.client_certs_dir.glob(f"*/{identifier}"):
                file_path = cert_dir / f"{identifier}.{file_type}"
                if file_path.exists():
                    return file_path.read_bytes()

            logger.warning(f"File not found: {identifier}.{file_type}")
            return None

        except Exception as e:
            logger.error(f"Error getting certificate file: {str(e)}")
            return None

    def check_renewals(self) -> Tuple[int, int, List[str]]:
        """
        Check for certificates that need renewal.

        Returns:
            Tuple of (checked_count, renewed_count, renewed_identifiers)
        """
        try:
            checked_count = 0
            renewed_count = 0
            renewed_identifiers = []

            certificates = self.list_client_certificates(revoked=False)

            for cert_metadata in certificates:
                checked_count += 1

                # Check if renewal is enabled
                if not cert_metadata.get("renewal_enabled", False):
                    continue

                # Validate expires_at before parsing
                expires_at_str = cert_metadata.get("expires_at")
                if not expires_at_str:
                    logger.warning(f"Skipping certificate {cert_metadata.get('identifier')}: missing expires_at")
                    continue
                try:
                    expires_at = datetime.fromisoformat(expires_at_str)
                except (ValueError, TypeError):
                    logger.warning(f"Skipping certificate {cert_metadata.get('identifier')}: invalid expires_at format")
                    continue

                # Check expiration date
                threshold_days = cert_metadata.get("renewal_threshold_days", 30)
                renewal_date = expires_at - timedelta(days=threshold_days)

                if datetime.utcnow() >= renewal_date:
                    identifier = cert_metadata.get("identifier")
                    success, error, _ = self.renew_certificate(identifier)

                    if success:
                        renewed_count += 1
                        renewed_identifiers.append(identifier)
                        logger.info(f"Auto-renewed certificate: {identifier}")
                    else:
                        logger.warning(f"Failed to auto-renew {identifier}: {error}")

            logger.info(f"Certificate renewal check: {checked_count} checked, {renewed_count} renewed")
            return checked_count, renewed_count, renewed_identifiers

        except Exception as e:
            logger.error(f"Error checking renewals: {str(e)}")
            return 0, 0, []

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about client certificates.

        Returns:
            Dictionary with statistics
        """
        try:
            all_certs = self.list_client_certificates()
            active_certs = self.list_client_certificates(revoked=False)
            revoked_certs = self.list_client_certificates(revoked=True)

            # Count by usage
            by_usage = {}
            for cert in active_certs:
                usage = cert.get("cert_usage", "other")
                by_usage[usage] = by_usage.get(usage, 0) + 1

            # Count by organization
            by_org = {}
            for cert in active_certs:
                org = cert.get("organization", "Unknown")
                by_org[org] = by_org.get(org, 0) + 1

            return {
                "total": len(all_certs),
                "active": len(active_certs),
                "revoked": len(revoked_certs),
                "by_usage": by_usage,
                "by_organization": by_org,
                "ca_status": "active" if self.private_ca.is_ca_loaded() else "not_loaded"
            }

        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {}
