"""
Certificate storage backends module for CertMate
Provides pluggable storage solutions for certificate storage including 
local filesystem, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, and Infisical
"""

import os
import json
import logging
import re
import shutil
import tempfile
import time
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from .constants import CERTIFICATE_FILES

logger = logging.getLogger(__name__)

_SAFE_DOMAIN_RE = re.compile(r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$')


def _is_transient(exc):
    """Determine whether an exception is transient and worth retrying.

    Checks exception type first (preferred), then falls back to HTTP
    status codes on cloud-SDK response objects, and finally to message
    keywords as a last resort.
    """
    # 1. Well-known transient exception types (no SDK import required)
    _TRANSIENT_TYPES = (
        ConnectionError, TimeoutError, OSError,
    )
    if isinstance(exc, _TRANSIENT_TYPES):
        return True

    # 2. Cloud SDK exceptions that carry an HTTP status code
    status = getattr(exc, 'status_code', None) or getattr(exc, 'code', None)
    if isinstance(status, int) and status in (429, 500, 502, 503, 504):
        return True
    # boto3 wraps status in response metadata
    response = getattr(exc, 'response', None)
    if isinstance(response, dict):
        http_code = response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        if isinstance(http_code, int) and http_code in (429, 500, 502, 503, 504):
            return True

    # 3. Fallback: keyword matching on the error message
    msg = str(exc).lower()
    return any(k in msg for k in (
        'timeout', 'rate', 'throttl', '429', '503',
        'service unavailable', 'connection',
    ))


def _with_retry(max_attempts=3, delay=1.0, exceptions=(Exception,)):
    """Decorator that retries a method on transient errors (rate limits, timeouts, etc.)"""
    import functools, time as _time
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if _is_transient(exc) and attempt < max_attempts:
                        logger.warning(f"{fn.__name__} attempt {attempt} failed (transient): {exc}. Retrying in {delay * attempt:.1f}s...")
                        _time.sleep(delay * attempt)
                        continue
                    raise  # non-transient — re-raise immediately
            raise last_exc
        return wrapper
    return decorator


def _validate_storage_domain(domain: str) -> str:
    """Validate domain name for use in storage backend paths/keys.
    Raises ValueError if domain contains path traversal or invalid chars."""
    if not domain or '..' in domain or '/' in domain or '\\' in domain or '\x00' in domain:
        raise ValueError(f"Invalid domain for storage: contains illegal characters")
    if not _SAFE_DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain for storage: does not match domain pattern")
    return domain


# Azure Key Vault storage modes. Default 'secrets' preserves the legacy
# behaviour. 'certificate' uses the native Certificate object (consumable
# directly by App Service / App Gateway / Front Door / API Management /
# AKS Ingress); 'both' writes to both surfaces during transitions or when
# the same vault is consumed by mixed clients.
AZURE_KV_MODE_SECRETS = 'secrets'
AZURE_KV_MODE_CERTIFICATE = 'certificate'
AZURE_KV_MODE_BOTH = 'both'
AZURE_KV_VALID_MODES = frozenset({AZURE_KV_MODE_SECRETS, AZURE_KV_MODE_CERTIFICATE, AZURE_KV_MODE_BOTH})

# Azure tag values cap at 256 chars; oversize SAN lists are truncated with
# a trailing '...' marker so operators can spot the truncation in the portal.
_AZURE_TAG_VALUE_MAX = 256


def _build_pfx(cert_pem: bytes, chain_pem: Optional[bytes], privkey_pem: bytes) -> bytes:
    """Bundle cert + chain + private key into a PKCS12 blob.

    The PFX is unencrypted — Key Vault re-encrypts it at rest on import. If
    the leaf or key bytes are missing or malformed, ``cryptography`` raises
    ``ValueError`` directly; we let that propagate so the caller sees a
    descriptive message.
    """
    from cryptography.hazmat.primitives.serialization import (
        pkcs12,
        load_pem_private_key,
        NoEncryption,
    )
    from cryptography.x509 import load_pem_x509_certificates

    leaf = load_pem_x509_certificates(cert_pem)[0]
    chain = load_pem_x509_certificates(chain_pem) if chain_pem else []
    key = load_pem_private_key(privkey_pem, password=None)
    return pkcs12.serialize_key_and_certificates(
        name=None,
        key=key,
        cert=leaf,
        cas=chain or None,
        encryption_algorithm=NoEncryption(),
    )


class CertificateStorageBackend(ABC):
    """Abstract base class for certificate storage backends"""
    
    @abstractmethod
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata for a domain"""
        pass
    
    @abstractmethod
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata for a domain"""
        pass
    
    @abstractmethod
    def list_certificates(self) -> List[str]:
        """List all stored certificate domains"""
        pass
    
    @abstractmethod
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate for a domain"""
        pass
    
    @abstractmethod
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists for a domain"""
        pass

    @abstractmethod
    def get_backend_name(self) -> str:
        """Get the name of this storage backend"""
        pass


class LocalFileSystemBackend(CertificateStorageBackend):
    """Local filesystem storage backend (default/legacy behavior)"""
    
    def __init__(self, cert_dir: Path):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"LocalFileSystemBackend initialized with cert_dir: {self.cert_dir}")
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to local filesystem"""
        try:
            domain_dir = self.cert_dir / domain
            domain_dir.mkdir(parents=True, exist_ok=True)
            
            # Store certificate files
            for filename, content in cert_files.items():
                file_path = domain_dir / filename
                with open(file_path, 'wb') as f:
                    f.write(content)
                # Set secure permissions for private keys
                if 'key' in filename.lower() or filename == 'privkey.pem':
                    os.chmod(file_path, 0o600)
                else:
                    os.chmod(file_path, 0o644)
            
            # Store metadata
            metadata_file = domain_dir / 'metadata.json'
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            os.chmod(metadata_file, 0o600)

            logger.info(f"Certificate stored successfully for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from local filesystem"""
        try:
            domain_dir = self.cert_dir / domain
            if not domain_dir.exists():
                return None
            
            cert_files = {}
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                file_path = domain_dir / filename
                if file_path.exists():
                    with open(file_path, 'rb') as f:
                        cert_files[filename] = f.read()
            
            # Load metadata
            metadata = {}
            metadata_file = domain_dir / 'metadata.json'
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in local filesystem"""
        try:
            domains = []
            if self.cert_dir.exists():
                for domain_dir in self.cert_dir.iterdir():
                    if domain_dir.is_dir() and (domain_dir / 'cert.pem').exists():
                        domains.append(domain_dir.name)
            return sorted(domains)
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from local filesystem"""
        try:
            domain_dir = self.cert_dir / domain
            if domain_dir.exists():
                shutil.rmtree(domain_dir)
                logger.info(f"Certificate deleted for {domain}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete certificate for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in local filesystem"""
        domain_dir = self.cert_dir / domain
        return domain_dir.exists() and (domain_dir / 'cert.pem').exists()
    
    def get_backend_name(self) -> str:
        return "local_filesystem"


class _AzureKeyVaultCertificateImporter:
    """Encapsulates Azure Key Vault Certificate-object operations.

    Kept as a private helper (composition) so AzureKeyVaultBackend remains
    a single class that handles auth/naming/retry while delegating the
    Certificate-API specifics here. Both clients are created lazily so that
    the helper can be instantiated even when the optional
    ``azure-keyvault-certificates`` package is missing — the import error
    is surfaced only when a Certificate-mode call is actually made.
    """

    def __init__(self, vault_url: str, credential, sanitize_name):
        self._vault_url = vault_url
        self._credential = credential
        self._sanitize_name = sanitize_name
        self._cert_client = None
        self._secret_client = None

    def _get_cert_client(self):
        if self._cert_client is None:
            try:
                from azure.keyvault.certificates import CertificateClient
            except ImportError:
                raise ImportError(
                    "Azure Key Vault Certificate mode requires the "
                    "'azure-keyvault-certificates' package"
                )
            self._cert_client = CertificateClient(vault_url=self._vault_url, credential=self._credential)
        return self._cert_client

    def _get_secret_client(self):
        if self._secret_client is None:
            from azure.keyvault.secrets import SecretClient
            self._secret_client = SecretClient(vault_url=self._vault_url, credential=self._credential)
        return self._secret_client

    def _certificate_name(self, domain: str) -> str:
        return self._sanitize_name(f"cert-{domain}")

    # Metadata keys we explicitly project to/from Azure tags. Any key outside
    # this set is ignored on rehydrate so that vault-level tags added by
    # Azure Policy or operators (Environment=prod, CostCenter=42, …) do not
    # contaminate the metadata returned to the rest of CertMate.
    _STRING_METADATA_KEYS = (
        'domain', 'dns_provider', 'challenge_type', 'email', 'account_id', 'created_at',
    )
    _CSV_TRUNCATION_MARKER = '...'

    @classmethod
    def _build_tags(cls, metadata: Dict[str, Any]) -> Dict[str, str]:
        """Project metadata onto Azure tags (string keys/values, ≤256 chars).

        ``san_domains`` is serialised as CSV; if the result exceeds the tag
        value cap it is truncated with a trailing ``...`` marker that the
        rehydration path strips back off cleanly.
        """
        tags: Dict[str, str] = {}
        for key in cls._STRING_METADATA_KEYS:
            value = metadata.get(key)
            if value is None or value == '':
                continue
            tags[key] = str(value)[:_AZURE_TAG_VALUE_MAX]
        # Treat staging=None the same as staging-not-present, to match how
        # other keys handle missing values and keep _build_tags + _tags_to_metadata
        # symmetric (None → no tag → no key on rehydrate).
        staging = metadata.get('staging')
        if staging is not None:
            tags['staging'] = 'true' if staging else 'false'
        san_domains = metadata.get('san_domains') or []
        if san_domains:
            csv = ','.join(str(d) for d in san_domains)
            if len(csv) > _AZURE_TAG_VALUE_MAX:
                logger.warning(
                    "san_domains for %s exceeds %d chars; truncating in tag (full list still in metadata secret if present)",
                    metadata.get('domain', '<unknown>'), _AZURE_TAG_VALUE_MAX,
                )
                csv = csv[:_AZURE_TAG_VALUE_MAX - len(cls._CSV_TRUNCATION_MARKER)] + cls._CSV_TRUNCATION_MARKER
            tags['san_domains'] = csv
        return tags

    @classmethod
    def _tags_to_metadata(cls, tags: Dict[str, str]) -> Dict[str, Any]:
        """Inverse of :meth:`_build_tags` with a strict allow-list."""
        if not tags:
            return {}
        metadata: Dict[str, Any] = {
            k: tags[k] for k in cls._STRING_METADATA_KEYS if k in tags
        }
        if 'staging' in tags:
            metadata['staging'] = tags['staging'] == 'true'
        san_csv = tags.get('san_domains')
        if san_csv:
            was_truncated = san_csv.endswith(cls._CSV_TRUNCATION_MARKER)
            if was_truncated:
                san_csv = san_csv[:-len(cls._CSV_TRUNCATION_MARKER)]
            entries = [d for d in san_csv.split(',') if d]
            # When the CSV was truncated, the last entry is, by construction,
            # an incomplete domain fragment (the truncation cut mid-string).
            # Drop it rather than expose a malformed FQDN to renew loops or
            # the dashboard.
            if was_truncated and entries:
                entries = entries[:-1]
            if entries:
                metadata['san_domains'] = entries
        return metadata

    def get_metadata_tags(self, domain: str) -> Dict[str, Any]:
        """Read metadata-from-tags for a Certificate object without exporting the PFX."""
        cert_name = self._certificate_name(domain)
        try:
            cert = self._get_cert_client().get_certificate(cert_name)
        except Exception as e:
            logger.debug("Could not read tags for Certificate %s: %s", cert_name, e)
            return {}
        return self._tags_to_metadata(dict(getattr(cert.properties, 'tags', None) or {}))

    def import_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Import the cert+chain+key bundle as a Key Vault Certificate object."""
        from azure.keyvault.certificates import CertificatePolicy

        cert_pem = cert_files.get('cert.pem')
        privkey_pem = cert_files.get('privkey.pem')
        if not cert_pem or not privkey_pem:
            logger.error(
                "Cannot import Certificate object for %s: cert.pem and privkey.pem are required",
                domain,
            )
            return False

        pfx = _build_pfx(cert_pem, cert_files.get('chain.pem'), privkey_pem)
        # Externally issued certs (Let's Encrypt, ZeroSSL, etc.) are flagged
        # with issuer "Unknown" so Key Vault does not try to renew them via
        # its built-in Certificate Manager — CertMate stays the source of
        # truth for renewals.
        policy = CertificatePolicy(issuer_name="Unknown", content_type="application/x-pkcs12")
        client = self._get_cert_client()
        cert_name = self._certificate_name(domain)
        client.import_certificate(
            certificate_name=cert_name,
            certificate_bytes=pfx,
            policy=policy,
            tags=self._build_tags(metadata),
            password=None,
        )
        logger.info("Certificate object imported into Azure Key Vault for %s as %s", domain, cert_name)
        return True

    def export_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Reconstruct the four PEM files (and metadata from tags) from a Certificate object.

        Azure exposes the full PFX (cert+key+chain) of an imported
        certificate via the Secret with the same name — that is the only
        way to retrieve the private key, since the Certificate API itself
        only returns the public certificate.
        """
        from cryptography.hazmat.primitives.serialization import (
            pkcs12,
            Encoding,
            PrivateFormat,
            NoEncryption,
        )
        import base64

        cert_name = self._certificate_name(domain)
        try:
            secret = self._get_secret_client().get_secret(cert_name)
        except Exception as e:
            logger.debug("Certificate object %s not found for %s: %s", cert_name, domain, e)
            return None

        secret_value = secret.value
        # Key Vault returns the PFX as base64 when content_type is PKCS12.
        # PEM-formatted certificates would be returned as-is; we only support
        # PKCS12 imports here, so decode accordingly.
        try:
            pfx_bytes = base64.b64decode(secret_value)
        except Exception as e:
            logger.error("Could not base64-decode Certificate secret for %s: %s", domain, e)
            return None

        try:
            key, leaf, additional = pkcs12.load_key_and_certificates(pfx_bytes, password=None)
        except Exception as e:
            logger.error("Could not parse PFX for %s: %s", domain, e)
            return None

        if leaf is None or key is None:
            logger.error("PFX for %s is missing leaf cert or private key", domain)
            return None

        cert_pem = leaf.public_bytes(Encoding.PEM)
        chain_pem = b''.join(c.public_bytes(Encoding.PEM) for c in (additional or []))
        privkey_pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        cert_files = {
            'cert.pem': cert_pem,
            'chain.pem': chain_pem,
            'fullchain.pem': cert_pem + chain_pem,
            'privkey.pem': privkey_pem,
        }

        metadata = self._tags_to_metadata(dict(secret.properties.tags or {}))
        return cert_files, metadata

    def list_domains(self) -> List[str]:
        """List domains stored as Certificate objects (read from the 'domain' tag)."""
        client = self._get_cert_client()
        domains = set()
        for props in client.list_properties_of_certificates():
            tags = getattr(props, 'tags', None) or {}
            domain = tags.get('domain')
            if domain:
                domains.add(domain)
        return sorted(domains)

    def delete(self, domain: str) -> bool:
        """Delete the Certificate object for a domain (best-effort)."""
        cert_name = self._certificate_name(domain)
        try:
            self._get_cert_client().begin_delete_certificate(cert_name)
            return True
        except Exception as e:
            logger.debug("Could not delete certificate object %s for %s: %s", cert_name, domain, e)
            return False

    def exists(self, domain: str) -> bool:
        """Return True if a Certificate object exists for the domain."""
        cert_name = self._certificate_name(domain)
        try:
            self._get_cert_client().get_certificate(cert_name)
            return True
        except Exception:
            return False

    def verify_api_access(self) -> None:
        """Probe Certificate API access; propagates SDK exceptions to the caller.

        ``next(iter(...))`` consumes only the first page so the probe stays
        cheap without depending on SDK kwargs that aren't part of the
        documented signature.
        """
        next(iter(self._get_cert_client().list_properties_of_certificates()), None)


class AzureKeyVaultBackend(CertificateStorageBackend):
    """Azure Key Vault storage backend.

    Supports three storage modes via ``config['storage_mode']``:

    * ``secrets`` (default): persist each PEM and the metadata as individual
      Key Vault Secrets. Backwards-compatible with the original layout.
    * ``certificate``: persist the cert+chain+key as a native Key Vault
      Certificate object (PKCS12), enabling direct binding from App Service,
      Application Gateway, Front Door, API Management or AKS Ingress.
    * ``both``: write to both surfaces. Reads still prefer the Secrets path
      (cheaper, no PFX parse).
    """

    def __init__(self, config: Dict[str, str]):
        self.vault_url = config.get('vault_url')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.tenant_id = config.get('tenant_id')

        self.vault_url = (self.vault_url or '').strip()
        self.client_id = (self.client_id or '').strip()
        self.client_secret = (self.client_secret or '').strip()
        self.tenant_id = (self.tenant_id or '').strip()
        if not all([self.vault_url, self.client_id, self.client_secret, self.tenant_id]):
            raise ValueError("Azure Key Vault backend requires vault_url, client_id, client_secret, and tenant_id")

        storage_mode = (config.get('storage_mode') or AZURE_KV_MODE_SECRETS).strip().lower()
        if storage_mode not in AZURE_KV_VALID_MODES:
            raise ValueError(
                f"Invalid storage_mode '{storage_mode}' for Azure Key Vault backend. "
                f"Expected one of: {sorted(AZURE_KV_VALID_MODES)}"
            )
        self.storage_mode = storage_mode

        self._client = None
        self._credential = None
        self._cert_importer: Optional[_AzureKeyVaultCertificateImporter] = None
        logger.info(
            "AzureKeyVaultBackend initialized for vault: %s (storage_mode=%s)",
            self.vault_url, self.storage_mode,
        )

    @property
    def writes_secrets(self) -> bool:
        return self.storage_mode in (AZURE_KV_MODE_SECRETS, AZURE_KV_MODE_BOTH)

    @property
    def writes_certificate(self) -> bool:
        return self.storage_mode in (AZURE_KV_MODE_CERTIFICATE, AZURE_KV_MODE_BOTH)

    def _get_credential(self):
        if self._credential is None:
            try:
                from azure.identity import ClientSecretCredential
            except ImportError:
                raise ImportError("Azure Key Vault backend requires the 'azure-identity' package")
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        return self._credential

    def _get_client(self):
        """Get Azure Key Vault SecretClient with lazy initialization"""
        if self._client is None:
            try:
                from azure.keyvault.secrets import SecretClient
            except ImportError:
                raise ImportError("Azure Key Vault backend requires 'azure-keyvault-secrets' and 'azure-identity' packages")
            self._client = SecretClient(vault_url=self.vault_url, credential=self._get_credential())
        return self._client

    def _get_cert_importer(self) -> _AzureKeyVaultCertificateImporter:
        if self._cert_importer is None:
            self._cert_importer = _AzureKeyVaultCertificateImporter(
                vault_url=self.vault_url,
                credential=self._get_credential(),
                sanitize_name=self._sanitize_secret_name,
            )
        return self._cert_importer

    @staticmethod
    def _sanitize_secret_name(name: str) -> str:
        """Sanitize name for Azure Key Vault secret naming requirements.

        Azure secret names support only alphanumerics and hyphens (max 127 chars).
        A 6-char CRC32 suffix prevents two different domain names from mapping to
        the same sanitized key (e.g. 'my-app.example.com' vs 'my.app-example.com').
        """
        import binascii
        sanitized = re.sub(r'[^a-zA-Z0-9-]', '-', name).strip('-')
        # Append a short hash of the ORIGINAL name to avoid collisions
        crc = binascii.crc32(name.encode()) & 0xFFFFFFFF
        suffix = f"-{crc:08x}"
        # Azure allows max 127 chars
        max_base = 127 - len(suffix)
        return sanitized[:max_base] + suffix

    def _store_as_secrets(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        client = self._get_client()
        for filename, content in cert_files.items():
            secret_name = self._sanitize_secret_name(f"cert-{domain}-{filename.replace('.', '-')}")
            client.set_secret(secret_name, content.decode('utf-8', errors='replace'))
        metadata_name = self._sanitize_secret_name(f"cert-{domain}-metadata")
        client.set_secret(metadata_name, json.dumps(metadata))
        return True

    @_with_retry()
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to Azure Key Vault."""
        try:
            _validate_storage_domain(domain)
            ok_secrets = True
            ok_certificate = True

            if self.writes_secrets:
                ok_secrets = self._store_as_secrets(domain, cert_files, metadata)
            if self.writes_certificate:
                try:
                    ok_certificate = self._get_cert_importer().import_certificate(domain, cert_files, metadata)
                except Exception as inner:
                    logger.error("Certificate-object import failed for %s: %s", domain, inner)
                    ok_certificate = False

            if ok_secrets and ok_certificate:
                logger.info("Certificate stored successfully in Azure Key Vault for %s (mode=%s)", domain, self.storage_mode)
                return True
            return False

        except Exception as e:
            logger.error(f"Failed to store certificate in Azure Key Vault for {domain}: {e}")
            return False

    def _retrieve_from_secrets(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        client = self._get_client()
        cert_files: Dict[str, bytes] = {}
        for filename in CERTIFICATE_FILES:
            secret_name = self._sanitize_secret_name(f"cert-{domain}-{filename.replace('.', '-')}")
            try:
                secret = client.get_secret(secret_name)
                cert_files[filename] = secret.value.encode('utf-8')
            except Exception as e:
                logger.debug(f"Secret {secret_name} not found for {domain}: {e}")
                continue

        if not cert_files:
            return None

        metadata: Dict[str, Any] = {}
        try:
            metadata_name = self._sanitize_secret_name(f"cert-{domain}-metadata")
            secret = client.get_secret(metadata_name)
            metadata = json.loads(secret.value)
        except Exception as e:
            logger.debug(f"Metadata not found in Azure Key Vault for {domain}: {e}")

        return cert_files, metadata

    @_with_retry()
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from Azure Key Vault.

        Lookup order depends on the active ``storage_mode``:

        * ``secrets``: read each PEM and the metadata-secret. Returns
          ``None`` if no PEM secret is found.
        * ``certificate``: export the PFX from the Certificate's companion
          Secret (Azure mirrors the Certificate object's tags onto that
          Secret, which is also the only surface that exposes the private
          key) and split it back into the four PEM files; metadata is
          rehydrated from those mirrored tags.
        * ``both``: prefer the Secrets path (cheaper, one round-trip per
          file, no PFX parse). When the PEMs are present but the
          metadata-secret is missing — manual deletion, legacy state from
          before metadata was stored, etc. — fall back to the Certificate
          object's tags (read directly from the Certificate API to avoid
          relying on companion-Secret mirroring for this defensive path)
          so callers don't lose ``dns_provider`` / ``staging`` /
          ``san_domains``. If no Secret is found at all, fall through to
          the Certificate-object export so a partial Secrets state cannot
          mask an existing Certificate object.
        """
        try:
            # Prefer the secrets path whenever it is active — it is one
            # round-trip per file with no PFX parsing.
            if self.writes_secrets:
                result = self._retrieve_from_secrets(domain)
                if result is not None:
                    cert_files, metadata = result
                    # The metadata-secret can be missing (manual deletion,
                    # never-stored legacy state, …) even when the PEM secrets
                    # are intact. In 'both' mode we can recover the semantic
                    # metadata (dns_provider, staging, san_domains, …) from
                    # the Certificate object's tags rather than returning an
                    # empty dict to the caller.
                    if not metadata and self.writes_certificate:
                        metadata = self._get_cert_importer().get_metadata_tags(domain)
                    return cert_files, metadata
                if self.storage_mode == AZURE_KV_MODE_SECRETS:
                    return None
                # In 'both' mode fall through to certificate-object retrieval
                # so that a partial Secrets state does not mask an existing
                # Certificate object.

            if self.writes_certificate:
                return self._get_cert_importer().export_certificate(domain)
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Azure Key Vault for {domain}: {e}")
            return None

    # Anchored at end of name so we match the metadata secret regardless of
    # the 8-char CRC32 suffix that `_sanitize_secret_name` always appends.
    # The previous filter (``endswith('-metadata')``) silently matched zero
    # secrets in production because every real secret ends in ``-<crc>``.
    _METADATA_SECRET_RE = re.compile(r'^cert-.+-metadata-[0-9a-f]{8}$')

    def _list_secret_domains(self) -> List[str]:
        client = self._get_client()
        domains = set()
        for secret_properties in client.list_properties_of_secrets():
            if not self._METADATA_SECRET_RE.match(secret_properties.name):
                continue
            try:
                secret = client.get_secret(secret_properties.name)
                meta = json.loads(secret.value)
                domain = meta.get('domain')
                if domain:
                    domains.add(domain)
            except Exception as inner_e:
                logger.warning(f"Could not read metadata secret {secret_properties.name}: {inner_e}")
        return sorted(domains)

    @_with_retry()
    def list_certificates(self) -> List[str]:
        """List all certificate domains in Azure Key Vault."""
        try:
            domains: set = set()
            if self.writes_secrets:
                domains.update(self._list_secret_domains())
            if self.writes_certificate:
                domains.update(self._get_cert_importer().list_domains())
            return sorted(domains)
        except Exception as e:
            logger.error(f"Failed to list certificates from Azure Key Vault: {e}")
            return []

    def _delete_secrets(self, domain: str) -> bool:
        client = self._get_client()
        ok = True
        for filename in CERTIFICATE_FILES:
            secret_name = self._sanitize_secret_name(f"cert-{domain}-{filename.replace('.', '-')}")
            try:
                client.begin_delete_secret(secret_name)
            except Exception as e:
                logger.debug(f"Could not delete secret {secret_name} for {domain}: {e}")
                ok = False
        try:
            metadata_name = self._sanitize_secret_name(f"cert-{domain}-metadata")
            client.begin_delete_secret(metadata_name)
        except Exception as e:
            logger.debug(f"Could not delete metadata for {domain} from Azure Key Vault: {e}")
        return ok

    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from Azure Key Vault across active modes."""
        try:
            if self.writes_secrets:
                self._delete_secrets(domain)
            if self.writes_certificate:
                self._get_cert_importer().delete(domain)
            logger.info(f"Certificate deleted from Azure Key Vault for {domain} (mode={self.storage_mode})")
            return True
        except Exception as e:
            logger.error(f"Failed to delete certificate from Azure Key Vault for {domain}: {e}")
            return False

    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in Azure Key Vault (in any active mode)."""
        if self.writes_secrets:
            try:
                client = self._get_client()
                secret_name = self._sanitize_secret_name(f"cert-{domain}-cert-pem")
                client.get_secret(secret_name)
                return True
            except Exception:
                pass
        if self.writes_certificate:
            try:
                return self._get_cert_importer().exists(domain)
            except Exception:
                return False
        return False

    def get_backend_name(self) -> str:
        return "azure_keyvault"

    # Public hooks used by the backfill endpoint to drive the helper without
    # exposing the importer to the rest of the codebase.
    def has_certificate_object(self, domain: str) -> bool:
        return self._get_cert_importer().exists(domain)

    def import_certificate_object(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        return self._get_cert_importer().import_certificate(domain, cert_files, metadata)

    def verify_certificate_api_access(self) -> None:
        """Probe Certificate API access (used by the storage test endpoint)."""
        self._get_cert_importer().verify_api_access()


class AWSSecretsManagerBackend(CertificateStorageBackend):
    """AWS Secrets Manager storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.region = config.get('region', 'us-east-1')
        self.access_key_id = config.get('access_key_id')
        self.secret_access_key = config.get('secret_access_key')
        
        self.region = (self.region or 'us-east-1').strip()
        self.access_key_id = (self.access_key_id or '').strip()
        self.secret_access_key = (self.secret_access_key or '').strip()
        if not all([self.access_key_id, self.secret_access_key]):
            raise ValueError("AWS Secrets Manager backend requires access_key_id and secret_access_key")
        
        self._client = None
        logger.info(f"AWSSecretsManagerBackend initialized for region: {self.region}")
    
    def _get_client(self):
        """Get AWS Secrets Manager client with lazy initialization"""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    'secretsmanager',
                    region_name=self.region,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key
                )
            except ImportError:
                raise ImportError("AWS Secrets Manager backend requires 'boto3' package")
        return self._client
    
    @_with_retry()
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to AWS Secrets Manager"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Combine all certificate data into a single secret
            secret_data = {
                'files': {k: v.decode('utf-8', errors='replace') for k, v in cert_files.items()},
                'metadata': metadata
            }
            
            secret_name = f"certmate/certificates/{domain}"
            
            try:
                # Try to update existing secret
                client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_data)
                )
            except client.exceptions.ResourceNotFoundException:
                # Create new secret
                client.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_data),
                    Description=f"SSL certificate for {domain} managed by CertMate"
                )
            
            logger.info(f"Certificate stored successfully in AWS Secrets Manager for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in AWS Secrets Manager for {domain}: {e}")
            return False
    
    @_with_retry()
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"certmate/certificates/{domain}"
            
            response = client.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response['SecretString'])
            
            cert_files = {k: v.encode('utf-8') for k, v in secret_data.get('files', {}).items()}
            metadata = secret_data.get('metadata', {})
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from AWS Secrets Manager for {domain}: {e}")
            return None
    
    @_with_retry()
    def list_certificates(self) -> List[str]:
        """List all certificate domains in AWS Secrets Manager"""
        try:
            client = self._get_client()
            domains = []
            
            paginator = client.get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    name = secret['Name']
                    if name.startswith('certmate/certificates/'):
                        domain = name.replace('certmate/certificates/', '')
                        domains.append(domain)
            
            return sorted(domains)
            
        except Exception as e:
            logger.error(f"Failed to list certificates from AWS Secrets Manager: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"certmate/certificates/{domain}"
            
            client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            
            logger.info(f"Certificate deleted from AWS Secrets Manager for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from AWS Secrets Manager for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"certmate/certificates/{domain}"
            client.describe_secret(SecretId=secret_name)
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "aws_secrets_manager"


class HashiCorpVaultBackend(CertificateStorageBackend):
    """HashiCorp Vault storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.vault_url = config.get('vault_url')
        self.vault_token = config.get('vault_token')
        self.mount_point = config.get('mount_point', 'secret')
        self.engine_version = config.get('engine_version', 'v2')
        
        self.vault_url = (self.vault_url or '').strip()
        self.vault_token = (self.vault_token or '').strip()
        if not all([self.vault_url, self.vault_token]):
            raise ValueError("HashiCorp Vault backend requires vault_url and vault_token")
        
        self._client = None
        self._token_renewed_at = 0
        logger.info(f"HashiCorpVaultBackend initialized for vault: {self.vault_url}")

    def _get_client(self):
        """Get HashiCorp Vault client with lazy initialization and token renewal."""
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(url=self.vault_url, token=self.vault_token)
                if not self._client.is_authenticated():
                    raise ValueError("Failed to authenticate with HashiCorp Vault")
                self._token_renewed_at = time.time()
            except ImportError:
                raise ImportError("HashiCorp Vault backend requires 'hvac' package")
        else:
            # Renew token every 6 hours to prevent expiry
            if time.time() - getattr(self, '_token_renewed_at', 0) > 6 * 3600:
                try:
                    self._client.auth.token.renew_self()
                    self._token_renewed_at = time.time()
                    logger.info("HashiCorp Vault token renewed successfully")
                except Exception as e:
                    logger.warning(f"Vault token renewal failed, re-authenticating: {e}")
                    self._client = None
                    return self._get_client()
        return self._client
    
    @_with_retry()
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to HashiCorp Vault"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Prepare secret data
            secret_data = {
                'files': {k: v.decode('utf-8', errors='replace') for k, v in cert_files.items()},
                'metadata': metadata
            }
            
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                client.secrets.kv.v2.create_or_update_secret(
                    path=secret_path,
                    secret=secret_data,
                    mount_point=self.mount_point
                )
            else:
                client.secrets.kv.v1.create_or_update_secret(
                    path=secret_path,
                    secret=secret_data,
                    mount_point=self.mount_point
                )
            
            logger.info(f"Certificate stored successfully in HashiCorp Vault for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in HashiCorp Vault for {domain}: {e}")
            return False
    
    @_with_retry()
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from HashiCorp Vault"""
        try:
            client = self._get_client()
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                response = client.secrets.kv.v2.read_secret_version(
                    path=secret_path,
                    mount_point=self.mount_point
                )
                secret_data = response['data']['data']
            else:
                response = client.secrets.kv.v1.read_secret(
                    path=secret_path,
                    mount_point=self.mount_point
                )
                secret_data = response['data']
            
            cert_files = {k: v.encode('utf-8') for k, v in secret_data.get('files', {}).items()}
            metadata = secret_data.get('metadata', {})
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from HashiCorp Vault for {domain}: {e}")
            return None
    
    @_with_retry()
    def list_certificates(self) -> List[str]:
        """List all certificate domains in HashiCorp Vault"""
        try:
            client = self._get_client()
            
            if self.engine_version == 'v2':
                response = client.secrets.kv.v2.list_secrets(
                    path="certmate/certificates",
                    mount_point=self.mount_point
                )
            else:
                response = client.secrets.kv.v1.list_secrets(
                    path="certmate/certificates",
                    mount_point=self.mount_point
                )
            
            return sorted(response.get('data', {}).get('keys', []))
            
        except Exception as e:
            logger.error(f"Failed to list certificates from HashiCorp Vault: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from HashiCorp Vault"""
        try:
            client = self._get_client()
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            else:
                client.secrets.kv.v1.delete_secret(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            
            logger.info(f"Certificate deleted from HashiCorp Vault for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from HashiCorp Vault for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in HashiCorp Vault"""
        try:
            client = self._get_client()
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                client.secrets.kv.v2.read_secret_version(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            else:
                client.secrets.kv.v1.read_secret(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "hashicorp_vault"


class InfisicalBackend(CertificateStorageBackend):
    """Infisical storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.site_url = config.get('site_url', 'https://app.infisical.com')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.project_id = config.get('project_id')
        self.environment = config.get('environment', 'prod')
        
        self.client_id = (self.client_id or '').strip()
        self.client_secret = (self.client_secret or '').strip()
        self.project_id = (self.project_id or '').strip()
        if not all([self.client_id, self.client_secret, self.project_id]):
            raise ValueError("Infisical backend requires client_id, client_secret, and project_id")
        
        self._client = None
        logger.info(f"InfisicalBackend initialized for project: {self.project_id}")
    
    def _get_client(self):
        """Get Infisical client with lazy initialization"""
        if self._client is None:
            try:
                from infisical import InfisicalClient, ClientSettings
                
                settings = ClientSettings(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    site_url=self.site_url
                )
                self._client = InfisicalClient(settings)
            except ImportError:
                raise ImportError("Infisical backend requires 'infisical-python' package")
        return self._client
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to Infisical"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Store certificate files as individual secrets (upsert: update if exists, create otherwise)
            for filename, content in cert_files.items():
                secret_key = f"certmate-{domain}-{filename.replace('.', '-')}"
                secret_value = content.decode('utf-8', errors='replace')
                try:
                    client.update_secret(
                        secret_name=secret_key,
                        secret_value=secret_value,
                        project_id=self.project_id,
                        environment=self.environment
                    )
                except Exception:
                    client.create_secret(
                        secret_name=secret_key,
                        secret_value=secret_value,
                        project_id=self.project_id,
                        environment=self.environment
                    )

            # Store metadata (upsert)
            metadata_key = f"certmate-{domain}-metadata"
            metadata_value = json.dumps(metadata)
            try:
                client.update_secret(
                    secret_name=metadata_key,
                    secret_value=metadata_value,
                    project_id=self.project_id,
                    environment=self.environment
                )
            except Exception:
                client.create_secret(
                    secret_name=metadata_key,
                    secret_value=metadata_value,
                    project_id=self.project_id,
                    environment=self.environment
                )
            
            logger.info(f"Certificate stored successfully in Infisical for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in Infisical for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from Infisical"""
        try:
            client = self._get_client()
            
            cert_files = {}
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                try:
                    secret_key = f"certmate-{domain}-{filename.replace('.', '-')}"
                    secret = client.get_secret(
                        secret_name=secret_key,
                        project_id=self.project_id,
                        environment=self.environment
                    )
                    cert_files[filename] = secret.secret_value.encode('utf-8')
                except Exception as e:
                    logger.debug(f"Secret {secret_key} not found for {domain}: {e}")
                    continue

            if not cert_files:
                return None

            # Load metadata
            metadata = {}
            try:
                metadata_key = f"certmate-{domain}-metadata"
                secret = client.get_secret(
                    secret_name=metadata_key,
                    project_id=self.project_id,
                    environment=self.environment
                )
                metadata = json.loads(secret.secret_value)
            except Exception as e:
                logger.debug(f"Metadata not found in Infisical for {domain}: {e}")
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Infisical for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in Infisical"""
        try:
            client = self._get_client()
            domains = set()
            
            secrets = client.list_secrets(
                project_id=self.project_id,
                environment=self.environment
            )
            
            for secret in secrets:
                if not (secret.secret_name.startswith('certmate-') and secret.secret_name.endswith('-metadata')):
                    continue
                # Read each metadata secret to get the authoritative domain name instead
                # of reversing the sanitized key (which is lossy for hyphenated domains).
                try:
                    meta_secret = client.get_secret(
                        secret_name=secret.secret_name,
                        project_id=self.project_id,
                        environment=self.environment
                    )
                    meta = json.loads(meta_secret.secret_value)
                    domain = meta.get('domain')
                    if domain:
                        domains.add(domain)
                except Exception as inner_e:
                    logger.warning(f"Could not read metadata secret {secret.secret_name}: {inner_e}")
            
            return sorted(list(domains))
            
        except Exception as e:
            logger.error(f"Failed to list certificates from Infisical: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from Infisical"""
        try:
            client = self._get_client()
            
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                try:
                    secret_key = f"certmate-{domain}-{filename.replace('.', '-')}"
                    client.delete_secret(
                        secret_name=secret_key,
                        project_id=self.project_id,
                        environment=self.environment
                    )
                except Exception as e:
                    logger.debug(f"Could not delete secret {secret_key} for {domain}: {e}")
                    continue

            # Delete metadata
            try:
                metadata_key = f"certmate-{domain}-metadata"
                client.delete_secret(
                    secret_name=metadata_key,
                    project_id=self.project_id,
                    environment=self.environment
                )
            except Exception as e:
                logger.debug(f"Could not delete metadata for {domain} from Infisical: {e}")
            
            logger.info(f"Certificate deleted from Infisical for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from Infisical for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in Infisical"""
        try:
            client = self._get_client()
            secret_key = f"certmate-{domain}-cert-pem"
            client.get_secret(
                secret_name=secret_key,
                project_id=self.project_id,
                environment=self.environment
            )
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "infisical"


class StorageManager:
    """Manager class for certificate storage backends"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        self._backend = None
        self._initialized = False
    
    def _initialize_backend(self):
        """Initialize storage backend based on settings"""
        if self._initialized:
            return
        
        try:
            settings = self.settings_manager.load_settings()
            storage_config = settings.get('certificate_storage', {})
            backend_type = storage_config.get('backend', 'local_filesystem')
            
            if backend_type == 'local_filesystem':
                # Default local filesystem backend
                cert_dir = Path(storage_config.get('cert_dir', 'certificates'))
                self._backend = LocalFileSystemBackend(cert_dir)
                
            elif backend_type == 'azure_keyvault':
                config = storage_config.get('azure_keyvault', {})
                self._backend = AzureKeyVaultBackend(config)
                
            elif backend_type == 'aws_secrets_manager':
                config = storage_config.get('aws_secrets_manager', {})
                self._backend = AWSSecretsManagerBackend(config)
                
            elif backend_type == 'hashicorp_vault':
                config = storage_config.get('hashicorp_vault', {})
                self._backend = HashiCorpVaultBackend(config)
                
            elif backend_type == 'infisical':
                config = storage_config.get('infisical', {})
                self._backend = InfisicalBackend(config)
                
            else:
                logger.warning(f"Unknown storage backend: {backend_type}, falling back to local filesystem")
                cert_dir = Path('certificates')
                self._backend = LocalFileSystemBackend(cert_dir)
            
            self._initialized = True
            logger.info(f"Storage backend initialized: {self._backend.get_backend_name()}")
            
        except Exception as e:
            logger.error(
                "Failed to initialize storage backend '%s': %s. "
                "FALLING BACK to local filesystem — cloud/remote storage is NOT active. "
                "Fix the configuration and restart to activate the intended backend.",
                backend_type, e
            )
            self._backend = LocalFileSystemBackend(Path('certificates'))
            self._initialized = True
    
    def get_backend(self) -> CertificateStorageBackend:
        """Get the current storage backend"""
        self._initialize_backend()
        return self._backend
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate using the configured backend"""
        backend = self.get_backend()
        return backend.store_certificate(domain, cert_files, metadata)
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate using the configured backend"""
        backend = self.get_backend()
        return backend.retrieve_certificate(domain)
    
    def list_certificates(self) -> List[str]:
        """List certificates using the configured backend"""
        backend = self.get_backend()
        return backend.list_certificates()
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate using the configured backend"""
        backend = self.get_backend()
        return backend.delete_certificate(domain)
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists using the configured backend"""
        backend = self.get_backend()
        return backend.certificate_exists(domain)
    
    def get_backend_name(self) -> str:
        """Get the name of the current storage backend"""
        backend = self.get_backend()
        return backend.get_backend_name()
    
    def migrate_certificates(self, source_backend: CertificateStorageBackend, target_backend: CertificateStorageBackend) -> Dict[str, bool]:
        """Migrate certificates from one backend to another"""
        migration_results = {}
        
        try:
            domains = source_backend.list_certificates()
            logger.info(f"Starting migration of {len(domains)} certificates from {source_backend.get_backend_name()} to {target_backend.get_backend_name()}")
            
            for domain in domains:
                try:
                    # Retrieve from source
                    cert_data = source_backend.retrieve_certificate(domain)
                    if cert_data:
                        cert_files, metadata = cert_data
                        # Store in target
                        success = target_backend.store_certificate(domain, cert_files, metadata)
                        migration_results[domain] = success
                        if success:
                            logger.info(f"Successfully migrated certificate for {domain}")
                        else:
                            logger.error(f"Failed to migrate certificate for {domain}")
                    else:
                        migration_results[domain] = False
                        logger.error(f"Failed to retrieve certificate for {domain} from source backend")
                except Exception as e:
                    migration_results[domain] = False
                    logger.error(f"Error migrating certificate for {domain}: {e}")
            
            successful = sum(1 for success in migration_results.values() if success)
            logger.info(f"Migration completed: {successful}/{len(domains)} certificates migrated successfully")
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
        
        return migration_results
