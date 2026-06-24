"""Ed25519 signing for the audit hash chain (Phase 3 of l0 #408).

Signed checkpoints and a signed export bundle let a third party verify, off the
box, that an exported audit chain was produced by THIS instance and was not
edited. The private key is persisted under the data tree
(``data/.audit_signing_key``), like the Flask secret key, and never leaves the
instance unless an operator points ``AUDIT_SIGNING_KEY_FILE`` at an off-box
location.

Honest threat model: a local signing key detects tampering by anyone WITHOUT the
key and ties an export to this instance's public key — but it does NOT bind the
operator, who holds the key and could re-sign a rewritten chain. Constraining the
operator needs external anchoring of signed checkpoints (a planned follow-up, not
implemented here).

Signing is best-effort: if the key cannot be loaded or generated, signing is
disabled and the unsigned hash chain (Phase 2) still works.
"""

import os
import base64
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SIGNING_KEY_FILENAME = '.audit_signing_key'
KEY_FILE_ENV = 'AUDIT_SIGNING_KEY_FILE'
ALGORITHM = 'ed25519'


class AuditSigner:
    """Holds the instance Ed25519 key and signs bytes."""

    def __init__(self, data_dir, key_file_env: str = KEY_FILE_ENV):
        self._private = None
        self._public = None
        try:
            self._private = self._load_or_create(Path(data_dir), key_file_env)
            if self._private is not None:
                self._public = self._private.public_key()
        except Exception as e:  # pragma: no cover - defensive
            logger.error(f"Audit signing disabled (key init failed): {e}")
            self._private = None
            self._public = None

    @property
    def available(self) -> bool:
        return self._private is not None

    def _load_or_create(self, data_dir: Path, env: str):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        def _read(p: Path):
            return serialization.load_pem_private_key(p.read_bytes(), password=None)

        # 1. Explicit off-box key file. If set but unreadable, do NOT silently
        #    generate (that would fork the instance identity) — disable signing.
        explicit = os.getenv(env)
        if explicit:
            try:
                return _read(Path(explicit))
            except Exception as e:
                logger.error(f"Could not read {env} ({explicit}): {e}; audit signing disabled.")
                return None

        # 2. Persisted instance key. If it exists but is corrupt, disable rather
        #    than regenerate: regenerating breaks verification of prior checkpoints
        #    and could mask tampering. The operator must restore or rotate it.
        path = data_dir / SIGNING_KEY_FILENAME
        if path.exists():
            try:
                return _read(path)
            except Exception as e:
                logger.error(
                    f"Existing audit signing key {path} is unreadable: {e}; audit "
                    f"signing disabled. Restore it, or remove it to mint a new identity.")
                return None

        # 3. First run: generate and persist with 0600 from the first byte.
        key = Ed25519PrivateKey.generate()
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as fh:
                fh.write(pem)
            try:
                path.chmod(0o600)
            except OSError:
                pass
        except OSError as e:
            logger.warning(
                f"Could not persist audit signing key to {path}: {e}. Signing is "
                f"in-memory only; the instance identity will change on restart.")
        return key

    def sign(self, data: bytes) -> Optional[str]:
        """Return a base64 Ed25519 signature over *data*, or None if unavailable."""
        if self._private is None:
            return None
        return base64.b64encode(self._private.sign(data)).decode('ascii')

    def public_key_pem(self) -> Optional[str]:
        if self._public is None:
            return None
        from cryptography.hazmat.primitives import serialization
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')

    def fingerprint(self) -> Optional[str]:
        """Short, stable instance identity: base64(sha256(raw pubkey))[:16]."""
        pem = self.public_key_pem()
        return fingerprint_from_pem(pem) if pem else None


def verify_signature(public_key_pem: str, signature_b64: str, data: bytes) -> bool:
    """Verify a base64 Ed25519 signature against *data* using a PEM public key.
    Used by the standalone verifier; needs only the public key + cryptography."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        pub = serialization.load_pem_public_key(public_key_pem.encode('ascii'))
        try:
            pub.verify(base64.b64decode(signature_b64), data)
            return True
        except InvalidSignature:
            return False
    except Exception:
        return False


def fingerprint_from_pem(public_key_pem: str) -> Optional[str]:
    """Compute the instance fingerprint from a PEM public key (for out-of-band
    pinning by an auditor)."""
    try:
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(public_key_pem.encode('ascii'))
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(hashlib.sha256(raw).digest()).decode('ascii')[:16]
    except Exception:
        return None
