"""
File operations module for CertMate
Handles file I/O, backup management, and safe file operations
"""

import base64
import io
import os
import re
import json
import tempfile
import zipfile
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
import fcntl
import logging

from .utils import utc_now, utc_now_iso, repair_certbot_lineage_symlinks

logger = logging.getLogger(__name__)

# Backup constants
BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
MAX_BACKUPS_PER_TYPE = 50   # Maximum number of backups to keep per type

# Top-level subdirectories under certificates/<domain>/ that certbot fills
# with ephemeral scratch and verbose logs. certbot's accounts/ and archive/
# directories are intentionally retained because renew_certificate() reuses
# the domain config dir for future renewals after a restore.
_BACKUP_EXCLUDE_DIRS = frozenset({'logs', 'work'})

# Private-key material that certbot/CertMate writes into the cert tree. On
# restore every one of these must get 0600 — not just the live `privkey.pem`.
# certbot keeps the real key bytes in archive/<domain>/privkeyN.pem (the
# live/privkey.pem symlink points at them) and the ACME account key in
# accounts/.../private_key.json; both are retained in the unified backup
# (accounts/ and archive/ are intentionally kept — see _BACKUP_EXCLUDE_DIRS).
# Matching only the exact name 'privkey.pem' left those world-readable (0644).
# Public material (cert/chain/fullchain + *.json metadata) stays 0644 so
# external consumers can still read it, mirroring certbot's own permissions.
_PRIVATE_KEY_FILE_RE = re.compile(
    r'(?:^|[._-])privkey\d*\.pem$|^private_key\.json$|\.key$',
    re.IGNORECASE,
)

# Subtrees of data_dir that a unified backup carries under the "data/" arc
# prefix. Without these the archive holds no PKI state at all: the private
# CA signing key, every client certificate, the CRL and the audit chain all
# live here, so a "restore" left an operator unable to issue, renew or
# revoke a single client cert (#409).
#
# This is also the RESTORE allowlist, and it deliberately excludes
# settings.json: settings are restored from the archive's own settings.json
# entry, which passes the deploy-hook revalidation gate. Honouring a
# "data/settings.json" member would let a tampered archive write settings
# straight to disk around that gate.
_BACKUP_DATA_SUBTREES = ('certs', 'audit')

# Per-entry ceiling when restoring the data/ subtrees. Deliberately far above
# the 10 MB used for PEM files: certificate_audit.log is append-only and grows
# with every operation, and an audit chain restored with a hole in it is
# unverifiable. Entries are streamed in chunks, so this is a bound on disk
# use, not on memory.
_MAX_DATA_ENTRY_BYTES = 512 * 1024 * 1024

# --- Backup encryption at rest --------------------------------------------
# Unified backups embed every certificate private key (privkey.pem). With
# CERTMATE_BACKUP_PASSPHRASE set, the whole zip is encrypted (Fernet:
# AES-128-CBC + HMAC-SHA256) with a key derived from the passphrase via
# PBKDF2-SHA256. The passphrase deliberately comes from the environment and
# NOT from settings.json — a passphrase stored in settings would itself be
# included in plaintext-mode backups, defeating the purpose.
#
# File layout of a `.zip.enc` backup (three newline-separated sections):
#   CERTMATE-BACKUP-ENC v1
#   {"kdf": ..., "iterations": ..., "salt": ..., "metadata": {...}}
#   <fernet token>
# The cleartext header carries only the non-secret backup metadata (id,
# timestamp, domain names) so list_backups() stays cheap — no KDF run per
# file per listing.
BACKUP_PASSPHRASE_ENV = 'CERTMATE_BACKUP_PASSPHRASE'
_BACKUP_ENC_MAGIC = b'CERTMATE-BACKUP-ENC v1'
_BACKUP_ENC_SUFFIX = '.zip.enc'
_BACKUP_ENC_KDF_ITERATIONS = 600_000  # OWASP 2023 floor for PBKDF2-SHA256


def _backup_passphrase():
    return os.environ.get(BACKUP_PASSPHRASE_ENV, '')


def _derive_backup_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))


def _encrypt_backup_payload(zip_bytes: bytes, passphrase: str, metadata: dict) -> bytes:
    from cryptography.fernet import Fernet
    import secrets as _secrets

    salt = _secrets.token_bytes(16)
    key = _derive_backup_key(passphrase, salt, _BACKUP_ENC_KDF_ITERATIONS)
    header = {
        'kdf': 'pbkdf2-sha256',
        'iterations': _BACKUP_ENC_KDF_ITERATIONS,
        'salt': base64.b64encode(salt).decode('ascii'),
        'metadata': metadata,
    }
    return b'\n'.join([
        _BACKUP_ENC_MAGIC,
        json.dumps(header, separators=(',', ':')).encode('utf-8'),
        Fernet(key).encrypt(zip_bytes),
    ])


def _parse_encrypted_backup(raw: bytes):
    """Split an encrypted backup file into (header_dict, fernet_token).
    Raises ValueError on any format problem."""
    magic, _, rest = raw.partition(b'\n')
    if magic != _BACKUP_ENC_MAGIC:
        raise ValueError('not a CertMate encrypted backup')
    header_line, _, token = rest.partition(b'\n')
    header = json.loads(header_line.decode('utf-8'))
    if not token:
        raise ValueError('encrypted backup is truncated')
    return header, token


def _decrypt_backup_payload(raw: bytes, passphrase: str) -> bytes:
    """Decrypt an encrypted backup file body back to zip bytes.
    Raises ValueError on bad format or wrong passphrase."""
    from cryptography.fernet import Fernet, InvalidToken

    header, token = _parse_encrypted_backup(raw)
    salt = base64.b64decode(header['salt'])
    iterations = int(header.get('iterations', _BACKUP_ENC_KDF_ITERATIONS))
    key = _derive_backup_key(passphrase, salt, iterations)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError('wrong passphrase or corrupted backup')


class FileOperations:
    """Class to handle file operations and backup management"""
    
    def __init__(self, cert_dir, data_dir, backup_dir, logs_dir):
        self.cert_dir = Path(cert_dir)
        self.data_dir = Path(data_dir)
        self.backup_dir = Path(backup_dir)
        self.logs_dir = Path(logs_dir)
        self.allowed_dirs = [
            self.cert_dir.resolve(),
            self.data_dir.resolve(),
            self.backup_dir.resolve(),
            self.logs_dir.resolve()
        ]

    def safe_file_read(self, file_path, is_json=False, default=None):
        """Safely read a file with proper error handling and file locking"""
        try:
            # Validate file path to prevent path traversal
            file_path = Path(file_path).resolve()
            
            # Ensure the file is within allowed directories
            if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in self.allowed_dirs):
                logger.error(f"Access denied: file outside allowed directories: {file_path}")
                return default
            
            if not file_path.exists():
                return default
                
            with open(file_path, 'r', encoding='utf-8') as f:
                # Use file locking for safety
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    content = f.read()
                    if is_json:
                        return json.loads(content) if content.strip() else default
                    return content
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return default
        except Exception as e:
            logger.error(f"Unexpected error reading file {file_path}: {e}")
            return default

    def safe_file_write(self, file_path, data, is_json=True):
        """Safely write data to a file with proper error handling and atomic operations"""
        # Initialise the cleanup target before any code that could raise. If
        # mkstemp() (below) fails — disk full, parent dir unwritable, sandbox
        # restriction — control jumps straight to one of the except blocks
        # where `temp_file.exists()` would otherwise raise UnboundLocalError
        # and mask the original OSError from the operator log.
        temp_file = None
        try:
            # Validate file path to prevent path traversal
            file_path = Path(file_path).resolve()
            
            # Ensure the file is within allowed directories
            if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in self.allowed_dirs):
                logger.error(f"Access denied: file outside allowed directories: {file_path}")
                return False
            
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temporary file for atomic writes with restrictive permissions
            import tempfile as _tmpmod
            _tmp_fd, _tmp_name = _tmpmod.mkstemp(dir=str(file_path.parent), suffix='.tmp')
            os.close(_tmp_fd)
            temp_file = Path(_tmp_name)
            fd = os.open(str(temp_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                # Use file locking for safety
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    if is_json:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(str(data))
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomic move
            temp_file.rename(file_path)
            
            # Set proper permissions
            os.chmod(file_path, 0o600)
            
            return True
            
        except (PermissionError, OSError) as e:
            logger.error(f"Error writing file {file_path}: {e}")
            # Clean up temp file if it was created before the failure.
            if temp_file is not None and temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error writing file {file_path}: {e}")
            if temp_file is not None and temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False

    def _mask_settings_secrets(self, settings_dict):
        """Delegate to the central ``mask_secrets_in_settings`` helper in
        ``modules/core/settings``. Kept as an instance method for
        backwards compatibility (older callers / tests that already
        monkey-patched this name).

        The central helper also picks up provider-specific secret
        fields (acme-dns ``username`` + ``subdomain``) that a name-only
        regex would have missed. See its docstring for the precise
        contract.
        """
        from .settings import mask_secrets_in_settings
        return mask_secrets_in_settings(settings_dict)

    def create_unified_backup(self, settings_data, backup_reason="manual", include_secrets=False):
        """Create a unified backup containing both settings and certificates.

        ``include_secrets`` controls whether secret-bearing fields in
        ``settings_data`` (DNS provider tokens, storage backend
        credentials, ``api_bearer_token``, ``smtp_password``, OIDC
        ``client_secret``, user password hashes, …) appear in plaintext
        in the resulting zip. Default ``False`` writes the canonical
        mask sentinel in place of every secret, so a leaked backup file
        does NOT also leak every CertMate credential. The opt-in
        ``include_secrets=True`` path produces a plaintext backup for
        full disaster-recovery use; callers MUST audit-log the opt-in
        because the resulting file on disk is now a credential dump
        that survives outside the API role gate.

        Output file is always chmod 0600 — only the certmate process
        user can read it — so backup-dir-readable threats (rsync,
        accidental Docker image bake, ops bastion) at least see
        an `EPERM` first.
        """
        try:
            timestamp = utc_now().strftime("%Y%m%d_%H%M%S_%f")
            backup_id = f"backup_{timestamp}_{backup_reason}"
            passphrase = _backup_passphrase()
            backup_filename = f"{backup_id}{_BACKUP_ENC_SUFFIX if passphrase else '.zip'}"
            backup_path = self.backup_dir / "unified" / backup_filename

            # Ensure backup directory exists
            backup_path.parent.mkdir(parents=True, exist_ok=True)

            # Single iterdir pass: collect the Path objects once so we don't
            # walk cert_dir twice (once for the domain-name list embedded in
            # the metadata, then again to copy files into the zip). Saves
            # N stat() calls per backup — minor on local SSD, noticeable on
            # NFS / spinning disk.
            domain_dirs = []
            if self.cert_dir.exists():
                for domain_dir in self.cert_dir.iterdir():
                    if domain_dir.is_dir():
                        domain_dirs.append(domain_dir)
            domains = [d.name for d in domain_dirs]

            # PKI + audit state that lives outside cert_dir (#409). Collected
            # here, before the metadata dict is built, so the count is
            # identical in settings.json and backup_metadata.json.
            data_files = []
            for subtree in _BACKUP_DATA_SUBTREES:
                subtree_dir = self.data_dir / subtree
                if not subtree_dir.is_dir():
                    continue
                data_files.extend(f for f in subtree_dir.rglob("*") if f.is_file())

            settings_to_write = settings_data if include_secrets else self._mask_settings_secrets(settings_data)

            metadata = {
                "backup_id": backup_id,
                "timestamp": utc_now_iso(),
                "backup_reason": backup_reason,
                "version": "2.2.0",  # New unified format
                "type": "unified",
                "domains": domains,
                "settings_domains": [d.get('domain') if isinstance(d, dict) else d for d in settings_data.get('domains', [])],
                "total_domains": len(domains),
                # Count of PKI/audit files carried under the "data/" prefix
                # (private CA, client certs, CRL, audit chain) — #409.
                "data_files": len(data_files),
                # Pin the secret-handling mode on the backup itself so an
                # operator inspecting an old archive can see whether it's
                # a share-safe (masked) snapshot or a full-restore one.
                "secrets_masked": not include_secrets,
                "encrypted": bool(passphrase),
            }

            # Create the ZIP in memory (backups are settings + a handful of
            # PEM files — small) so the encrypted path never spills a
            # plaintext zip to disk, not even transiently.
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add settings data
                settings_backup = {
                    "metadata": metadata,
                    "settings": settings_to_write
                }
                zipf.writestr("settings.json", json.dumps(settings_backup, indent=2))

                # Reuse the domain_dirs list from above instead of doing a
                # second iterdir + is_dir() on the same cert_dir.
                for domain_dir in domain_dirs:
                    for cert_file in domain_dir.rglob("*"):
                        if not cert_file.is_file():
                            continue
                        # certbot runs with --config-dir/--work-dir/--logs-dir
                        # all under certificates/<domain>/, so each domain dir
                        # accumulates logs/ and work/. Those have no restore
                        # value and can dominate routine backups. Keep
                        # accounts/ and archive/: certbot renew needs lineage
                        # state after a backup restore.
                        rel_parts = cert_file.relative_to(domain_dir).parts
                        if rel_parts and rel_parts[0] in _BACKUP_EXCLUDE_DIRS:
                            continue
                        # Add file to zip with relative path under certificates/
                        arc_path = f"certificates/{cert_file.relative_to(self.cert_dir)}"
                        zipf.write(cert_file, arc_path)

                # PKI + audit state (#409). certificates/ only covers the
                # ACME server certs; the private CA key, the client certs it
                # signed, the CRL and the audit chain live under data_dir and
                # were previously absent from every backup — silently, since
                # total_domains still looked right.
                for data_file in data_files:
                    zipf.write(data_file, f"data/{data_file.relative_to(self.data_dir)}")

                # Add unified metadata
                zipf.writestr("backup_metadata.json", json.dumps(metadata, indent=2))

            payload = zip_buffer.getvalue()
            if passphrase:
                payload = _encrypt_backup_payload(payload, passphrase, metadata)

            # Write with 0600 from the first byte. Default umask leaves the
            # file world-readable on most distros; the contents include every
            # certificate private key. 0600 = certmate-user only.
            fd = os.open(str(backup_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as fh:
                fh.write(payload)
            try:
                os.chmod(backup_path, 0o600)
            except OSError as perm_err:
                logger.warning(f"Could not tighten permissions on {backup_path}: {perm_err}")

            mode_tag = 'plaintext' if include_secrets else 'masked'
            enc_tag = 'encrypted' if passphrase else 'cleartext'
            logger.info(f"Unified backup created: {backup_filename} (contains {len(domains)} domains; secrets={mode_tag}; at-rest={enc_tag})")
            self._prune_unified_backups()
            self._upload_backup_offsite(backup_path, backup_filename, settings_data,
                                        encrypted=bool(passphrase))
            return backup_filename

        except Exception as e:
            logger.error(f"Error creating unified backup: {e}")
            return None

    def _upload_backup_offsite(self, backup_path, backup_filename, settings_data,
                               encrypted=False):
        """Best-effort off-site copy of the unified backup to an S3-compatible
        target. NEVER raises: the local backup is authoritative; the S3 copy is
        a disaster-recovery convenience. Enabled via settings
        ``backup_storage`` = {'backend': 's3_compatible', 's3_compatible': {...}}.
        Works with any S3 endpoint (Hetzner, Contabo, OVHcloud, Scaleway, Wasabi,
        MinIO, AWS); boto3 is already a core dependency.

        ``encrypted`` MUST be True for the upload to proceed: the unified backup
        contains every domain's private key, and at-rest encryption is only
        applied when CERTMATE_BACKUP_PASSPHRASE is set. Off-site upload and
        encryption are independent settings, so refusing here is what prevents
        an operator who enabled S3 without a passphrase from silently
        exfiltrating cleartext private keys to third-party storage.
        """
        try:
            cfg = (settings_data or {}).get('backup_storage') or {}
            if cfg.get('backend') != 's3_compatible':
                return
            s3 = cfg.get('s3_compatible') or {}
            endpoint = (s3.get('endpoint_url') or '').strip()
            bucket = (s3.get('bucket') or '').strip()
            access_key = (s3.get('access_key_id') or '').strip()
            secret_key = (s3.get('secret_access_key') or '').strip()
            if not all([endpoint, bucket, access_key, secret_key]):
                return

            # Refuse to ship cleartext private keys off-box. This is the guard
            # that couples off-site upload to encryption (they are otherwise
            # unrelated settings). Fail-safe: default False, so a caller that
            # forgets to pass the flag never leaks.
            if not encrypted:
                logger.error(
                    "Off-site backup upload SKIPPED: the backup is NOT encrypted "
                    "(CERTMATE_BACKUP_PASSPHRASE is not set) and contains every "
                    "domain's private key. Refusing to upload cleartext keys to "
                    "external storage. Set CERTMATE_BACKUP_PASSPHRASE to enable "
                    "off-site backups."
                )
                return
            if not endpoint.lower().startswith('https://'):
                # The payload is encrypted at rest, so this is not a key-leak,
                # but plaintext transport is still worth flagging. Log the
                # scheme only — never the endpoint host/credentials.
                logger.warning(
                    "Off-site backup endpoint is not HTTPS (scheme=%s); prefer "
                    "an HTTPS endpoint for transport security.",
                    (endpoint.split('://', 1)[0] or 'unknown'),
                )
            prefix = (s3.get('prefix') or 'certmate/backups').strip().strip('/')
            region = (s3.get('region') or 'us-east-1').strip()

            import boto3
            client = boto3.client(
                's3', endpoint_url=endpoint, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key, region_name=region)
            with open(backup_path, 'rb') as fh:
                client.put_object(
                    Bucket=bucket, Key=f"{prefix}/{backup_filename}", Body=fh.read())
            logger.info("Backup %s copied off-site to s3://%s/%s/%s",
                        backup_filename, bucket, prefix, backup_filename)
        except Exception as e:
            # Log the type only — never the message/config — and keep the
            # local backup. Off-site is a convenience, not a hard dependency.
            logger.warning(
                "Off-site backup upload failed (local backup is intact): %s",
                type(e).__name__)

    def _prune_unified_backups(self):
        """Enforce backup retention: keep at most MAX_BACKUPS_PER_TYPE files,
        and delete files older than BACKUP_RETENTION_DAYS regardless of count."""
        try:
            backup_dir = self.backup_dir / "unified"
            if not backup_dir.exists():
                return
            # backup_*.zip* matches both cleartext (.zip) and encrypted
            # (.zip.enc) backups so retention applies across the mix.
            backups = sorted(
                backup_dir.glob("backup_*.zip*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            cutoff = utc_now() - timedelta(days=BACKUP_RETENTION_DAYS)
            removed = 0
            for idx, path in enumerate(backups):
                try:
                    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).replace(tzinfo=None)
                    if idx >= MAX_BACKUPS_PER_TYPE or mtime < cutoff:
                        path.unlink()
                        removed += 1
                except OSError as e:
                    logger.debug(f"Could not prune backup {path.name}: {e}")
            if removed:
                logger.info(f"Pruned {removed} old unified backup(s)")
        except Exception as e:
            logger.warning(f"Backup pruning failed: {e}")





    def list_backups(self):
        """List all available unified backups with metadata"""
        try:
            backups = {
                "unified": []
            }
            
            # List unified backups (only format)
            unified_backup_dir = self.backup_dir / "unified"
            if unified_backup_dir.exists():
                for backup_file in sorted(unified_backup_dir.glob("backup_*.zip*")):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}

                        # Try to read unified backup metadata
                        try:
                            if backup_file.name.endswith(_BACKUP_ENC_SUFFIX):
                                # Encrypted backup: metadata lives in the
                                # cleartext header, no passphrase needed.
                                header, _ = _parse_encrypted_backup(backup_file.read_bytes())
                                if isinstance(header.get('metadata'), dict):
                                    metadata.update(header['metadata'])
                                metadata["type"] = "unified"
                                metadata["encrypted"] = True
                            else:
                                with zipfile.ZipFile(backup_file, 'r') as zipf:
                                    if "backup_metadata.json" in zipf.namelist():
                                        metadata_content = zipf.read("backup_metadata.json")
                                        zip_metadata = json.loads(metadata_content.decode('utf-8'))
                                        metadata.update(zip_metadata)
                                        metadata["type"] = "unified"
                        except Exception as e:
                            logger.debug(f"Could not read ZIP metadata from {backup_file}: {e}")

                        backups["unified"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process unified backup {backup_file}: {e}")
            
            return backups
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return {"unified": []}

    @staticmethod
    def _revalidate_restored_deploy_hooks(settings_data):
        """Run the current ``DeployManager._validate_hook`` over every
        hook present in the restored ``settings_data``. Returns ``None``
        if every hook passes, or a human-readable error string naming
        the offending hook otherwise. A restore that would install
        even one rejectable hook is refused (audit finding M1)."""
        try:
            from .deployer import DeployManager
        except Exception as imp_err:
            logger.warning(f"Could not import DeployManager for restore validation: {imp_err}")
            return None

        hooks = []
        deploy_block = settings_data.get('deploy_hooks') or {}
        if isinstance(deploy_block, dict):
            global_hooks = deploy_block.get('global_hooks') or []
            if isinstance(global_hooks, list):
                hooks.extend(h for h in global_hooks if isinstance(h, dict))
        if not hooks:
            return None

        # Instantiate without a settings_manager argument — _validate_hook
        # only reads from the hook dict itself, so a bare instance works.
        try:
            dm = DeployManager.__new__(DeployManager)
        except Exception as ctor_err:
            logger.warning(f"Could not construct DeployManager for hook re-validation: {ctor_err}")
            return None

        for hook in hooks:
            try:
                ok, err = dm._validate_hook(hook)
            except Exception as ve:
                return f"hook validator raised {type(ve).__name__}: {ve}"
            if not ok:
                return err or "hook failed current validator"
        return None

    def restore_unified_backup(self, backup_file_path):
        """Restore from a unified backup file (both settings and certificates).

        Two safety gates run before the restored ``settings.json`` is
        written to disk:

        1. If the restored payload contains any ``deploy_hooks.global_hooks``
           entry whose ``command`` field fails the current
           ``DeployManager._validate_hook`` rules, the entire restore is
           aborted. Hook commands stored under older, more-permissive
           validator versions (or smuggled in via a tampered backup zip)
           would otherwise execute on the next renewal via ``sh -c`` —
           the pre-restore safety net depends on ``pre_restore_backup``
           which the caller creates before invoking us.

        2. If the backup was created in masked-secrets mode (see
           ``create_unified_backup(include_secrets=False)``), every
           credential field arrives as the ``SECRET_MASK_SENTINEL``
           string. Existing on-disk secrets are preserved via the same
           ``_strip_masked_values`` + deep-merge pipeline used by the
           settings POST path (PR #215). On a fresh restore where no
           on-disk settings file exists yet, the masked sentinels stay
           in place and the response log surfaces a warning so the
           operator knows to re-enter credentials.
        """
        temp_zip_path = None
        try:
            logger.info(f"Starting unified backup restore from: {backup_file_path}")
            backup_path = Path(backup_file_path)

            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False

            if backup_path.name.endswith(_BACKUP_ENC_SUFFIX):
                passphrase = _backup_passphrase()
                if not passphrase:
                    # Env var name spelled as a literal: interpolating the
                    # *_PASSPHRASE_* constant trips CodeQL's clear-text-logging
                    # name heuristic even though only the name is logged.
                    logger.error(
                        f"Cannot restore encrypted backup {backup_path.name}: "
                        "CERTMATE_BACKUP_PASSPHRASE is not set"
                    )
                    return False
                try:
                    zip_bytes = _decrypt_backup_payload(backup_path.read_bytes(), passphrase)
                except (ValueError, KeyError, json.JSONDecodeError) as dec_err:
                    logger.error(f"Failed to decrypt backup {backup_path.name}: {dec_err}")
                    return False
                tmp_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
                with os.fdopen(tmp_fd, 'wb') as tmp_fh:
                    tmp_fh.write(zip_bytes)
                backup_path = Path(temp_zip_path)
                logger.info("Encrypted backup decrypted for restore")

            # Ensure directories exist
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)

            restored_domains = []
            settings_data = None

            # Extract unified backup
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # First, restore settings
                if "settings.json" in zipf.namelist():
                    settings_content = zipf.read("settings.json")
                    settings_backup = json.loads(settings_content.decode('utf-8'))

                    if "settings" in settings_backup:
                        settings_data = settings_backup["settings"]

                        # Gate 1: re-validate deploy hooks against the
                        # current validator before we trust anything in
                        # this settings dict. Importing DeployManager
                        # lazily because file_operations.py is imported
                        # early in the boot path and DeployManager pulls
                        # in scheduler/event-bus state we don't want at
                        # module-import time.
                        hook_err = self._revalidate_restored_deploy_hooks(settings_data)
                        if hook_err:
                            logger.error(
                                f"Refusing restore: deploy hook validation failed "
                                f"({hook_err}). Original on-disk settings untouched; "
                                f"see pre_restore_backup for rollback."
                            )
                            return False

                        # Gate 2: if the backup is masked, deep-merge
                        # against the on-disk settings so existing
                        # secrets survive. The merge falls back to the
                        # raw payload when the backup is plaintext
                        # (legacy v2.2.0 backups or include_secrets=True
                        # snapshots).
                        from .settings import (
                            _strip_masked_values,
                            _deep_merge_dict,
                            _DEEP_MERGE_SETTINGS_KEYS,
                        )
                        cleaned_payload = _strip_masked_values(settings_data)
                        masked_mode = (
                            isinstance(settings_backup.get('metadata'), dict)
                            and settings_backup['metadata'].get('secrets_masked') is True
                        )
                        settings_file = self.data_dir / "settings.json"
                        if masked_mode and settings_file.exists():
                            try:
                                with open(settings_file, 'r', encoding='utf-8') as existing_fp:
                                    existing = json.load(existing_fp) or {}
                            except (OSError, json.JSONDecodeError):
                                existing = {}
                            merged = dict(existing)
                            for key, value in cleaned_payload.items():
                                if (
                                    key in _DEEP_MERGE_SETTINGS_KEYS
                                    and isinstance(existing.get(key), dict)
                                    and isinstance(value, dict)
                                ):
                                    merged[key] = _deep_merge_dict(existing[key], value)
                                else:
                                    merged[key] = value
                            settings_data_to_write = merged
                        else:
                            settings_data_to_write = cleaned_payload
                            if masked_mode:
                                logger.warning(
                                    "Restoring a masked backup onto a fresh "
                                    "install: secret fields will remain as the "
                                    "mask sentinel. Operator must re-enter "
                                    "DNS / storage / SMTP credentials before "
                                    "the next renewal."
                                )

                        if self.safe_file_write(settings_file, settings_data_to_write, is_json=True):
                            logger.info("Settings restored from unified backup")
                        else:
                            logger.error("Failed to restore settings from unified backup")
                            return False
                
                # Then, restore certificates
                cert_dir_resolved = self.cert_dir.resolve()
                data_dir_resolved = self.data_dir.resolve()
                restored_data_files = 0
                for file_info in zipf.infolist():
                    if file_info.filename.startswith("certificates/") and file_info.filename != "certificates/":
                        # Remove "certificates/" prefix from the path.
                        # NB: an off-by-one here ([12:] — "certificates/" is
                        # 13 chars) used to leave a leading '/', which the
                        # ZIP-slip guard below rejected: every certificate
                        # file was silently skipped and restores were
                        # settings-only.
                        relative_path = file_info.filename[len("certificates/"):]

                        # ZIP Slip protection: reject entries with path traversal
                        if '..' in relative_path or relative_path.startswith('/'):
                            logger.warning(f"Skipping suspicious ZIP entry: {file_info.filename}")
                            continue

                        target_path = self.cert_dir / relative_path

                        # Verify resolved path stays within cert_dir
                        try:
                            target_resolved = target_path.resolve()
                            target_resolved.relative_to(cert_dir_resolved)
                        except ValueError:
                            logger.warning(f"ZIP Slip blocked: {file_info.filename} -> {target_path}")
                            continue
                        except OSError:
                            logger.warning(f"Invalid path in ZIP: {file_info.filename}")
                            continue

                        # Decompression bomb protection: reject oversized entries
                        max_entry_size = 10 * 1024 * 1024  # 10 MB per file
                        if file_info.file_size > max_entry_size:
                            logger.warning(f"Skipping oversized ZIP entry: {file_info.filename} ({file_info.file_size} bytes)")
                            continue

                        logger.info(f"Extracting certificate file: {file_info.filename}")

                        # Ensure target directory exists
                        target_path.parent.mkdir(parents=True, exist_ok=True)

                        # Extract file with size limit
                        try:
                            with zipf.open(file_info) as source, open(target_path, 'wb') as target:
                                data = source.read(max_entry_size + 1)
                                if len(data) > max_entry_size:
                                    logger.warning(f"ZIP entry exceeds size limit: {file_info.filename}")
                                    continue
                                target.write(data)
                        except Exception as e:
                            logger.error(f"Error extracting {file_info.filename}: {e}")
                            continue

                        # Set appropriate permissions: lock down every private
                        # key (live, archived, and the ACME account key), leave
                        # public cert material world-readable.
                        if _PRIVATE_KEY_FILE_RE.search(target_path.name):
                            os.chmod(target_path, 0o600)
                        else:
                            os.chmod(target_path, 0o644)

                        # Track restored domains
                        if '/' in relative_path:
                            domain = relative_path.split('/')[0]
                            if domain and domain not in restored_domains:
                                logger.info(f"Found domain in unified backup: {domain}")
                                restored_domains.append(domain)

                    # Then, restore the PKI + audit subtrees (#409). Same
                    # ZIP-slip / size / permission handling as certificates,
                    # but the first path segment is checked against
                    # _BACKUP_DATA_SUBTREES so a tampered archive cannot use
                    # this branch to drop a settings.json (or anything else)
                    # into data_dir behind the deploy-hook validation gate.
                    elif file_info.filename.startswith("data/") and file_info.filename != "data/":
                        relative_path = file_info.filename[len("data/"):]

                        if '..' in relative_path or relative_path.startswith('/'):
                            logger.warning(f"Skipping suspicious ZIP entry: {file_info.filename}")
                            continue

                        top_level = relative_path.split('/')[0]
                        if top_level not in _BACKUP_DATA_SUBTREES:
                            logger.warning(
                                f"Skipping non-allowlisted data entry: {file_info.filename}"
                            )
                            continue

                        target_path = self.data_dir / relative_path

                        try:
                            target_resolved = target_path.resolve()
                            target_resolved.relative_to(data_dir_resolved)
                        except ValueError:
                            logger.warning(f"ZIP Slip blocked: {file_info.filename} -> {target_path}")
                            continue
                        except OSError:
                            logger.warning(f"Invalid path in ZIP: {file_info.filename}")
                            continue

                        # The 10 MB per-entry cap that suits PEM files would
                        # silently truncate DR here: certificate_audit.log is
                        # append-only and routinely outgrows it on a
                        # long-lived instance. Skipping it would leave the
                        # audit chain unverifiable while the restore still
                        # reported success. Larger cap, chunked write (never
                        # hold the file in memory), and an ERROR — not a
                        # warning — when even that is exceeded, because the
                        # result is an incomplete restore.
                        if file_info.file_size > _MAX_DATA_ENTRY_BYTES:
                            logger.error(
                                f"Restore incomplete: {file_info.filename} is "
                                f"{file_info.file_size} bytes, above the "
                                f"{_MAX_DATA_ENTRY_BYTES}-byte limit for data/ entries"
                            )
                            continue

                        target_path.parent.mkdir(parents=True, exist_ok=True)

                        try:
                            written = 0
                            with zipf.open(file_info) as source, open(target_path, 'wb') as target:
                                while True:
                                    chunk = source.read(1024 * 1024)
                                    if not chunk:
                                        break
                                    written += len(chunk)
                                    if written > _MAX_DATA_ENTRY_BYTES:
                                        raise ValueError(
                                            'declared size understated the real size'
                                        )
                                    target.write(chunk)
                        except Exception as e:
                            logger.error(f"Error extracting {file_info.filename}: {e}")
                            # Never leave a half-written PKI/audit file behind:
                            # a truncated ca.key or audit chain is worse than
                            # an absent one, because it looks restored.
                            try:
                                target_path.unlink(missing_ok=True)
                            except OSError:
                                pass
                            continue

                        # The CA signing key, the audit signing key and every
                        # client private key land here. Unlike certificates/,
                        # which operators bind-mount and read from other
                        # containers, nothing outside the app process reads
                        # data/ — so everything restored here is 0600. That
                        # includes the CA cert and the CRL: they are public
                        # information, but publishing them is the server's
                        # job (/api/crl/download), not the filesystem's.
                        os.chmod(target_path, 0o600)

                        restored_data_files += 1
            
            # A ZIP cannot carry symlinks, so certbot's live/<domain>/*.pem
            # came back as flat files and certbot would parsefail the lineage
            # and skip it — making every future renewal a silent no-op (#410).
            # Rebuild the links from the archive/ generation we restored.
            for domain in restored_domains:
                try:
                    if repair_certbot_lineage_symlinks(self.cert_dir / domain, domain):
                        logger.info(f"Rebuilt certbot lineage symlinks for {domain}")
                except OSError as e:
                    logger.warning(f"Could not rebuild lineage symlinks for {domain}: {e}")

            logger.info(f"Unified backup restored successfully from: {backup_path.name}")
            if restored_domains:
                logger.info(f"Restored {len(restored_domains)} domains: {', '.join(restored_domains)}")
            if restored_data_files:
                logger.info(f"Restored {restored_data_files} PKI/audit files under data/")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring unified backup: {e}")
            return False
        finally:
            if temp_zip_path:
                try:
                    os.unlink(temp_zip_path)
                except OSError:
                    pass


