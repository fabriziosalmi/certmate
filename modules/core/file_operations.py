"""
File operations module for CertMate
Handles file I/O, backup management, and safe file operations
"""

import os
import json
import tempfile
import zipfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import fcntl
import logging

logger = logging.getLogger(__name__)

# Backup constants
BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
MAX_BACKUPS_PER_TYPE = 50   # Maximum number of backups to keep per type


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
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            backup_id = f"backup_{timestamp}_{backup_reason}"
            backup_filename = f"{backup_id}.zip"
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

            settings_to_write = settings_data if include_secrets else self._mask_settings_secrets(settings_data)

            metadata = {
                "backup_id": backup_id,
                "timestamp": datetime.now().isoformat(),
                "backup_reason": backup_reason,
                "version": "2.2.0",  # New unified format
                "type": "unified",
                "domains": domains,
                "settings_domains": [d.get('domain') if isinstance(d, dict) else d for d in settings_data.get('domains', [])],
                "total_domains": len(domains),
                # Pin the secret-handling mode on the backup itself so an
                # operator inspecting an old archive can see whether it's
                # a share-safe (masked) snapshot or a full-restore one.
                "secrets_masked": not include_secrets,
            }

            # Create ZIP file with both settings and certificates
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
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
                        if cert_file.is_file():
                            # Add file to zip with relative path under certificates/
                            arc_path = f"certificates/{cert_file.relative_to(self.cert_dir)}"
                            zipf.write(cert_file, arc_path)

                # Add unified metadata
                zipf.writestr("backup_metadata.json", json.dumps(metadata, indent=2))

            # Lock the file down. Default umask leaves the zip world-
            # readable on most distros; the contents are a JSON blob of
            # operator-facing material (private keys live in the cert
            # subtree but still). 0600 = certmate-user only.
            try:
                os.chmod(backup_path, 0o600)
            except OSError as perm_err:
                logger.warning(f"Could not tighten permissions on {backup_path}: {perm_err}")

            mode_tag = 'plaintext' if include_secrets else 'masked'
            logger.info(f"Unified backup created: {backup_filename} (contains {len(domains)} domains; secrets={mode_tag})")
            self._prune_unified_backups()
            return backup_filename

        except Exception as e:
            logger.error(f"Error creating unified backup: {e}")
            return None

    def _prune_unified_backups(self):
        """Enforce backup retention: keep at most MAX_BACKUPS_PER_TYPE files,
        and delete files older than BACKUP_RETENTION_DAYS regardless of count."""
        try:
            backup_dir = self.backup_dir / "unified"
            if not backup_dir.exists():
                return
            backups = sorted(
                backup_dir.glob("backup_*.zip"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            cutoff = datetime.now() - timedelta(days=BACKUP_RETENTION_DAYS)
            removed = 0
            for idx, path in enumerate(backups):
                try:
                    mtime = datetime.fromtimestamp(path.stat().st_mtime)
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
                for backup_file in unified_backup_dir.glob("backup_*.zip"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read unified backup metadata
                        try:
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
        try:
            logger.info(f"Starting unified backup restore from: {backup_file_path}")
            backup_path = Path(backup_file_path)

            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False

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
                for file_info in zipf.infolist():
                    if file_info.filename.startswith("certificates/") and file_info.filename != "certificates/":
                        # Remove "certificates/" prefix from the path
                        relative_path = file_info.filename[12:]  # len("certificates/") = 12

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

                        # Set appropriate permissions
                        if target_path.name == 'privkey.pem':
                            os.chmod(target_path, 0o600)
                        else:
                            os.chmod(target_path, 0o644)

                        # Track restored domains
                        if '/' in relative_path:
                            domain = relative_path.split('/')[0]
                            if domain and domain not in restored_domains:
                                logger.info(f"Found domain in unified backup: {domain}")
                                restored_domains.append(domain)
            
            logger.info(f"Unified backup restored successfully from: {backup_path.name}")
            if restored_domains:
                logger.info(f"Restored {len(restored_domains)} domains: {', '.join(restored_domains)}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring unified backup: {e}")
            return False


