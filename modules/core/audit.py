"""
Audit logging module for CertMate
Tracks all certificate operations for compliance and debugging
"""

import os
import logging
import json
import threading
from pathlib import Path
from datetime import datetime
from collections import deque
from .utils import utc_now
from . import audit_chain
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AuditLogger:
    """Centralized audit logging for certificate operations."""

    def __init__(self, audit_log_dir: Path, chain_dir: Optional[Path] = None,
                 enable_chain: bool = True):
        """
        Initialize Audit Logger.

        Args:
            audit_log_dir: Directory to store audit logs
            chain_dir: Directory for the tamper-evident hash chain. Defaults to
                ``audit_log_dir``. In production this is pointed at a
                backed-up location (``data/audit``) so the verifiable artifact
                survives in backups, while the human-readable ``.log`` can stay
                under the (backup-excluded) ``logs`` tree.
            enable_chain: write the hash chain (default True). Disable via the
                ``CERTMATE_AUDIT_CHAIN=0`` environment variable as a kill switch.
        """
        self.audit_log_dir = Path(audit_log_dir)
        self.audit_log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_file = self.audit_log_dir / "certificate_audit.log"

        # Configure audit file handler
        self.file_handler = logging.FileHandler(self.audit_log_file)
        self.file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        )

        # Create audit logger
        self.audit_logger = logging.getLogger('certmate.audit')
        self.audit_logger.addHandler(self.file_handler)
        self.audit_logger.setLevel(logging.INFO)

        # Tamper-evident hash chain (Phase 2). One writer, one local file; the
        # lock guards the shared next-seq/last-hash state because Flask request
        # threads and the APScheduler renewal thread share this instance.
        self._chain_enabled = enable_chain and os.environ.get('CERTMATE_AUDIT_CHAIN', '1') != '0'
        self._chain_dir = Path(chain_dir) if chain_dir is not None else self.audit_log_dir
        self.audit_chain_file = self._chain_dir / audit_chain.CHAIN_FILENAME
        self._chain_lock = threading.Lock()
        self._next_seq = 0
        self._last_hash = audit_chain.GENESIS_PREV
        if self._chain_enabled:
            self._recover_chain_state()

    def _recover_chain_state(self) -> None:
        """Recover ``_next_seq`` / ``_last_hash`` from the last complete chain
        line so appends continue the chain across restarts. A truncated trailing
        line (an interrupted write) is tolerated: we resume from the last record
        that parses, and the next append overwrites nothing (append-only)."""
        try:
            self._chain_dir.mkdir(parents=True, exist_ok=True)
            if not self.audit_chain_file.exists():
                return
            last_good = None
            with open(self.audit_chain_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # skip a corrupt/truncated line
                    if isinstance(rec.get('seq'), int) and rec.get('hash'):
                        last_good = rec
            if last_good is not None:
                self._next_seq = last_good['seq'] + 1
                self._last_hash = last_good['hash']
        except OSError as e:
            logger.error(f"Could not recover audit chain state: {e}")
            # Disable the chain rather than fork it from a wrong baseline.
            self._chain_enabled = False

    def _chain_append(self, entry: Dict[str, Any]) -> None:
        """Append one audit entry to the hash chain. Best-effort and isolated:
        a chain failure must never break audit logging or the audited
        operation. On failure the seq/hash state is NOT advanced, so the next
        append retries from the same baseline and no phantom gap is created."""
        if not self._chain_enabled:
            return
        try:
            with self._chain_lock:
                seq = self._next_seq
                line = audit_chain.make_line(seq, entry, self._last_hash)
                with open(self.audit_chain_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(line, ensure_ascii=False) + '\n')
                    f.flush()
                    os.fsync(f.fileno())
                # Advance only after the line is durably written.
                self._next_seq = seq + 1
                self._last_hash = line['hash']
        except Exception as e:
            logger.error(f"Failed to append to audit chain: {e}")

    def verify_chain(self) -> Dict[str, Any]:
        """Verify this instance's hash chain. Thin wrapper over
        :func:`audit_chain.verify_chain` for in-process callers and tests."""
        return audit_chain.verify_chain(self.audit_chain_file)

    def log_operation(
        self,
        operation: str,
        resource_type: str,
        resource_id: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
        error: Optional[str] = None,
        actor: Optional[Dict[str, Any]] = None,
        trigger: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a certificate operation.

        Args:
            operation: Operation type (create, revoke, renew, download, etc.)
            resource_type: Resource type (certificate, csr, crl, etc.)
            resource_id: Resource identifier
            status: Operation status (success, failure, denied)
            details: Additional operation details
            user: User who performed operation
            ip_address: IP address of requester
            error: Error message if operation failed
            actor: Structured attribution of WHO/WHAT acted, e.g.
                ``{'kind': 'agent'|'user'|'api_token'|'scheduler'|'system',
                'id': <api_key_id>, 'label': <username>, 'token_prefix': ...,
                'agent_session': <client-supplied claim>}``. When omitted, a
                ``{'kind': 'system', 'label': user}`` actor is synthesised so
                existing call sites keep working and the field is always present.
            trigger: Structured cause of the action, e.g.
                ``{'cause': 'manual'|'api'|'agent'|'scheduled_renewal'|'event',
                'job_id': <scheduler job id>}``. Defaults to ``{'cause': 'event'}``.

        ``actor`` and ``trigger`` are additive: readers that do not know about
        them ignore the extra keys, and the on-disk line stays backward
        compatible. ``actor.kind`` is always derived from the *authenticated*
        identity by the caller — a client-supplied ``agent_session`` is recorded
        as an informational claim and never sets ``kind`` on its own.
        """
        try:
            audit_entry = {
                'timestamp': utc_now().isoformat(),
                'operation': operation,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'status': status,
                'user': user or 'system',
                'ip_address': ip_address or 'unknown',
                'details': details or {},
                'error': error,
                'actor': actor or {'kind': 'system', 'label': user or 'system'},
                'trigger': trigger or {'cause': 'event'},
            }

            # Log to audit file as JSON for easy parsing
            self.audit_logger.info(json.dumps(audit_entry))
            # Mirror into the tamper-evident hash chain. Isolated: a chain
            # failure must never break audit logging or the audited operation.
            self._chain_append(audit_entry)

        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def log_certificate_created(
        self,
        identifier: str,
        common_name: str,
        usage: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """Log certificate creation."""
        self.log_operation(
            operation='create',
            resource_type='certificate',
            resource_id=identifier,
            status='success',
            details={
                'common_name': common_name,
                'usage': usage
            },
            user=user,
            ip_address=ip_address
        )

    def log_certificate_revoked(
        self,
        identifier: str,
        reason: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """Log certificate revocation."""
        self.log_operation(
            operation='revoke',
            resource_type='certificate',
            resource_id=identifier,
            status='success',
            details={'reason': reason},
            user=user,
            ip_address=ip_address
        )

    def log_certificate_renewed(
        self,
        identifier: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """Log certificate renewal."""
        self.log_operation(
            operation='renew',
            resource_type='certificate',
            resource_id=identifier,
            status='success',
            user=user,
            ip_address=ip_address
        )

    def log_certificate_downloaded(
        self,
        identifier: str,
        file_type: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """Log certificate file download."""
        self.log_operation(
            operation='download',
            resource_type='certificate',
            resource_id=identifier,
            status='success',
            details={'file_type': file_type},
            user=user,
            ip_address=ip_address
        )

    def log_batch_operation(
        self,
        operation: str,
        total: int,
        successful: int,
        failed: int,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """Log batch operation (e.g., CSV import)."""
        self.log_operation(
            operation=f'batch_{operation}',
            resource_type='certificates',
            resource_id='batch',
            status='success',
            details={
                'total': total,
                'successful': successful,
                'failed': failed
            },
            user=user,
            ip_address=ip_address
        )

    def log_api_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
        response_time_ms: Optional[float] = None
    ) -> None:
        """Log API request."""
        self.log_operation(
            operation='api_request',
            resource_type='endpoint',
            resource_id=endpoint,
            status='success' if status_code < 400 else 'failure',
            details={
                'method': method,
                'status_code': status_code,
                'response_time_ms': response_time_ms
            },
            user=user,
            ip_address=ip_address
        )

    def log_error(
        self,
        operation: str,
        resource_type: str,
        resource_id: str,
        error_message: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """Log operation error."""
        self.log_operation(
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
            status='failure',
            user=user,
            ip_address=ip_address,
            error=error_message
        )

    # ---- Configuration & access-control mutations ----
    # These methods cover the audit gap identified in Sprint 1: any operation
    # that mutates settings, auth config, API keys, users, deploy hooks, or
    # CA providers MUST log a non-repudiable record. Values that may contain
    # secrets are NEVER serialized — we record the set of keys changed and
    # any non-sensitive metadata.

    # Top-level settings keys whose VALUE we treat as secret. Diffs over these
    # keys still log the key name and a flag that the value changed, but
    # never the plaintext value.
    _SENSITIVE_SETTINGS_KEYS = frozenset({
        'api_bearer_token', 'api_bearer_token_hash',
        'cloudflare_token', 'dns_providers',
        'certificate_storage',  # contains vault tokens, AWS keys, etc.
        'users', 'api_keys',
    })

    def log_settings_changed(
        self,
        changed_keys: list,
        sensitive_changed: list,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log a mutation to top-level settings.

        Args:
            changed_keys: keys whose value changed (non-sensitive values may
                be diffed by callers if useful — we only record the names here)
            sensitive_changed: subset of changed_keys whose values are secret
                and therefore never serialized
        """
        self.log_operation(
            operation='update',
            resource_type='settings',
            resource_id='settings',
            status='success',
            details={
                'changed_keys': sorted(changed_keys),
                'sensitive_changed': sorted(sensitive_changed),
            },
            user=user,
            ip_address=ip_address,
        )

    def log_auth_config_changed(
        self,
        local_auth_enabled_before: bool,
        local_auth_enabled_after: bool,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log a change to the local-auth toggle."""
        self.log_operation(
            operation='update',
            resource_type='auth_config',
            resource_id='local_auth_enabled',
            status='success',
            details={
                'before': bool(local_auth_enabled_before),
                'after': bool(local_auth_enabled_after),
            },
            user=user,
            ip_address=ip_address,
        )

    def log_api_key_created(
        self,
        key_id: str,
        name: str,
        role: str,
        allowed_domains: Optional[list] = None,
        expires_at: Optional[str] = None,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log scoped API key creation. Token plaintext is NEVER logged."""
        self.log_operation(
            operation='create',
            resource_type='api_key',
            resource_id=key_id,
            status='success',
            details={
                'name': name,
                'role': role,
                'allowed_domains': allowed_domains,
                'expires_at': expires_at,
            },
            user=user,
            ip_address=ip_address,
        )

    def log_api_key_revoked(
        self,
        key_id: str,
        name: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log scoped API key revocation."""
        self.log_operation(
            operation='revoke',
            resource_type='api_key',
            resource_id=key_id,
            status='success',
            details={'name': name},
            user=user,
            ip_address=ip_address,
        )

    def log_user_created(
        self,
        username: str,
        role: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log local-auth user creation."""
        self.log_operation(
            operation='create',
            resource_type='user',
            resource_id=username,
            status='success',
            details={'role': role},
            user=user,
            ip_address=ip_address,
        )

    def log_user_deleted(
        self,
        username: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log local-auth user deletion."""
        self.log_operation(
            operation='delete',
            resource_type='user',
            resource_id=username,
            status='success',
            user=user,
            ip_address=ip_address,
        )

    def log_user_role_changed(
        self,
        username: str,
        old_role: str,
        new_role: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log a role change on a local-auth user."""
        self.log_operation(
            operation='update',
            resource_type='user',
            resource_id=username,
            status='success',
            details={'old_role': old_role, 'new_role': new_role},
            user=user,
            ip_address=ip_address,
        )

    def log_deploy_hook_changed(
        self,
        scope: str,
        hook_id: str,
        operation: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log a deploy hook mutation. Hook commands themselves are NOT logged
        (they can contain secrets and risk creating an injection log line).

        Args:
            scope: 'global' or a domain name
            hook_id: hook identifier
            operation: 'create' | 'update' | 'delete' | 'enable' | 'disable'
        """
        self.log_operation(
            operation=operation,
            resource_type='deploy_hook',
            resource_id=f"{scope}:{hook_id}",
            status='success',
            details={'scope': scope},
            user=user,
            ip_address=ip_address,
        )

    def log_ca_provider_changed(
        self,
        old: Optional[str],
        new: Optional[str],
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log a change to the active CA provider."""
        self.log_operation(
            operation='update',
            resource_type='ca_provider',
            resource_id='active',
            status='success',
            details={'before': old, 'after': new},
            user=user,
            ip_address=ip_address,
        )

    def log_authz_denied(
        self,
        operation: str,
        resource_type: str,
        resource_id: str,
        reason: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log an authorization denial (e.g. scoped key tried to access
        a domain outside its allowed_domains)."""
        self.log_operation(
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
            status='denied',
            details={'reason': reason},
            user=user,
            ip_address=ip_address,
        )

    def get_recent_entries(self, limit: int = 100) -> list:
        """
        Get recent audit log entries.

        Uses a tail-seek approach to avoid reading the entire file.

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of audit entries (parsed JSON), newest first
        """
        try:
            if not self.audit_log_file.exists():
                return []

            if limit <= 0:
                return []

            file_size = self.audit_log_file.stat().st_size
            if file_size == 0:
                return []

            # Read only the tail of the file so large audit logs do not block
            # the activity page or other callers that only need recent entries.
            block_size = 8192
            blocks = []
            remaining = file_size

            with open(self.audit_log_file, 'rb') as f:
                while remaining > 0 and len(blocks) <= limit:
                    read_size = min(block_size, remaining)
                    remaining -= read_size
                    f.seek(remaining)
                    blocks.append(f.read(read_size))

            raw_lines = b''.join(reversed(blocks)).splitlines()

            # If we did not read from the start of the file, the first line can be partial.
            if remaining > 0 and raw_lines:
                raw_lines = raw_lines[1:]

            entries = []
            for line in raw_lines[-limit:]:
                try:
                    raw = line.decode('utf-8', errors='replace')
                    if ' - INFO - ' not in raw:
                        continue
                    json_str = raw.split(' - INFO - ', 1)[1].strip()
                    entries.append(json.loads(json_str))
                except (UnicodeDecodeError, json.JSONDecodeError, IndexError):
                    continue

            return entries

        except Exception as e:
            logger.error(f"Error reading audit logs: {e}")
            return []

    def get_entries_by_resource(self, resource_id: str) -> list:
        """
        Get all audit entries for a specific resource.

        Args:
            resource_id: Resource identifier

        Returns:
            List of matching audit entries
        """
        try:
            entries = []
            if not self.audit_log_file.exists():
                return entries

            with open(self.audit_log_file, 'r') as f:
                for line in f:
                    try:
                        if ' - INFO - ' in line:
                            json_str = line.split(' - INFO - ', 1)[1].strip()
                            entry = json.loads(json_str)
                            if entry.get('resource_id') == resource_id:
                                entries.append(entry)
                    except (json.JSONDecodeError, IndexError):
                        continue

            return entries

        except Exception as e:
            logger.error(f"Error reading audit logs: {e}")
            return []
