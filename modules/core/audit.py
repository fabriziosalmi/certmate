"""
Audit logging module for CertMate
Tracks all certificate operations for compliance and debugging
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from collections import deque
from .utils import utc_now
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AuditLogger:
    """Centralized audit logging for certificate operations."""

    def __init__(self, audit_log_dir: Path):
        """
        Initialize Audit Logger.

        Args:
            audit_log_dir: Directory to store audit logs
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

    def log_operation(
        self,
        operation: str,
        resource_type: str,
        resource_id: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
        error: Optional[str] = None
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
                'error': error
            }

            # Log to audit file as JSON for easy parsing
            self.audit_logger.info(json.dumps(audit_entry))

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
