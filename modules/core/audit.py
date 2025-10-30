"""
Audit logging module for CertMate
Tracks all certificate operations for compliance and debugging
"""

import logging
import json
from pathlib import Path
from datetime import datetime
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
                'timestamp': datetime.utcnow().isoformat(),
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

    def get_recent_entries(self, limit: int = 100) -> list:
        """
        Get recent audit log entries.

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of audit entries (parsed JSON)
        """
        try:
            entries = []
            if not self.audit_log_file.exists():
                return entries

            with open(self.audit_log_file, 'r') as f:
                lines = f.readlines()
                # Get last 'limit' lines
                for line in lines[-limit:]:
                    try:
                        # Extract JSON from log line (format: timestamp - logger - level - {json})
                        if ' - INFO - ' in line:
                            json_str = line.split(' - INFO - ', 1)[1].strip()
                            entries.append(json.loads(json_str))
                    except (json.JSONDecodeError, IndexError):
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
