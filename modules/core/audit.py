"""
Audit logging module for CertMate
Tracks all certificate operations for compliance and debugging
"""

import os
import logging
import json
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from collections import deque
from .utils import utc_now
from . import audit_chain
from . import audit_signing
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Rotation defaults for the human-readable audit .log (#443). Same shape as the
# application log's (#431), and deliberately NOT applied to the hash chain:
# `certificate_audit.chain.jsonl` is append-only and tamper-evident, and naive
# rotation breaks the property it exists for (see #437).
DEFAULT_AUDIT_LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MB per file
DEFAULT_AUDIT_LOG_BACKUP_COUNT = 5               # ~60 MB ceiling


def _int_env(name: str, default: int) -> int:
    """Read a positive int from the environment, ignoring anything unusable.
    A typo in a log-rotation setting must not take the application down."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning("Ignoring %s=%r (not an integer); using %d", name, raw, default)
        return default
    if value < 0:
        logger.warning("Ignoring %s=%r (negative); using %d", name, raw, default)
        return default
    return value


class AuditLogger:
    """Centralized audit logging for certificate operations."""

    def __init__(self, audit_log_dir: Path, chain_dir: Optional[Path] = None,
                 enable_chain: bool = True, signer=None,
                 checkpoint_interval: int = 100,
                 max_bytes: Optional[int] = None,
                 backup_count: Optional[int] = None):
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
            max_bytes / backup_count: rotation of the human-readable ``.log``
                (#443). Default to ``CERTMATE_AUDIT_LOG_MAX_BYTES`` /
                ``CERTMATE_AUDIT_LOG_BACKUP_COUNT``, then to 10 MB × 5.
                ``max_bytes=0`` disables rotation, which is how ``logging`` spells
                it and the only way to get an unbounded file back.
        """
        self.audit_log_dir = Path(audit_log_dir)
        self.audit_log_file = self.audit_log_dir / "certificate_audit.log"

        if max_bytes is None:
            max_bytes = _int_env('CERTMATE_AUDIT_LOG_MAX_BYTES',
                                 DEFAULT_AUDIT_LOG_MAX_BYTES)
        if backup_count is None:
            backup_count = _int_env('CERTMATE_AUDIT_LOG_BACKUP_COUNT',
                                    DEFAULT_AUDIT_LOG_BACKUP_COUNT)

        # Configure the audit file handler. Rotating, not plain (#443): this
        # file grew without bound, and #431's fix covered only the application
        # log — this handler is built here and was never reached by it.
        #
        # Safe to rotate because it carries no integrity property: it is
        # human-readable text, not hashed, not chained, and the `logs/` tree is
        # excluded from backups. The verifiable artifact is the hash chain in
        # `data/audit/`, which is emphatically NOT rotated (see #437).
        #
        # RotatingFileHandler is not multi-process safe; the container runs
        # gunicorn with `--workers 1 --threads 8`, one process, which is the
        # same single-writer assumption the hash chain already depends on.
        self.file_handler = None
        try:
            self.audit_log_dir.mkdir(parents=True, exist_ok=True)
            self.file_handler = RotatingFileHandler(
                str(self.audit_log_file),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8',
            )
            self.file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
            )
        except OSError as e:
            # Previously this raised out of __init__, which the factory calls
            # unguarded — an unwritable logs directory took the whole
            # application down over a *log file*. The hash chain below is the
            # record that matters and is written elsewhere; keep going.
            logger.error(
                "Could not open audit log file %s (%s); the human-readable "
                "audit log is disabled. The tamper-evident chain is unaffected.",
                self.audit_log_file, e,
            )

        # Create audit logger
        self.audit_logger = logging.getLogger('certmate.audit')
        if self.file_handler is not None:
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

        # Phase 3: signed checkpoints. Every `checkpoint_interval` entries (and
        # on demand / graceful shutdown) the current chain head is signed and
        # appended to a checkpoint file, giving a third party signed anchors to
        # verify an exported bundle against. No-op when no signer is wired.
        self._signer = signer
        self._checkpoint_interval = max(1, int(checkpoint_interval))
        self.audit_checkpoint_file = self._chain_dir / audit_chain.CHECKPOINT_FILENAME
        self._since_checkpoint = 0

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
                    if not isinstance(rec, dict):
                        continue  # a non-object line is not a valid record
                    if isinstance(rec.get('seq'), int) and rec.get('hash'):
                        last_good = rec
            if last_good is not None:
                self._next_seq = last_good['seq'] + 1
                self._last_hash = last_good['hash']
        except Exception as e:
            # Recovery runs inside AuditLogger.__init__, which the factory calls
            # unguarded — it must NEVER abort app startup (that would take the
            # renewal scheduler down with it). On any trouble, disable the chain
            # rather than fork it from a wrong baseline or raise.
            logger.error(f"Could not recover audit chain state; disabling chain: {e}")
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
                self._since_checkpoint += 1
                due = self._since_checkpoint >= self._checkpoint_interval
            # Write the checkpoint outside the append (it takes the lock itself).
            if due:
                self.write_checkpoint()
        except Exception as e:
            logger.error(f"Failed to append to audit chain: {e}")

    def write_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Sign the current chain head and append it to the checkpoint file.
        No-op (returns None) without a signer or with an empty chain. Best-effort:
        a checkpoint failure never breaks audit logging. Call on graceful
        shutdown to seal the tail."""
        if self._signer is None or not getattr(self._signer, 'available', False):
            return None
        try:
            with self._chain_lock:
                if self._next_seq == 0:  # nothing written yet
                    return None
                seq = self._next_seq - 1
                head_hash = self._last_hash
                checkpoint = {
                    'seq': seq,
                    'hash': head_hash,
                    'count': self._next_seq,
                    'timestamp': utc_now().isoformat(),
                }
                sig = self._signer.sign(
                    audit_chain.canon_bytes({
                        'seq': checkpoint['seq'], 'hash': checkpoint['hash'],
                        'count': checkpoint['count'], 'timestamp': checkpoint['timestamp'],
                    })
                )
                if sig is None:
                    return None
                checkpoint['signature'] = sig
                with open(self.audit_checkpoint_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(checkpoint, ensure_ascii=False) + '\n')
                    f.flush()
                    os.fsync(f.fileno())
                self._since_checkpoint = 0
                return checkpoint
        except Exception as e:
            logger.error(f"Failed to write audit checkpoint: {e}")
            return None

    def public_key_info(self) -> Optional[Dict[str, Any]]:
        """Return this instance's audit signing identity, or None when unsigned."""
        if self._signer is None or not getattr(self._signer, 'available', False):
            return None
        pem = self._signer.public_key_pem()
        if not pem:
            return None
        return {
            'algorithm': audit_signing.ALGORITHM,
            'public_key_pem': pem,
            'fingerprint': self._signer.fingerprint(),
        }

    def export_bundle(self, from_seq: Optional[int] = None,
                      to_seq: Optional[int] = None) -> Dict[str, Any]:
        """Build a signed, independently-verifiable export of the audit chain.

        Returns ``{manifest, entries, bundle_signature}``. The manifest pins the
        instance fingerprint, public key, seq range and head hash; the signature
        is over the canonical manifest, which (via head_hash) transitively
        commits to every entry. ``bundle_signature`` is None when no signer is
        wired (the entries + chain are still verifiable, just not attributed)."""
        with self._chain_lock:
            records = audit_chain.load_records(self.audit_chain_file, from_seq, to_seq)
        signed = self._signer is not None and getattr(self._signer, 'available', False)
        fingerprint = self._signer.fingerprint() if signed else None
        public_key_pem = self._signer.public_key_pem() if signed else None
        manifest = audit_chain.build_manifest(
            records,
            fingerprint=fingerprint,
            public_key_pem=public_key_pem,
            exported_at=utc_now().isoformat(),
            algorithm=audit_signing.ALGORITHM,
        )
        bundle_signature = None
        if signed:
            bundle_signature = self._signer.sign(audit_chain.manifest_signing_bytes(manifest))
        return {
            'manifest': manifest,
            'entries': records,
            'bundle_signature': bundle_signature,
        }

    def has_checkpoints(self) -> bool:
        """True if at least one signed checkpoint has been written. Used to tell
        a genuinely fresh instance (no chain, no checkpoints — benign) from a
        chain file that was DELETED after checkpoints attested it existed
        (tamper). Deliberately propagates
        :class:`audit_chain.CheckpointReadError`: an UNREADABLE checkpoint
        file must fail closed at the caller, never read as "no checkpoints"."""
        return bool(audit_chain.read_checkpoints(self.audit_checkpoint_file))

    def verify_chain(self) -> Dict[str, Any]:
        """Verify this instance's hash chain. Wraps
        :func:`audit_chain.verify_chain` (internal consistency) and then, when a
        signer is wired, cross-checks the chain against the latest signed
        checkpoint — a fail-closed anchor.

        The bare hash chain cannot, on its own, detect a tail truncation or a
        wholesale rewrite (anyone who can write the file can recompute it). The
        signed checkpoints were being WRITTEN but never READ, so that gap stood
        open. Reading them back here means an attacker WITHOUT the signing key
        can no longer roll the chain back to, or rewrite it at/below, the last
        checkpoint without detection: they cannot forge a matching signed
        checkpoint. (Binding an operator who HOLDS the key still needs off-box
        anchoring — see the audit_chain / audit_signing docstrings; this does
        not claim to provide that.)

        Takes the append lock so a verify that races an in-flight append does
        not observe a half-written final line and report a spurious truncation
        (the standalone CLI verifier cannot take the lock and accepts that)."""
        with self._chain_lock:
            result = audit_chain.verify_chain(self.audit_chain_file)
            if result.get("ok"):
                self._cross_check_latest_checkpoint(result)
            return result

    def _cross_check_latest_checkpoint(self, result: Dict[str, Any]) -> None:
        """Cross-check an internally-consistent chain against the newest signed
        checkpoint that verifies under the current key. Mutates *result*:
        always sets ``checkpoint_verified`` / ``checkpoint_reason``, and flips
        ``ok`` to False if the chain diverges from the checkpoint."""
        result["checkpoint_verified"] = False
        if self._signer is None or not getattr(self._signer, "available", False):
            result["checkpoint_reason"] = "no signer; checkpoints not cross-checked"
            return
        pubkey = self._signer.public_key_pem()
        if not pubkey:
            result["checkpoint_reason"] = "signer has no public key"
            return
        try:
            checkpoints = audit_chain.read_checkpoints(self.audit_checkpoint_file)
        except audit_chain.CheckpointReadError as e:
            # Fail closed: an unreadable anchor means the chain CANNOT be
            # verified against it, which must not read as "intact".
            result["ok"] = False
            result["checkpoint_unreadable"] = True
            result["checkpoint_reason"] = str(e)
            result["reason"] = "checkpoint file unreadable — cannot verify integrity"
            return
        if not checkpoints:
            result["checkpoint_reason"] = "no checkpoints written yet"
            return
        # Newest checkpoint whose signature verifies under the current key. A
        # checkpoint that does not verify is ignored (e.g. key rotation, or a
        # chain imported from another instance) rather than treated as tamper,
        # to avoid false positives; the newest VERIFIED one is the anchor.
        latest = None
        for cp in reversed(checkpoints):
            sig = cp.get("signature")
            if sig and audit_signing.verify_signature(
                pubkey, sig, audit_chain.checkpoint_signing_bytes(cp)
            ):
                latest = cp
                break
        if latest is None:
            result["checkpoint_reason"] = (
                "no checkpoint signature verifies under the current key "
                "(key rotated, or checkpoints from another instance)"
            )
            return
        records = audit_chain.load_records(self.audit_chain_file)
        check = audit_chain.cross_check_checkpoint(records, latest)
        result["checkpoint_verified"] = bool(check.get("ok"))
        result["checkpoint_seq"] = latest.get("seq")
        result["checkpoint_reason"] = check.get("reason")
        if not check.get("ok"):
            result["ok"] = False
            result["reason"] = check.get("reason")
            result["error_seq"] = latest.get("seq")

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

    # ``get_entries_by_resource`` was removed with #443. It read the entire
    # audit log to filter by resource_id and had no callers anywhere in the
    # codebase. Leaving a whole-file reader behind a rotating handler is how a
    # "why is the history missing" bug gets born: it would have silently
    # reported only what survived in the active file. Per-resource history
    # belongs on the hash chain, which is complete and verifiable.
