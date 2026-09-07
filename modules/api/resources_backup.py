"""Backup listing, creation, download, restore and deletion.

Extracted from the `create_api_resources` closure (#669). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`, which is what makes them importable — and therefore
testable — without constructing the whole manager graph.

`_validate_backup_filename` moves with them: it is used only by these five
endpoints, and leaving it behind would have made this module import
`resources.py`, which imports this one. `resources.py` re-exports it so the
existing tests keep their import path.
"""
from pathlib import Path

from flask import request, send_file
from flask_restx import Resource, fields

import logging

from ..core.file_operations import RestoreIncompleteError
from .resource_context import ApiContext

logger = logging.getLogger(__name__)


def _validate_backup_filename(filename):
    """Reject path traversal attempts in backup filenames. Returns error string or None."""
    if not filename:
        return 'Filename is required'
    if '..' in filename or '/' in filename or '\\' in filename or '\x00' in filename:
        return 'Invalid filename'
    # NUL was rejected above but the other control characters were not, so a
    # name like "x\nFORGED.zip" passed and reached the log lines that report
    # the filename back — under the non-JSON log format that forges a record.
    # Every backup this application writes is named backup_<timestamp>.zip, so
    # a control character in one is never legitimate: refuse it here, at the
    # single point all five endpoints already go through, rather than scrubbing
    # each log site and waiting for the next one to be added without it.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in filename):
        return 'Invalid filename'
    # .zip = cleartext backup, .zip.enc = encrypted-at-rest backup
    # (CERTMATE_BACKUP_PASSPHRASE).
    if not (filename.endswith('.zip') or filename.endswith('.zip.enc')):
        return 'Invalid backup file format'
    return None


def create_backup_resources(api, models, ctx: ApiContext) -> dict:
    """Build the backup resources against *ctx*."""

    class BackupList(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['backup_list_model'])
        @ctx.auth.require_role('viewer')
        def get(self):
            """List all available backups"""
            try:
                backups = ctx.file_ops.list_backups()
                return backups
            except Exception as e:
                logger.error(f"Error listing backups: {e}")
                return {'error': 'Failed to list backups'}, 500

    class BackupCreate(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupCreateRequest', {
            'type': fields.String(required=True, enum=['unified', 'settings', 'certificates', 'both'],
                                  description='Type of backup to create (unified recommended for data consistency)'),
            'reason': fields.String(description='Reason for backup creation', default='manual'),
            'include_secrets': fields.Boolean(
                description=(
                    'Default false: every secret-bearing field is replaced '
                    'with the mask sentinel in the resulting zip, so the '
                    'file is safe to share. true: produces a plaintext '
                    'snapshot for disaster-recovery restore; the resulting '
                    'file on disk now contains every credential and a '
                    'dedicated audit-log entry records the opt-in.'
                ),
                default=False,
            ),
        }))
        @ctx.auth.require_role('admin')
        def post(self):
            """Create a new backup (unified format recommended)"""
            try:
                data = api.payload
                backup_type = data.get('type', 'unified')  # Default to unified
                reason = data.get('reason', 'manual')
                # `include_secrets` decides between a share-safe masked archive
                # and a plaintext dump of every credential and private key, so
                # it MUST be a real JSON boolean. bool() coercion was the trap:
                # bool("false") is True, so a client sending the value as a
                # string — trivial in a shell or an untyped template —
                # asked for masked and got the plaintext dump. Accept only a
                # JSON boolean; anything else is refused rather than guessed,
                # and the safe default (masked) applies only when it is absent.
                raw_include = data.get('include_secrets', False)
                if not isinstance(raw_include, bool):
                    return {
                        'error': 'include_secrets must be a JSON boolean '
                                 '(true or false)'
                    }, 400
                include_secrets = raw_include

                created_backups = []

                # Only support unified backup (legacy removed)
                settings = ctx.settings.load_settings()
                filename = ctx.file_ops.create_unified_backup(
                    settings, reason, include_secrets=include_secrets,
                )
                if filename:
                    created_backups.append({'type': 'unified', 'filename': filename})
                    # Log the secret-handling MODE name, not the boolean
                    # `include_secrets` — CodeQL's clear-text-logging rule
                    # flags any expression named "secrets" landing in a log
                    # line, even when the value is a True/False flag.
                    backup_mode = 'plaintext' if include_secrets else 'masked'
                    logger.info(f"Created unified backup: {filename} (mode={backup_mode})")

                if created_backups:
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='create',
                            resource_type='backup',
                            resource_id=created_backups[0].get('filename', 'unknown'),
                            status='success',
                            details={
                                'type': 'unified',
                                'reason': reason,
                                # Pin the secret-handling mode on the
                                # audit record so a SIEM can flag the
                                # opt-in path (the resulting file on
                                # disk is a credential dump).
                                'include_secrets': include_secrets,
                                'secrets_masked': not include_secrets,
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {
                        'message': 'Backup created successfully',
                        'backups': created_backups,
                        'secrets_masked': not include_secrets,
                        'recommendation': 'Use unified backup' if backup_type != 'unified' else None,
                    }, 201
                else:
                    return {'error': 'Failed to create backup'}, 500

            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                return {'error': 'Failed to create backup'}, 500

    class BackupDownload(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def get(self, backup_type, filename):
            """Download a backup file"""
            try:
                if backup_type != 'unified':
                    return {'error': 'Only unified backup download is supported'}, 400

                err = _validate_backup_filename(filename)
                if err:
                    return {'error': err}, 400

                backup_path = Path(ctx.file_ops.backup_dir) / backup_type / filename

                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(ctx.file_ops.backup_dir).resolve())):
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        ctx.audit.log_operation(
                            operation='download',
                            resource_type='backup',
                            resource_id=filename,
                            status='denied',
                            details={
                                'backup_type': backup_type,
                                'reason': 'Path traversal attempt'
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    return {'error': 'Access denied'}, 403

                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='download',
                        resource_type='backup',
                        resource_id=filename,
                        status='success',
                        details={
                            'backup_type': backup_type
                        },
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )

                return send_file(
                    str(backup_path.resolve()),
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/octet-stream'
                )

            except FileNotFoundError:
                return {'error': 'Backup file not found'}, 404
            except PermissionError:
                return {'error': 'Access denied to backup file'}, 403
            except Exception as e:
                logger.error(f"Error downloading backup: {e}")
                return {'error': 'Failed to download backup'}, 500

    class BackupRestore(Resource):
        @api.doc(security='Bearer')
        @api.expect(api.model('BackupRestoreRequest', {
            'filename': fields.String(required=True, description='Backup filename to restore from'),
            'create_backup_before_restore': fields.Boolean(description='Create backup before restore', default=True)
        }))
        @ctx.auth.require_role('admin')
        def post(self, backup_type):
            """Restore from a unified backup file (only unified backups supported)"""
            try:
                if backup_type != 'unified':
                    return {'error': 'Only unified backup restoration is supported'}, 400

                data = api.payload
                filename = data.get('filename')
                create_backup = data.get('create_backup_before_restore', True)

                err = _validate_backup_filename(filename)
                if err:
                    return {'error': err}, 400

                backup_path = Path(ctx.file_ops.backup_dir) / "unified" / filename

                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                # Security check
                if not str(backup_path.resolve()).startswith(str(Path(ctx.file_ops.backup_dir).resolve())):
                    return {'error': 'Access denied'}, 403

                # Create backup of current state if requested
                pre_restore_backup = None
                if create_backup:
                    current_settings = ctx.settings.load_settings()
                    # include_secrets=True: this archive exists for exactly one
                    # purpose — putting the instance back if the restore below
                    # goes wrong. A masked rollback cannot recover a single
                    # credential, which makes it a file that looks like a
                    # safety net and is not one. It never leaves the host and
                    # is written chmod 0600, and the opt-in is audit-logged
                    # with the restore entry below.
                    pre_restore_backup = ctx.file_ops.create_unified_backup(
                        current_settings, "pre_restore", include_secrets=True)
                    # create_unified_backup returns None on failure (e.g. the
                    # backups directory is not writable). The operator asked for
                    # a pre-restore backup precisely so the restore is
                    # reversible; if we cannot make one, proceeding would
                    # overwrite settings and certificates with no way back. Fail
                    # closed instead of silently doing the irreversible thing.
                    if not pre_restore_backup:
                        return {
                            'error': 'Refusing to restore: the pre-restore '
                                     'backup could not be created, so the '
                                     'restore would not be reversible. Check '
                                     'that the backup directory is writable, or '
                                     'retry with '
                                     'create_backup_before_restore=false to '
                                     'proceed without a safety net.'
                        }, 500
                    logger.info(f"Created pre-restore backup: {pre_restore_backup}")

                # Restore from unified backup
                success = ctx.file_ops.restore_unified_backup(str(backup_path))
                restore_msg = "Settings and certificates restored atomically"

                if success:
                    if ctx.audit:
                        user = getattr(request, 'current_user', None) or {}
                        # Restore wholesale-replaces settings + certificates;
                        # the audit entry must surface both source filename
                        # and the pre-restore backup (if one was created) so
                        # an admin can roll back via the audit trail alone.
                        ctx.audit.log_operation(
                            operation='restore',
                            resource_type='backup',
                            resource_id=filename,
                            status='success',
                            details={
                                'backup_type': 'unified',
                                'pre_restore_backup': pre_restore_backup,
                            },
                            user=user.get('username'),
                            ip_address=request.remote_addr,
                        )
                    response = {
                        'message': f'{restore_msg} successfully from {filename}',
                        'restored_from': filename,
                        'backup_type': 'unified'
                    }
                    if pre_restore_backup:
                        response['pre_restore_backup'] = pre_restore_backup
                        response['note'] = 'A backup of the previous state was created before restore'

                    return response, 200
                else:
                    reason = getattr(ctx.file_ops, 'last_restore_error', None)
                    if reason:
                        # The restore declined for a reason it can state
                        # (a share-safe archive over a populated instance);
                        # nothing was written. 409, not 500.
                        return {'error': f'Restore refused: {reason}'}, 409
                    return {'error': 'Failed to restore unified backup'}, 500

            except FileNotFoundError:
                return {'error': 'Backup file not found'}, 404
            except RestoreIncompleteError as e:
                # Some members restored, at least one did not. The failed ones
                # kept their pre-existing files (atomic extract), so nothing was
                # truncated — but the instance is now a mix of old and new and
                # must not be reported as a clean restore. Name the members so
                # the operator knows what to check before rolling back.
                logger.error(f"Restore incomplete: {e}")
                return {
                    'error': 'Restore incomplete — some files could not be '
                             'restored and were left unchanged; the instance '
                             'is in a mixed state. Roll back with the '
                             'pre-restore backup.',
                    'failed': e.failed,
                }, 500
            except ValueError as e:
                logger.warning(f"Backup restore validation error: {e}")
                return {'error': 'Invalid backup data'}, 400
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
                return {'error': 'Failed to restore backup'}, 500

    class BackupDelete(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('admin')
        def delete(self, backup_type, filename):
            """Delete a unified backup file"""
            try:
                file_ops_manager = ctx.managers.get('file_ops')
                if not file_ops_manager:
                    return {'error': 'File operations manager not available'}, 503

                if backup_type != 'unified':
                    return {'error': 'Only unified backup deletion is supported'}, 400

                err = _validate_backup_filename(filename)
                if err:
                    return {'error': err}, 400

                backup_dir = file_ops_manager.backup_dir / backup_type
                backup_path = backup_dir / filename

                # Validate the backup file exists and is within the backup directory
                if not backup_path.exists():
                    return {'error': 'Backup file not found'}, 404

                if not str(backup_path.resolve()).startswith(str(backup_dir.resolve())):
                    return {'error': 'Invalid backup path'}, 400

                # Delete the backup file
                backup_path.unlink()

                logger.info(f"Backup deleted: {backup_type}/{filename}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='delete',
                        resource_type='backup',
                        resource_id=filename,
                        status='success',
                        details={'backup_type': backup_type},
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {
                    'message': f'Backup {filename} deleted successfully',
                    'deleted_file': filename,
                    'backup_type': backup_type
                }, 200

            except Exception as e:
                logger.error(f"Error deleting backup: {e}")
                return {'error': 'Failed to delete backup'}, 500

    return {
        'BackupList': BackupList,
        'BackupCreate': BackupCreate,
        'BackupDownload': BackupDownload,
        'BackupRestore': BackupRestore,
        'BackupDelete': BackupDelete,
    }
