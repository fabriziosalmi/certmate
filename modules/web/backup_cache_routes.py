import logging

from functools import wraps

from flask import request, jsonify
from modules.core.auth import domain_restricted_refusal
from modules.core.request_fields import json_booleans

logger = logging.getLogger(__name__)


def register_backup_cache_routes(app, managers, require_web_auth,
                                 auth_manager, file_ops, settings_manager,
                                 cache_manager):
    """Register backup and cache related routes"""

    def not_for_restricted_keys(fn):
        # The dashboard's twins of the backup API, held to the same rule: a key
        # restricted to domains has no claim on a backup of the whole instance.
        @wraps(fn)
        def wrapped(*args, **kwargs):
            refusal = domain_restricted_refusal(managers.get('audit'), 'backup', 'backups')
            if refusal:
                return jsonify({'error': refusal, 'code': 'DOMAIN_OUT_OF_SCOPE'}), 403
            return fn(*args, **kwargs)
        return wrapped

    @app.route('/api/web/backups', methods=['GET'])
    @auth_manager.require_role('admin')
    @not_for_restricted_keys
    def list_backups_web():
        """List all backups"""
        try:
            backups = file_ops.list_backups()
            return jsonify(backups)
        except Exception as e:
            # Logged, not only answered. The operator gets the same generic
            # 500 — a traceback must not reach the client — but the cause has
            # to exist somewhere, and this file used to have no logger at all.
            logger.error("Failed to list backups: %s", e)
            return jsonify({'error': 'Failed to list backups'}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    @auth_manager.require_role('admin')
    @not_for_restricted_keys
    @json_booleans(include_secrets=False)
    def create_backup_web():
        """Create a new backup.

        ``include_secrets`` (boolean, default false) mirrors the RESTX
        endpoint contract: false produces a share-safe masked snapshot,
        true produces a plaintext disaster-recovery snapshot. The opt-in
        path is admin-only and surfaces in audit_logger.
        """
        try:
            data = request.json or {}
            backup_reason = data.get('reason', 'manual')
            # false means a share-safe masked archive, true a plaintext dump
            # of every private key, so the decorator refuses anything that is
            # not a JSON boolean before this runs.
            include_secrets = request.json_booleans['include_secrets']
            settings_data = settings_manager.load_settings()
            filename = file_ops.create_unified_backup(
                settings_data, backup_reason, include_secrets=include_secrets,
            )
            # `create_unified_backup` returns None on failure — a directory
            # that is not writable, a full disk — and this answered
            # 200 {"message": "Backup created", "filename": null} anyway.
            # An operator taking a backup before something risky got a green
            # toast and no file, which is the one moment that answer must be
            # true. The RESTX twin has always answered 500 here; the
            # pre-restore path refuses to continue at all.
            if not filename:
                return jsonify({'error': 'Failed to create backup'}), 500
            return jsonify({
                'message': 'Backup created',
                'filename': filename,
                'secrets_masked': not include_secrets,
            })
        except Exception as e:
            logger.error("Backup creation failed: %s", e)
            return jsonify({'error': 'Backup creation failed'}), 500

    # Only /api/web/... is registered here. The bare /api/cache/stats is
    # owned by the flask-restx CacheStats resource, registered first in
    # setup_api, so it always won the duplicate rule and this binding was
    # dead. Same shadowing that cert_routes.py documents for
    # /api/certificates/create. Leaving it bound was not harmless: the
    # restx CacheClear writes an audit entry and this one does not, so a
    # change in registration order would have silently stopped auditing
    # cache clears.
    @app.route('/api/web/cache/stats', methods=['GET'])
    @auth_manager.require_role('viewer')
    def cache_stats_web():
        """Get cache statistics, held to the rule of the API's twin: a key
        restricted to domains gets the entries for certificates its scope covers."""
        try:
            scope = (getattr(request, 'current_user', None) or {}).get('allowed_domains')
            visible = None if scope is None else (
                lambda domain: managers['certificates'].every_name_matches(
                    domain, lambda name: auth_manager.domain_matches_scope(name, scope)))
            return jsonify(cache_manager.get_cache_stats(visible))
        except Exception as e:
            logger.error("Failed to get cache stats: %s", e)
            return jsonify({'error': 'Failed to get cache stats'}), 500

    @app.route('/api/web/cache/clear', methods=['POST'])
    @auth_manager.require_role('admin')
    def cache_clear_web():
        """Clear cache"""
        try:
            cache_manager.clear_cache()
            return jsonify({'message': 'Cache cleared'})
        except Exception as e:
            logger.error("Failed to clear cache: %s", e)
            return jsonify({'error': 'Failed to clear cache'}), 500
