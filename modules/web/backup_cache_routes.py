from flask import request, jsonify
from modules.core.request_fields import json_booleans


def register_backup_cache_routes(app, managers, require_web_auth,
                                 auth_manager, file_ops, settings_manager,
                                 cache_manager):
    """Register backup and cache related routes"""

    @app.route('/api/web/backups', methods=['GET'])
    @auth_manager.require_role('admin')
    def list_backups_web():
        """List all backups"""
        try:
            backups = file_ops.list_backups()
            return jsonify(backups)
        except Exception:
            return jsonify({'error': 'Failed to list backups'}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    @auth_manager.require_role('admin')
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
            return jsonify({
                'message': 'Backup created',
                'filename': filename,
                'secrets_masked': not include_secrets,
            })
        except Exception:
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
        """Get cache statistics"""
        try:
            stats = cache_manager.get_cache_stats()
            return jsonify(stats)
        except Exception:
            return jsonify({'error': 'Failed to get cache stats'}), 500

    @app.route('/api/web/cache/clear', methods=['POST'])
    @auth_manager.require_role('admin')
    def cache_clear_web():
        """Clear cache"""
        try:
            cache_manager.clear_cache()
            return jsonify({'message': 'Cache cleared'})
        except Exception:
            return jsonify({'error': 'Failed to clear cache'}), 500
