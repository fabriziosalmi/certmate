from flask import request, jsonify


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
        except Exception as e:
            return jsonify({'error': 'Failed to list backups'}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    @auth_manager.require_role('admin')
    def create_backup_web():
        """Create a new backup"""
        try:
            data = request.json or {}
            backup_type = data.get('type', 'full')
            filename = file_ops.create_backup(backup_type)
            return jsonify({'message': 'Backup created', 'filename': filename})
        except Exception as e:
            return jsonify({'error': 'Backup creation failed'}), 500

    @app.route('/api/cache/stats', methods=['GET'])
    @app.route('/api/web/cache/stats', methods=['GET'])
    @auth_manager.require_role('viewer')
    def cache_stats_web():
        """Get cache statistics"""
        try:
            stats = cache_manager.get_cache_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': 'Failed to get cache stats'}), 500

    @app.route('/api/cache/clear', methods=['POST'])
    @app.route('/api/web/cache/clear', methods=['POST'])
    @auth_manager.require_role('admin')
    def cache_clear_web():
        """Clear cache"""
        try:
            cache_manager.clear_cache()
            return jsonify({'message': 'Cache cleared'})
        except Exception as e:
            return jsonify({'error': 'Failed to clear cache'}), 500
