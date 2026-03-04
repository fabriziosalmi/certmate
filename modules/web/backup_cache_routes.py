from flask import request, jsonify


def register_backup_cache_routes(app, managers, require_web_auth,
                                 auth_manager, file_ops, settings_manager,
                                 cache_manager):
    """Register backup and cache related routes"""

    @app.route('/api/web/backups', methods=['GET'])
    def list_backups_web():
        """List all backups"""
        try:
            backups = file_ops.list_backups()
            return jsonify(backups)
        except Exception as e:
            return jsonify({'error': f"Failed to list backups: {e}"}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    def create_backup_web():
        """Create a new backup"""
        try:
            data = request.json
            backup_type = data.get('type', 'full')
            filename = file_ops.create_backup(backup_type)
            return jsonify({'message': 'Backup created', 'filename': filename})
        except Exception as e:
            return jsonify({'error': f"Backup creation failed: {e}"}), 500

    @app.route('/api/cache/stats', methods=['GET'])
    @app.route('/api/web/cache/stats', methods=['GET'])
    def cache_stats_web():
        """Get cache statistics"""
        try:
            stats = cache_manager.get_cache_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': f"Failed to get cache stats: {e}"}), 500

    @app.route('/api/cache/clear', methods=['POST'])
    @app.route('/api/web/cache/clear', methods=['POST'])
    def cache_clear_web():
        """Clear cache"""
        try:
            cache_manager.clear_cache()
            return jsonify({'message': 'Cache cleared'})
        except Exception as e:
            return jsonify({'error': f"Failed to clear cache: {e}"}), 500
