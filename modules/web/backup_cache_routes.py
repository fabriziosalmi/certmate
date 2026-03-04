import json
import logging
import os
import re
import tempfile
import zipfile
import concurrent.futures
from datetime import datetime
from functools import wraps
from pathlib import Path
from collections import defaultdict
from time import time
from flask import render_template, request, jsonify, send_file, send_from_directory, redirect, url_for, after_this_request, Response, stream_with_context

logger = logging.getLogger(__name__)

def register_backup_cache_routes(app, managers, require_web_auth, auth_manager, file_ops, settings_manager, cache_manager):
    # Backup management endpoints
    @app.route('/api/web/backups')
    @auth_manager.require_role('viewer')
    def web_list_backups():
        """Web interface endpoint to list backups"""
        try:
            backups = file_ops.list_backups()
            return jsonify(backups)
        except Exception as e:
            logger.error(f"Error listing backups via web: {e}")
            return jsonify({'error': 'Failed to list backups'}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    @auth_manager.require_role('admin')
    def web_create_backup():
        """Web interface endpoint to create backup"""
        try:
            data = request.json or {}
            backup_type = data.get('type', 'unified')
            reason = data.get('reason', 'manual')
            
            created_backups = []
            
            # Only create unified backups
            settings = settings_manager.load_settings()
            filename = file_ops.create_unified_backup(settings, reason)
            if filename:
                created_backups.append({'type': 'unified', 'filename': filename})
            
            if created_backups:
                return jsonify({
                    'success': True,
                    'message': 'Backup created successfully',
                    'backups': created_backups
                })
            else:
                return jsonify({'error': 'Failed to create backup'}), 500
                
        except Exception as e:
            logger.error(f"Error creating backup via web: {e}")
            return jsonify({'error': 'Failed to create backup'}), 500

    @app.route('/api/web/backups/download/<backup_type>/<filename>')
    @auth_manager.require_role('admin')
    def web_download_backup(backup_type, filename):
        """Web interface endpoint to download unified backup"""
        try:
            if backup_type != 'unified':
                return jsonify({'error': 'Only unified backup download is supported'}), 400

            # Validate filename — reject path traversal attempts
            if '..' in filename or '/' in filename or '\\' in filename or '\x00' in filename:
                return jsonify({'error': 'Invalid filename'}), 400
            if not filename.endswith('.zip'):
                return jsonify({'error': 'Invalid backup file format'}), 400

            backup_path = Path(file_ops.backup_dir) / backup_type / filename

            if not backup_path.exists():
                return jsonify({'error': 'Backup file not found'}), 404

            # Security check — resolved path must stay within backup_dir
            if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                return jsonify({'error': 'Access denied'}), 403
            
            return send_file(
                backup_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
            
        except Exception as e:
            logger.error(f"Error downloading backup via web: {e}")
            return jsonify({'error': 'Failed to download backup'}), 500

    # Cache management endpoints
    @app.route('/api/web/cache/stats')
    @auth_manager.require_role('viewer')
    def web_cache_stats():
        """Web interface endpoint to get cache statistics"""
        try:
            stats = cache_manager.get_cache_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error getting cache stats for web: {e}")
            return jsonify({'error': 'Failed to get cache statistics'}), 500

    @app.route('/api/web/cache/clear', methods=['POST'])
    @auth_manager.require_role('admin')
    def web_cache_clear():
        """Web interface endpoint to clear cache"""
        try:
            cleared_count = cache_manager.clear_cache()
            return jsonify({
                'success': True,
                'message': 'Cache cleared successfully',
                'cleared_entries': cleared_count
            })
        except Exception as e:
            logger.error(f"Error clearing cache for web: {e}")
            return jsonify({'error': 'Failed to clear cache'}), 500
