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

def register_misc_routes(app, managers, require_web_auth, auth_manager):
    @app.route('/api/activity')
    @auth_manager.require_role('viewer')
    def activity_api():
        """Get recent audit log entries."""
        audit_logger = managers.get('audit')
        if not audit_logger:
            return jsonify({'entries': []})
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 500)
        entries = audit_logger.get_recent_entries(limit=limit)
        # Return newest first
        entries.reverse()
        return jsonify({'entries': entries})

    @app.route('/api/notifications/config', methods=['GET', 'POST'])
    @auth_manager.require_role('viewer')
    def notifications_config():
        """Get or update notification configuration."""
        if request.method == 'POST':
            user = getattr(request, 'current_user', {})
            if ROLE_HIERARCHY.get(user.get('role'), -1) < ROLE_HIERARCHY['admin']:
                return jsonify({'error': 'admin privileges required', 'code': 'INSUFFICIENT_ROLE'}), 403
        settings = settings_manager.load_settings()

        if request.method == 'GET':
            notif_config = settings.get('notifications', {})
            # Strip passwords from response
            safe = json.loads(json.dumps(notif_config))
            smtp = safe.get('channels', {}).get('smtp', {})
            if smtp.get('password'):
                smtp['password'] = '••••••••'
            for wh in safe.get('channels', {}).get('webhooks', []):
                if wh.get('secret'):
                    wh['secret'] = '••••••••'
            return jsonify(safe)

        # POST — update notification config
        data = request.get_json(silent=True) or {}
        settings['notifications'] = data
        settings_manager.save_settings(settings)
        return jsonify({'status': 'saved'})

    @app.route('/api/notifications/test', methods=['POST'])
    @auth_manager.require_role('operator')
    def notifications_test():
        """Test a notification channel."""
        notifier = managers.get('notifier')
        if not notifier:
            return jsonify({'error': 'Notifier not available'}), 500
        data = request.get_json(silent=True) or {}
        channel_type = data.get('channel_type', '')
        config = data.get('config', {})
        result = notifier.test_channel(channel_type, config)
        return jsonify(result)

    @app.route('/api/webhooks/deliveries')
    @auth_manager.require_role('viewer')
    def webhook_deliveries():
        """Return recent webhook delivery log entries."""
        notifier = managers.get('notifier')
        if not notifier:
            return jsonify({'error': 'Notifier not available'}), 500
        limit = request.args.get('limit', 50, type=int)
        limit = min(max(limit, 1), 200)
        return jsonify(notifier.get_deliveries(limit=limit))

    # --- Deploy Hooks endpoints ---

    @app.route('/api/deploy/config', methods=['GET', 'POST'])
    @auth_manager.require_role('admin')
    def deploy_config():
        """Get or update deploy hooks configuration."""
        deploy_manager = managers.get('deployer')
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 500

        if request.method == 'GET':
            return jsonify(deploy_manager.get_config())

        data = request.get_json(silent=True) or {}
        if deploy_manager.save_config(data):
            return jsonify({'status': 'saved'})
        return jsonify({'error': 'Invalid configuration'}), 400

    @app.route('/api/deploy/test/<string:hook_id>', methods=['POST'])
    @auth_manager.require_role('admin')
    def deploy_test_hook(hook_id):
        """Dry-run test a deploy hook."""
        deploy_manager = managers.get('deployer')
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 500
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', 'test.example.com')
        result = deploy_manager.test_hook(hook_id, domain=domain)
        if result.get('error') and 'not found' in result.get('error', '').lower():
            return jsonify(result), 404
        return jsonify(result)

    @app.route('/api/deploy/history')
    @auth_manager.require_role('admin')
    def deploy_history():
        """Return recent deploy hook execution history."""
        deploy_manager = managers.get('deployer')
        if not deploy_manager:
            return jsonify({'error': 'Deploy manager not available'}), 500
        limit = request.args.get('limit', 50, type=int)
        limit = min(max(limit, 1), 200)
        domain = request.args.get('domain')
        return jsonify(deploy_manager.get_history(limit=limit, domain=domain))

    @app.route('/api/digest/send', methods=['POST'])
    @auth_manager.require_role('admin')
    def send_digest():
        """Send weekly digest email on demand."""
        digest_manager = managers.get('digest')
        if not digest_manager:
            return jsonify({'error': 'Digest not available'}), 500
        result = digest_manager.send()
        if result.get('error'):
            return jsonify(result), 500
        return jsonify(result)

    @app.route('/api/digest/preview')
    @auth_manager.require_role('viewer')
    def preview_digest():
        """Preview weekly digest data without sending."""
        digest_manager = managers.get('digest')
        if not digest_manager:
            return jsonify({'error': 'Digest not available'}), 500
        return jsonify(digest_manager.build_digest())

    @app.route('/api/events/stream')
    @auth_manager.require_role('viewer')
    def event_stream():
        """SSE endpoint for real-time updates."""
        event_bus = managers.get('events')
        if not event_bus:
            return jsonify({'error': 'Event bus not available'}), 500
        q = event_bus.subscribe()
        return Response(
            stream_with_context(event_bus.stream(q)),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )

    # Health check for Docker
    @app.route('/health')
    def health_check():
        """Simple health check endpoint"""
        try:
            from app import __version__
            settings = settings_manager.load_settings()
            return jsonify({
                'status': 'healthy',
                'version': __version__,
                'timestamp': str(datetime.now())
            })
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({'status': 'unhealthy'}), 500

    # Prometheus metrics endpoint (requires auth to prevent info disclosure)
    @app.route('/metrics')
    @auth_manager.require_role('viewer')
    def metrics():
        """Prometheus metrics endpoint"""
        try:
            return generate_metrics_response()
        except Exception as e:
            logger.error(f"Error generating metrics: {e}")
            return "# Error generating metrics\n", 500

