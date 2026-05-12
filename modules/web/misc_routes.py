import logging
from ..core.metrics import generate_metrics_response
from flask import request, jsonify, Response, stream_with_context


logger = logging.getLogger(__name__)


def register_misc_routes(app, managers, require_web_auth, auth_manager):
    """Register miscellaneous routes"""

    @app.route('/api/activity')
    @auth_manager.require_role('viewer')
    def activity_api():
        """Activity log endpoint"""
        try:
            audit_logger = managers['audit']
            logs = audit_logger.get_recent_entries(limit=50)
            return jsonify(logs)
        except Exception as e:
            logger.error(f"Activity API error: {e}")
            return jsonify({'error': 'Failed to fetch activity'}), 500

    @app.route('/metrics')
    @auth_manager.require_role('admin')
    def metrics():
        """Prometheus metrics endpoint"""
        try:
            return generate_metrics_response()
        except Exception as e:
            logger.error(f"Metrics error: {e}")
            return jsonify({'error': 'Internal Server Error'}), 500

    @app.route('/health')
    def health_check():
        """Health check endpoint — intentionally public for load balancers"""
        import shutil
        checks = {}
        overall = 'healthy'

        # Scheduler
        scheduler = managers.get('scheduler')
        checks['scheduler'] = 'running' if (scheduler and scheduler.running) else 'not_running'
        if checks['scheduler'] != 'running':
            overall = 'degraded'

        # Cert directory
        file_ops = managers.get('file_ops')
        if file_ops:
            cert_dir_ok = file_ops.cert_dir.exists()
            checks['cert_dir'] = 'ok' if cert_dir_ok else 'missing'
            if not cert_dir_ok:
                overall = 'degraded'

            # Disk space (warn if less than 100 MB free)
            try:
                usage = shutil.disk_usage(str(file_ops.cert_dir.parent))
                free_mb = usage.free // (1024 * 1024)
                checks['disk_free_mb'] = free_mb
                if free_mb < 100:
                    checks['disk_space'] = 'low'
                    overall = 'degraded'
                else:
                    checks['disk_space'] = 'ok'
            except Exception:
                checks['disk_space'] = 'unknown'

        # Always return 200 — Flask is serving requests.
        # Load balancers and the conftest health-wait both check for 200.
        # The 'status' field ('healthy'/'degraded') is for monitoring systems.
        return jsonify({
            'status': overall,
            'version': app.config.get('VERSION', 'unknown'),
            'checks': checks
        })

    @app.route('/api/events/stream')
    def events_stream():
        """SSE: stream certificate lifecycle events to authenticated browsers.

        SSE cannot send custom headers, so this only accepts the cookie session.
        When local auth is enabled and the request has no valid session, this
        returns a 401 JSON error and does not expose the event stream.
        """
        from flask import Response, stream_with_context, request as _req
        if auth_manager.is_local_auth_enabled() and auth_manager.has_any_users():
            session_id = _req.cookies.get('certmate_session')
            if not session_id or not auth_manager.validate_session(session_id):
                return jsonify({'error': 'Unauthenticated'}), 401
        event_bus = managers.get('events')
        if event_bus is None:
            return jsonify({'error': 'Event bus not available'}), 503
        q = event_bus.subscribe()
        return Response(
            stream_with_context(event_bus.stream(q)),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
        )

    @app.route('/api/web/logs/stream')
    @auth_manager.require_role('admin')
    def stream_logs():
        """Stream application logs — admin only (logs may contain credentials)"""
        def generate():
            log_file = managers['file_ops'].logs_dir / 'certmate.log'
            if log_file.exists():
                with open(log_file, 'r') as f:
                    f.seek(0, 2)
                    while True:
                        line = f.readline()
                        if line:
                            yield f"data: {line}\n\n"
            else:
                yield "data: Log file not found\n\n"

        return Response(stream_with_context(generate()),
                        mimetype='text/event-stream')

    # ------------------------------------------------------------------ #
    # Notifications + digest + webhook deliveries (#114)                  #
    # ------------------------------------------------------------------ #
    # The frontend (settings-notifications.js) was calling these but the
    # routes weren't registered, so users always saw 404 in the network
    # tab and notification settings couldn't be saved from the UI. The
    # backend logic (Notifier, WeeklyDigest) was already complete — this
    # just surfaces it.

    @app.route('/api/notifications/config', methods=['GET', 'POST'])
    @auth_manager.require_role('admin')
    def api_notifications_config():
        """Get or replace the notifications config block."""
        notifier = managers.get('notifier')
        settings_manager = managers.get('settings')
        if notifier is None or settings_manager is None:
            return jsonify({'error': 'Notifier not available'}), 503

        if request.method == 'GET':
            try:
                return jsonify(notifier._get_config())
            except Exception as e:
                logger.error(f"Failed to read notifications config: {e}")
                return jsonify({'error': 'Failed to read notifications config'}), 500

        try:
            data = request.json or {}
            if not isinstance(data, dict):
                return jsonify({'error': 'Body must be a JSON object'}), 400

            def _mutator(s):
                s['notifications'] = data
                return s

            settings_manager.update(_mutator)
            audit_logger = managers.get('audit')
            if audit_logger:
                actor = getattr(request, 'current_user', {}) or {}
                # Channel credentials (Slack/Discord webhook URLs, SMTP
                # passwords) ride inside `data`; record only the set of
                # configured channels, not their secrets.
                channels = sorted(k for k in data.keys() if isinstance(data.get(k), dict))
                audit_logger.log_operation(
                    operation='update',
                    resource_type='notifications_config',
                    resource_id='notifications',
                    status='success',
                    details={'channels_present': channels},
                    user=actor.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'message': 'Notification settings saved'})
        except Exception as e:
            logger.error(f"Failed to save notifications config: {e}")
            return jsonify({'error': 'Failed to save notifications config'}), 500

    @app.route('/api/notifications/test', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_notifications_test():
        """Send a test message through one channel without persisting anything."""
        notifier = managers.get('notifier')
        if notifier is None:
            return jsonify({'error': 'Notifier not available'}), 503
        try:
            data = request.json or {}
            channel_type = data.get('channel_type')
            config = data.get('config') or {}
            if not channel_type:
                return jsonify({'error': 'channel_type is required'}), 400
            if not isinstance(config, dict):
                return jsonify({'error': 'config must be a JSON object'}), 400

            result = notifier.test_channel(channel_type, config)
            # test_channel returns {error: ...} or {success: True, status: ...}
            success = 'error' not in result
            return jsonify({'success': success, **result})
        except Exception as e:
            logger.error(f"Notification test failed: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/digest/send', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_digest_send():
        """Manually trigger the weekly digest. Returns the WeeklyDigest.send() result."""
        digest = managers.get('digest')
        if digest is None:
            return jsonify({'error': 'Digest not available'}), 503
        try:
            result = digest.send()
            # send() returns either {success: True, ...} or {skipped: '...'} or {error: ...}
            return jsonify(result)
        except Exception as e:
            logger.error(f"Digest send failed: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/webhooks/deliveries', methods=['GET'])
    @auth_manager.require_role('admin')
    def api_webhook_deliveries():
        """Recent webhook delivery log entries, newest first."""
        notifier = managers.get('notifier')
        if notifier is None:
            return jsonify({'error': 'Notifier not available'}), 503
        try:
            limit = min(max(request.args.get('limit', 50, type=int), 1), 500)
            return jsonify(notifier.get_deliveries(limit=limit))
        except Exception as e:
            logger.error(f"Webhook deliveries fetch failed: {e}")
            return jsonify({'error': 'Failed to read webhook deliveries'}), 500

    @app.route('/api/web/audit-logs', methods=['GET'])
    @auth_manager.require_role('admin')
    def get_audit_logs():
        """Get audit logs"""
        try:
            limit = min(max(request.args.get('limit', 100, type=int), 1), 1000)
            audit_logger = managers['audit']
            logs = audit_logger.get_recent_entries(limit=limit)
            return jsonify(logs)
        except Exception as e:
            logger.error(f"Audit log fetch failed: {e}")
            return jsonify({'error': 'Failed to fetch audit logs'}), 500
