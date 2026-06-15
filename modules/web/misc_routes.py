import logging
from ..core.metrics import generate_metrics_response
from flask import request, jsonify, Response, stream_with_context


logger = logging.getLogger(__name__)


def register_misc_routes(app, managers, require_web_auth, auth_manager):
    """Register miscellaneous routes"""

    @app.route('/api/activity')
    @auth_manager.require_role('viewer')
    def activity_api():
        """Activity log endpoint.

        Honors ``?limit=N`` from the query string, bounded to [1, 500]
        so the client can implement Load-more pagination without hitting
        an unbounded read on a large audit log. Response is shaped as
        ``{entries, count, limit}`` so the client can decide whether to
        offer a "Load more" affordance (entries.length >= limit
        ⇒ there may be more).
        """
        try:
            raw_limit = request.args.get('limit', 100)
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                limit = 100
            limit = max(1, min(limit, 500))

            audit_logger = managers['audit']
            logs = audit_logger.get_recent_entries(limit=limit)
            return jsonify({
                'entries': logs,
                'count': len(logs),
                'limit': limit,
            })
        except Exception as e:
            logger.error(f"Activity API error: {e}")
            return jsonify({'error': 'Failed to fetch activity'}), 500

    @app.route('/api/audit/verify')
    @auth_manager.require_role('admin')
    def audit_verify_api():
        """Verify the tamper-evident audit hash chain.

        Read-only integrity check: recomputes the SHA-256 chain and reports
        whether it is intact or, on the first break, the exact ``seq`` and
        reason (modification / deletion / reorder / truncation). Admin-gated
        because the result and the head hash are sensitive integrity evidence.

        Returns the verifier result plus HTTP 200 when intact and 409 when the
        chain is broken, so an operator (or a monitoring probe) can alert on a
        non-2xx without parsing the body. The honest threat-model caveat (a
        local chain does not bind the operator) is documented in
        ``modules/core/audit_chain.py`` and ``docs/compliance.md``.
        """
        try:
            audit_logger = managers.get('audit')
            if audit_logger is None or not hasattr(audit_logger, 'verify_chain'):
                return jsonify({'error': 'Audit chain not available'}), 503
            result = audit_logger.verify_chain()
            status = 200 if result.get('ok') else 409
            return jsonify(result), status
        except Exception as e:
            logger.error(f"Audit verify API error: {e}")
            return jsonify({'error': 'Failed to verify audit chain'}), 500

    @app.route('/metrics')
    @auth_manager.require_role('admin')
    def metrics():
        """Prometheus metrics endpoint.

        Builds the collection context from the managers so the certificate,
        DNS-provider and cache gauges are actually populated. Without a
        context, generate_metrics_response only emits application_uptime and
        every labelled inventory metric stays empty ('No data' at scrape).
        """
        try:
            app_context = None
            settings_manager = managers.get('settings')
            file_ops = managers.get('file_ops')
            cert_manager = managers.get('certificates')
            if settings_manager and file_ops and cert_manager:
                try:
                    app_context = {
                        'settings': settings_manager.load_settings(),
                        'cert_dir': file_ops.cert_dir,
                        'get_certificate_info': cert_manager.get_certificate_info,
                        'cache': managers.get('cache'),
                    }
                except Exception as ctx_err:
                    logger.warning(
                        "Metrics context unavailable, emitting base metrics "
                        f"only: {ctx_err}")
            return generate_metrics_response(app_context)
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
        scheduler_status = managers.get('scheduler_status') or {}
        if scheduler and scheduler.running:
            checks['scheduler'] = 'running'
        elif scheduler_status.get('state') == 'failed':
            # Setup raised an exception. Surface the reason so operators can
            # diagnose without grepping logs; without this the /health response
            # collapsed to a bare 'not_running' that hid the actual cause.
            checks['scheduler'] = 'failed'
            checks['scheduler_error'] = scheduler_status.get('error')
            checks['scheduler_failed_at'] = scheduler_status.get('timestamp')
            overall = 'degraded'
        else:
            checks['scheduler'] = 'not_running'
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

    @app.route('/health/ready')
    def readiness_check():
        """Readiness probe for orchestrators (Kubernetes readiness, compose
        healthcheck, deploy gates).

        Distinct from /health on purpose: /health is *liveness* and stays
        200 whenever Flask serves requests, so a load balancer keeps routing
        traffic to a process that is otherwise fine. But if APScheduler — the
        only thing that runs automatic renewals on this single-instance
        build — failed to start, the instance is serving yet quietly never
        renewing anything. That used to be invisible to every probe because
        /health returned 200. This endpoint returns 503 in exactly that case
        so the failure becomes loud: a deploy gate fails, a readiness probe
        flips the pod out of rotation, an alert fires.
        """
        scheduler = managers.get('scheduler')
        scheduler_status = managers.get('scheduler_status') or {}
        running = bool(scheduler and getattr(scheduler, 'running', False))
        ready = running and scheduler_status.get('state') != 'failed'
        body = {
            'ready': ready,
            'scheduler': 'running' if running else (scheduler_status.get('state') or 'not_running'),
        }
        if not ready and scheduler_status.get('error'):
            body['scheduler_error'] = scheduler_status.get('error')
        return jsonify(body), (200 if ready else 503)

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
                # Audit H5: this endpoint previously returned raw
                # `notifications` config including plaintext
                # `smtp_password` + webhook URLs with embedded auth
                # tokens. Now goes through the central masking helper
                # so the response shape matches `/api/web/settings`
                # for the same subtree.
                from modules.core.settings import mask_secrets_in_settings
                raw = notifier._get_config() or {}
                return jsonify(mask_secrets_in_settings(raw))
            except Exception as e:
                logger.error(f"Failed to read notifications config: {e}")
                return jsonify({'error': 'Failed to read notifications config'}), 500

        try:
            data = request.json or {}
            if not isinstance(data, dict):
                return jsonify({'error': 'Body must be a JSON object'}), 400

            # Audit H4 (May 2026): the prior `s['notifications'] = data`
            # wholesale-replaced the subtree. The UI round-trips a GET
            # response — where SMTP `smtp_password` and webhook URLs
            # arrive masked as `'********'` — back into POST, and the
            # plain assignment overwrote real on-disk secrets with the
            # literal sentinel. Strip the sentinel BEFORE the write
            # (same shape PR #215 + audit C2 fix applied elsewhere)
            # and deep-merge against the existing notifications block
            # so a partial UI submit (e.g. toggling `enabled` without
            # re-typing the SMTP password) does not destroy siblings.
            from modules.core.settings import (
                _strip_masked_values, _deep_merge_dict, _restore_masked_list_secrets,
            )
            clean_data = _strip_masked_values(data)

            def _mutator(s):
                existing = s.get('notifications')
                if isinstance(existing, dict) and isinstance(clean_data, dict):
                    merged = _deep_merge_dict(existing, clean_data)
                else:
                    existing = existing if isinstance(existing, dict) else {}
                    merged = clean_data
                # The webhooks list is replaced wholesale by the merge above, so
                # per-channel secrets/tokens the UI sent back masked must be
                # restored from the prior on-disk list (sentinel = unchanged).
                if isinstance(merged, dict):
                    old_ch = existing.get('channels') if isinstance(existing, dict) else None
                    new_ch = merged.get('channels')
                    old_whs = old_ch.get('webhooks') if isinstance(old_ch, dict) else None
                    new_whs = new_ch.get('webhooks') if isinstance(new_ch, dict) else None
                    if isinstance(new_whs, list):
                        _restore_masked_list_secrets(old_whs, new_whs)
                s['notifications'] = merged
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
