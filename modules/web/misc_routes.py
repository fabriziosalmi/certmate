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
        return jsonify({
            'status': 'healthy',
            'version': app.config.get('VERSION', 'unknown')
        })

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
