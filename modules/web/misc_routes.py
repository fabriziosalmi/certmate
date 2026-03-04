import logging
from ..core.metrics import generate_metrics_response
from flask import request, jsonify, Response, stream_with_context


logger = logging.getLogger(__name__)


def register_misc_routes(app, managers, require_web_auth, auth_manager):
    """Register miscellaneous routes"""

    @app.route('/api/activity')
    def activity_api():
        """Activity log endpoint"""
        try:
            # Simple activity stream or recent audit logs
            audit_logger = managers['audit']
            logs = audit_logger.get_recent_logs(limit=50)
            return jsonify(logs)
        except Exception as e:
            logger.error(f"Activity API error: {e}")
            return jsonify({'error': 'Failed to fetch activity'}), 500

    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        try:
            return generate_metrics_response()
        except Exception as e:
            logger.error(f"Metrics error: {e}")
            return "Internal Server Error", 500

    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'version': app.config.get('VERSION', 'unknown')
        })

    @app.route('/api/web/logs/stream')
    def stream_logs():
        """Stream application logs"""
        def generate():
            log_file = managers['file_ops'].logs_dir / 'certmate.log'
            if log_file.exists():
                with open(log_file, 'r') as f:
                    # Seek to end
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
            limit = request.args.get('limit', 100, type=int)
            audit_logger = managers['audit']
            logs = audit_logger.get_recent_logs(limit=limit)
            return jsonify(logs)
        except Exception as e:
            logger.error(f"Audit log fetch failed: {e}")
            return jsonify({'error': 'Failed to fetch audit logs'}), 500
