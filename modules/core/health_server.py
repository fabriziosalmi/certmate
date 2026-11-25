"""The health report on a port of its own, served by a thread no request can take (#1463).

gunicorn runs the app on a fixed number of threads. When slow requests hold
all of them, `/health` on the request port waits like any other request, and a
healthcheck with a 10-second timeout counts the wait as a failure: measured on
2026-11-25, 8 overlapping cold listings of 2,000 certificates held the image's
8 threads for 45 s, and /health timed out. This server answers `GET /health`
only, on `HEALTH_PORT`, with the same report.

One thread, one request at a time, and a short socket timeout: a probe is
small and quick, and a client that connects and sends nothing is dropped
instead of holding the one thread. The report is built without a request, so
it is the anonymous one: reasons are withheld as for any caller without
credentials.
"""
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

logger = logging.getLogger(__name__)

# Seconds a connection may take to send its request line and headers.
REQUEST_TIMEOUT_SECONDS = 3


class _HealthHandler(BaseHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT_SECONDS
    server_version = 'CertMate-health'
    sys_version = ''

    def do_GET(self):
        if self.path.split('?', 1)[0] != '/health':
            self._send(404, {'error': 'Only /health is served on this port'})
            return
        body, status = self.server.report()
        self._send(status, body)

    def _send(self, status, body):
        payload = json.dumps(body).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # a probe every few seconds is not news
        pass


class _HealthServer(HTTPServer):
    def __init__(self, address, report):
        self.report = report
        super().__init__(address, _HealthHandler)


def start_health_server(report, host, port):
    """Serve ``report()`` (a ``(body, status)`` pair) at ``GET /health`` on
    *host*:*port* from a daemon thread, and return the server; its
    ``server_address`` holds the port when *port* is 0."""
    server = _HealthServer((host, port), report)
    thread = threading.Thread(target=server.serve_forever, name='health-server', daemon=True)
    thread.start()
    return server
