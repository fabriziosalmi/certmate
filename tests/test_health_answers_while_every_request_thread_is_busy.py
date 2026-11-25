"""/health answers on a thread of its own, and says when requests stop moving (#1463).

With the image's 8 gunicorn threads all held by slow listings, `curl -f
/health` waited for one of them; past its 10-second timeout Docker counted a
failure, and three made the container `unhealthy` while every check was fine.
Measured on 2026-11-25: 8 cold listings of 2,000 certificates held the 8 threads
for 45 s each, and /health on the request port timed out at 30 s.

So the health report is also served on `HEALTH_PORT` by a small server on its
own thread, which no request can take. A health check that always answers
would hide a server whose threads are stuck for good, so the report also says
whether requests still move: when every request thread has been busy and none
has finished for `CERTMATE_HEALTH_STALL_SECONDS`, it answers 503 "unhealthy",
and a supervisor restarts what is really stuck.
"""
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from modules.core.health_server import start_health_server
from modules.core.request_progress import RequestProgress

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _get(port, path='/health', timeout=5):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}{path}', timeout=timeout) as r:
            return r.status, json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'null')


# --- what "requests still move" means ------------------------------------

def test_a_server_with_a_free_thread_is_not_stalled():
    clock = Clock()
    progress = RequestProgress(threads=2, stall_seconds=60, clock=clock)
    progress.started()
    clock.now += 3600
    assert progress.state()['stalled'] is False


def test_every_thread_busy_and_nothing_finished_for_the_stall_time_is_stalled():
    clock = Clock()
    progress = RequestProgress(threads=2, stall_seconds=60, clock=clock)
    progress.started()
    progress.started()
    clock.now += 59
    assert progress.state()['stalled'] is False
    clock.now += 2
    assert progress.state()['stalled'] is True


def test_a_request_that_finishes_while_all_are_busy_counts_as_movement():
    clock = Clock()
    progress = RequestProgress(threads=2, stall_seconds=60, clock=clock)
    for _ in range(3):
        progress.started()
    clock.now += 50
    progress.finished()          # still 2 in flight: busy, but moving
    clock.now += 50
    assert progress.state()['stalled'] is False
    clock.now += 11
    assert progress.state()['stalled'] is True


def test_a_thread_coming_free_ends_the_stall():
    clock = Clock()
    progress = RequestProgress(threads=2, stall_seconds=10, clock=clock)
    progress.started()
    progress.started()
    clock.now += 11
    assert progress.state()['stalled'] is True
    progress.finished()
    assert progress.state()['stalled'] is False
    assert progress.state()['in_flight'] == 1


def test_a_streamed_response_holds_its_thread_until_it_is_closed():
    progress = RequestProgress(threads=8, stall_seconds=60)

    def app(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/event-stream')])
        return iter([b'data: 1\n\n', b'data: 2\n\n'])

    body = progress.wrap(app)({}, lambda *a: None)
    next(iter(body))
    assert progress.state()['in_flight'] == 1
    body.close()
    assert progress.state()['in_flight'] == 0


def test_a_request_that_raises_still_gives_its_thread_back():
    progress = RequestProgress(threads=8, stall_seconds=60)

    def app(environ, start_response):
        raise RuntimeError('boom')

    with pytest.raises(RuntimeError):
        progress.wrap(app)({}, lambda *a: None)
    assert progress.state()['in_flight'] == 0


def test_the_default_stall_time_is_longer_than_any_request_gunicorn_allows(monkeypatch):
    """A request may take up to GUNICORN_TIMEOUT by design (DNS-01 waits for
    propagation): eight of them at once are slow, not stuck, and a restart in
    the middle would throw their work away."""
    from modules.core.request_progress import configured_stall_seconds
    monkeypatch.delenv('CERTMATE_HEALTH_STALL_SECONDS', raising=False)
    monkeypatch.setenv('GUNICORN_TIMEOUT', '300')
    assert configured_stall_seconds() == 360
    monkeypatch.setenv('GUNICORN_TIMEOUT', '900')
    assert configured_stall_seconds() == 960
    monkeypatch.delenv('GUNICORN_TIMEOUT')
    assert configured_stall_seconds() == 360
    monkeypatch.setenv('CERTMATE_HEALTH_STALL_SECONDS', '45')
    assert configured_stall_seconds() == 45


# --- the server on its own thread ----------------------------------------

def test_the_health_port_answers_the_report_and_nothing_else():
    server = start_health_server(lambda: ({'status': 'healthy'}, 200), '127.0.0.1', 0)
    try:
        port = server.server_address[1]
        assert _get(port) == (200, {'status': 'healthy'})
        assert _get(port, '/health?x=1') == (200, {'status': 'healthy'})
        assert _get(port, '/api/certificates')[0] == 404
    finally:
        server.shutdown()


def test_the_health_port_says_503_when_the_report_does():
    server = start_health_server(lambda: ({'status': 'unhealthy'}, 503), '127.0.0.1', 0)
    try:
        assert _get(server.server_address[1]) == (503, {'status': 'unhealthy'})
    finally:
        server.shutdown()


def test_a_client_that_sends_nothing_does_not_hold_the_health_port():
    """One server thread: a connection that never sends a request must be
    dropped, or it would be the next thing that makes /health time out."""
    server = start_health_server(lambda: ({'status': 'healthy'}, 200), '127.0.0.1', 0)
    port = server.server_address[1]
    idle = socket.create_connection(('127.0.0.1', port))
    try:
        started = time.monotonic()
        status, _ = _get(port, timeout=10)
        assert status == 200 and time.monotonic() - started < 8
    finally:
        # Closed before the shutdown, so a server that did wait on it is
        # released and this test fails instead of hanging.
        idle.close()
        server.shutdown()


# --- the whole app: a busy server, a stuck one ----------------------------

@pytest.fixture
def instance(tmp_path, monkeypatch):
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('HEALTH_PORT', '0')
    monkeypatch.setenv('HEALTH_HOST', '127.0.0.1')
    monkeypatch.setenv('GUNICORN_THREADS', '2')
    monkeypatch.setenv('CERTMATE_HEALTH_STALL_SECONDS', '10')
    from modules.factory import create_app, stop_background_work
    app, container = create_app()
    yield app, container
    stop_background_work(container)


def test_the_health_port_answers_while_every_request_thread_is_held(instance):
    _app, container = instance
    server = container.managers['health_server']
    progress = container.managers['request_progress']
    release = threading.Event()

    def slow(environ, start_response):
        assert release.wait(30)
        start_response('200 OK', [])
        return [b'']

    held = progress.wrap(slow)
    threads = [threading.Thread(target=lambda: list(held({}, lambda *a: None))) for _ in range(2)]
    for thread in threads:
        thread.start()
    try:
        deadline = time.monotonic() + 5
        while progress.state()['in_flight'] < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        started = time.monotonic()
        status, body = _get(server.server_address[1])
        assert time.monotonic() - started < 2
        assert status == 200 and body['checks']['requests'] == 'progressing'
        assert body['checks']['requests_in_flight'] == 2
    finally:
        release.set()
        for thread in threads:
            thread.join(10)


def test_a_server_whose_threads_are_stuck_is_reported_unhealthy(instance, monkeypatch):
    _app, container = instance
    server = container.managers['health_server']
    progress = container.managers['request_progress']
    clock = Clock()
    monkeypatch.setattr(progress, '_clock', clock)
    progress.started()
    progress.started()
    clock.now += 11
    status, body = _get(server.server_address[1])
    assert status == 503
    assert body['status'] == 'unhealthy' and body['checks']['requests'] == 'stalled'
    progress.finished()
    progress.finished()
    status, body = _get(server.server_address[1])
    assert status == 200 and body['checks']['requests'] == 'progressing'


def test_the_health_port_never_shows_a_reason(instance):
    """The health port has no request, so no credentials: like an anonymous
    caller of /health (#1150), it gets the pointer to the log, never the
    certbot or scheduler error itself."""
    from modules.web.misc_routes import REASON_WITHHELD
    _app, container = instance
    reason = '/opt/venv/bin/certbot: exited 1: ImportError in /opt/venv/lib/python3.12'
    container.managers['issuance_status'] = {'state': 'failed', 'error': reason}
    container.managers['shell_executor'] = None
    container.managers['scheduler'] = None
    container.managers['scheduler_status'] = {'state': 'failed', 'error': reason, 'timestamp': 't'}
    status, body = _get(container.managers['health_server'].server_address[1])
    assert status == 200
    assert body['checks']['certbot_error'] == REASON_WITHHELD
    assert body['checks']['scheduler_error'] == REASON_WITHHELD
    assert reason not in json.dumps(body)


def test_the_request_port_health_says_the_same(instance, monkeypatch):
    app, container = instance
    progress = container.managers['request_progress']
    clock = Clock()
    monkeypatch.setattr(progress, '_clock', clock)
    with app.test_client() as client:
        response = client.get('/health')
        assert response.status_code == 200
        assert response.get_json()['checks']['requests'] == 'progressing'
        progress.started()
        progress.started()
        clock.now += 11
        response = client.get('/health')
        assert response.status_code == 503
        assert response.get_json()['status'] == 'unhealthy'


def test_without_health_port_no_second_server_starts(tmp_path, monkeypatch):
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.delenv('HEALTH_PORT', raising=False)
    from modules.factory import create_app, stop_background_work
    _app, container = create_app()
    try:
        assert container.managers.get('health_server') is None
    finally:
        stop_background_work(container)


# --- every supervisor the repo ships asks the health port ------------------

def test_the_image_checks_its_health_on_the_health_port():
    dockerfile = (REPO / 'Dockerfile').read_text()
    assert 'ENV HEALTH_PORT=8001' in dockerfile
    healthcheck = dockerfile[dockerfile.index('HEALTHCHECK'):].split('\n\n')[0]
    assert '${HEALTH_PORT}/health' in healthcheck
    assert '--threads ${GUNICORN_THREADS}' in dockerfile


@pytest.mark.parametrize('compose', ['docker-compose.yml', 'deploy/docker-compose.yml'])
def test_the_compose_files_check_the_health_port(compose):
    text = (REPO / compose).read_text()
    service = text[text.index('certmate'):]
    at = service.index('healthcheck:')
    healthcheck = service[at:at + 300]
    assert ':8001/health' in healthcheck or '${HEALTH_PORT' in healthcheck


def test_the_chart_probes_the_health_port():
    deployment = (REPO / 'charts' / 'certmate' / 'templates' / 'deployment.yaml').read_text()
    for probe in ('livenessProbe', 'readinessProbe'):
        block = deployment[deployment.index(probe):deployment.index(probe) + 200]
        assert 'port: health' in block, probe
    assert 'name: health' in deployment
