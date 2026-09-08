"""A certbot that cannot run must be visible at startup, not at the first renewal.

CertMate drives certbot as a subprocess. It is the one dependency without which
nothing the product exists for works, and it was the one dependency nothing
checked. A broken certbot produced an instance that started, answered `/health`
200 and `/health/ready` 200, scheduled its renewals, and found out at the first
one — hours later, in a log line, on a certificate by then closer to expiry.

The failure is not usually "not installed". Twice on this project it has been:
pip resolves cleanly, the binary is present and executable, and then

    certbot --version

dies on `AttributeError: module 'OpenSSL.crypto' has no attribute 'X509Req'`

because a `cryptography` or `pyOpenSSL` version moved under the pinned ACME
stack. That is why the probe runs the command instead of checking the path —
`os.access` says the installation is fine in exactly that case, which is the
one that has actually happened.

These tests pin the three things that can each independently make the check
worthless: what counts as failure, that the answer reaches `/health/ready`, and
that a probe which never ran is not reported as a probe that failed.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core import issuance_readiness as readiness
from modules.web.misc_routes import register_misc_routes

pytestmark = [pytest.mark.unit]

X509REQ_TRACEBACK = (
    'Traceback (most recent call last):\n'
    '  File "/opt/venv/lib/python3.12/site-packages/acme/crypto_util.py", '
    'line 32, in <module>\n'
    "AttributeError: module 'OpenSSL.crypto' has no attribute 'X509Req'\n")


@pytest.fixture(autouse=True)
def clean_probe():
    """The probe result is process-global on purpose — certbot does not change
    under a running interpreter. Tests must not inherit each other's."""
    readiness.reset()
    yield
    readiness.reset()


def _executor(results):
    """A shell that answers from `results`, keyed by the binary path."""
    calls = []

    class Executor:
        produces_artifacts = True

        def run(self, cmd, **kwargs):
            calls.append((cmd, kwargs))
            answer = results.get(cmd[0])
            if isinstance(answer, Exception):
                raise answer
            return answer

    return Executor(), calls


def _result(returncode=0, stdout='', stderr=''):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


# --- what the probe decides ---------------------------------------------

def test_a_working_certbot_is_ok_and_its_version_is_kept():
    executor, _ = _executor({'.venv/bin/certbot': _result(stdout='certbot 2.10.0\n')})
    status = readiness.probe(executor)

    assert status['state'] == 'ok'
    assert status['version'] == 'certbot 2.10.0'
    assert readiness.is_ready(status)


def test_the_version_is_read_from_stderr_when_that_is_where_it_lands():
    """Older certbot releases print --version to stderr."""
    executor, _ = _executor({'.venv/bin/certbot': _result(stderr='certbot 1.21.0\n')})
    assert readiness.probe(executor)['version'] == 'certbot 1.21.0'


def test_a_certbot_that_starts_and_dies_importing_its_stack_is_a_failure():
    """The failure this exists for. The binary runs; the process exits
    non-zero. A path check calls this installation healthy."""
    executor, _ = _executor({
        '.venv/bin/certbot': _result(returncode=1, stderr=X509REQ_TRACEBACK),
        'certbot': _result(returncode=1, stderr=X509REQ_TRACEBACK),
    })
    status = readiness.probe(executor)

    assert status['state'] == 'failed'
    assert not readiness.is_ready(status)
    assert 'X509Req' in status['error'], (
        'the cause was dropped, so /health says only that something is wrong'
    )


def test_a_missing_certbot_is_a_failure():
    executor, _ = _executor({
        '.venv/bin/certbot': FileNotFoundError('no such file'),
        'certbot': FileNotFoundError('no such file'),
    })
    assert readiness.probe(executor)['state'] == 'failed'


def test_a_certbot_that_cannot_answer_in_time_is_a_failure():
    """A timeout is not "unknown": a certbot that cannot print its version
    inside the bound cannot issue a certificate."""
    import subprocess
    executor, _ = _executor({
        '.venv/bin/certbot': subprocess.TimeoutExpired('certbot', 30),
        'certbot': subprocess.TimeoutExpired('certbot', 30),
    })
    assert readiness.probe(executor)['state'] == 'failed'


def test_exit_zero_with_no_output_is_a_failure_not_a_pass():
    """CONTROL: reading the version out of an empty string and calling that
    success is how a stubbed binary passes this check."""
    executor, _ = _executor({'.venv/bin/certbot': _result(stdout=''),
                             'certbot': _result(stdout='')})
    assert readiness.probe(executor)['state'] == 'failed'


def test_the_path_fallback_is_tried_when_the_venv_copy_is_absent():
    """A source checkout has .venv/bin/certbot; the image has it on PATH."""
    executor, calls = _executor({
        '.venv/bin/certbot': FileNotFoundError('no venv here'),
        'certbot': _result(stdout='certbot 2.10.0\n'),
    })
    assert readiness.probe(executor)['state'] == 'ok'
    assert [c[0][0] for c in calls] == ['.venv/bin/certbot', 'certbot']


def test_the_probe_is_bounded_in_time():
    """Unbounded, a hung certbot hangs startup instead of reporting it."""
    executor, calls = _executor({'.venv/bin/certbot': _result(stdout='certbot 2.10.0')})
    readiness.probe(executor)
    assert calls[0][1]['timeout'] == readiness.PROBE_TIMEOUT_SECONDS


# --- once per process ----------------------------------------------------

def test_the_probe_runs_once_however_many_apps_are_built():
    """certbot does not change under a running interpreter, and the test
    suite builds dozens of applications."""
    executor, calls = _executor({'.venv/bin/certbot': _result(stdout='certbot 2.10.0')})
    readiness.probe(executor)
    readiness.probe(executor)
    readiness.probe(executor)
    assert len(calls) == 1


def test_a_double_that_runs_nothing_is_skipped_not_failed():
    """MockShellExecutor answers from a canned script. Its answer about
    certbot means nothing, and reporting nothing as a failure would take every
    test instance out of rotation."""
    class Mock:
        produces_artifacts = False

        def run(self, cmd, **kwargs):            # pragma: no cover - not called
            raise AssertionError('the probe ran against a non-executing double')

    status = readiness.probe(Mock())
    assert status['state'] == 'skipped'
    assert readiness.is_ready(status)


def test_no_shell_at_all_is_skipped():
    assert readiness.probe(None)['state'] == 'skipped'


def test_before_the_probe_runs_the_state_is_unknown_and_ready():
    """A startup window in which nothing has been measured must not read as a
    failure — otherwise every instance is unready for its first moment."""
    assert readiness.get_status()['state'] == 'unknown'
    assert readiness.is_ready()


# --- the answer has to reach the probes ---------------------------------

def _app(managers):
    app = Flask(__name__)
    app.config['VERSION'] = 'test'
    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    auth.require_session_role = lambda role: (lambda fn: fn)
    auth.is_local_auth_enabled.return_value = False
    auth.has_any_users.return_value = False
    register_misc_routes(app, managers, require_web_auth=None,
                         auth_manager=auth)
    return app


def _running_scheduler():
    scheduler = MagicMock()
    scheduler.running = True
    return scheduler


def test_readiness_is_503_when_certbot_cannot_run():
    """The whole point: an orchestrator takes the instance out of rotation."""
    app = _app({'scheduler': _running_scheduler(),
                'scheduler_status': {'state': 'running'},
                'issuance_status': {'state': 'failed',
                                    'error': "no attribute 'X509Req'"}})
    response = app.test_client().get('/health/ready')

    assert response.status_code == 503
    assert response.get_json()['ready'] is False
    assert response.get_json()['certbot'] == 'failed'
    assert 'X509Req' in response.get_json()['certbot_error']


def test_readiness_is_200_when_certbot_works():
    app = _app({'scheduler': _running_scheduler(),
                'scheduler_status': {'state': 'running'},
                'issuance_status': {'state': 'ok', 'version': 'certbot 2.10.0'}})
    assert app.test_client().get('/health/ready').status_code == 200


def test_readiness_is_200_when_the_probe_was_skipped():
    """CONTROL: a probe that did not run must not fail readiness, or every
    instance built with a shell double is permanently unready."""
    app = _app({'scheduler': _running_scheduler(),
                'scheduler_status': {'state': 'running'},
                'issuance_status': {'state': 'skipped'}})
    assert app.test_client().get('/health/ready').status_code == 200


def test_readiness_is_200_when_nothing_recorded_a_probe_at_all():
    """Backwards compatibility with an app built before this existed."""
    app = _app({'scheduler': _running_scheduler(),
                'scheduler_status': {'state': 'running'}})
    assert app.test_client().get('/health/ready').status_code == 200


def test_a_dead_scheduler_still_fails_readiness_on_its_own():
    """CONTROL: the new condition must be additional, not a replacement."""
    app = _app({'scheduler': None,
                'scheduler_status': {'state': 'failed', 'error': 'boom'},
                'issuance_status': {'state': 'ok'}})
    assert app.test_client().get('/health/ready').status_code == 503


def test_health_reports_certbot_and_degrades_on_failure():
    app = _app({'scheduler': _running_scheduler(),
                'scheduler_status': {'state': 'running'},
                'issuance_status': {'state': 'failed', 'error': 'X509Req'}})
    body = app.test_client().get('/health').get_json()

    assert body['checks']['certbot'] == 'failed'
    assert body['checks']['certbot_error'] == 'X509Req'
    assert body['status'] == 'degraded'


def test_health_reports_the_certbot_version_when_it_works():
    app = _app({'scheduler': _running_scheduler(),
                'scheduler_status': {'state': 'running'},
                'issuance_status': {'state': 'ok', 'version': 'certbot 2.10.0'}})
    body = app.test_client().get('/health').get_json()

    assert body['checks']['certbot'] == 'ok'
    assert body['checks']['certbot_version'] == 'certbot 2.10.0'
    assert body['status'] == 'healthy'


# --- the wiring ----------------------------------------------------------

def test_startup_records_the_probe_where_the_probes_read_it():
    from modules.core import factory

    class Container:
        managers = {'shell_executor': _executor(
            {'.venv/bin/certbot': _result(stdout='certbot 2.10.0')})[0]}

    status = factory.check_issuance_readiness(Container())
    assert status['state'] == 'ok'
    assert Container.managers['issuance_status']['state'] == 'ok'


def test_a_probe_that_itself_explodes_does_not_stop_startup(monkeypatch):
    """CONTROL: a readiness check that can crash the boot is worse than the
    blindness it removes — the instance would not come back at all."""
    from modules.core import factory

    monkeypatch.setattr(readiness, 'probe',
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('x')))

    class Container:
        managers = {'shell_executor': None}

    status = factory.check_issuance_readiness(Container())
    assert status['state'] == 'unknown'
    assert readiness.is_ready(status), (
        'a probe that crashed must not be reported as certbot being broken'
    )
