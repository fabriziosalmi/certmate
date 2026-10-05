"""Outside an e2e test, the suite refuses to run the real certbot.

The guard is `_NoRealCertbot` in conftest.py, put in when the session starts and
left in until the process ends. These tests call the one
launch point the application uses, `ShellExecutor.run`, the way an escaped
issuance would. The command points certbot at a closed port on the loopback
interface, so that if the guard were missing the certbot that ran would fail
there and not reach a CA.
"""
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

import tests.conftest as conftest
from modules.core.shell import ShellExecutor

pytestmark = [pytest.mark.unit]


def _register(tmp_path):
    return ['certbot', 'register', '--non-interactive', '--agree-tos',
            '-m', 'nobody@example.com', '--server', 'http://127.0.0.1:9/directory',
            '--config-dir', str(tmp_path), '--work-dir', str(tmp_path),
            '--logs-dir', str(tmp_path)]


@pytest.fixture
def refusals():
    """The refusals this test causes are its own, not the session's failure."""
    before = len(conftest._REAL_CERTBOT['refused'])
    yield conftest._REAL_CERTBOT['refused']
    del conftest._REAL_CERTBOT['refused'][before:]


def test_an_issuing_certbot_is_refused(tmp_path, refusals):
    before = len(refusals)
    with pytest.raises(RuntimeError, match='refused to run the real certbot'):
        ShellExecutor().run(_register(tmp_path))
    assert refusals[before:] == ['certbot register']


def test_it_is_refused_on_a_thread_no_test_waits_for(tmp_path, refusals):
    """The case that happened: a queued job running after its test."""
    before = len(refusals)
    errors = []

    def job():
        try:
            ShellExecutor().run(_register(tmp_path))
        except RuntimeError as e:
            errors.append(str(e))

    worker = threading.Thread(target=job)
    worker.start()
    worker.join(30)
    assert errors and 'refused to run the real certbot' in errors[0]
    assert refusals[before:] == ['certbot register']


def test_reading_the_local_installation_is_allowed():
    """CONTROL: `--version` and `plugins` touch no CA and are left alone."""
    seen = []

    class Real:
        def run(self, cmd, *args, **kwargs):
            seen.append(cmd)

    guard = conftest._NoRealCertbot(Real())
    guard.run(['certbot', '--version'])
    guard.run(['/usr/bin/certbot', 'plugins'])
    guard.run(['openssl', 'version'])
    assert seen == [['certbot', '--version'], ['/usr/bin/certbot', 'plugins'], ['openssl', 'version']]


@pytest.mark.e2e
def test_an_e2e_test_is_let_through():
    """CONTROL: the tests meant to reach a CA are not stopped. Checked on the
    switch alone, so this runs nothing."""
    assert conftest._REAL_CERTBOT['allowed'] is True


def test_it_is_still_refused_after_the_last_test(tmp_path):
    """A job can outlive the session: it runs on a worker thread while the
    interpreter closes, after every fixture is gone. A whole pytest run is
    started here, with one test that leaves such a job, and what the job met
    is read once that run's process has ended."""
    met = tmp_path / 'met.txt'
    inner = tmp_path / 'test_leaves_a_job.py'
    inner.write_text(textwrap.dedent(f"""
        import threading
        import time

        import tests.conftest as conftest
        from modules.core.shell import ShellExecutor


        def test_leaves_a_job():
            def job():
                while not conftest._REAL_CERTBOT['session_over']:
                    time.sleep(0.05)
                time.sleep(0.3)
                try:
                    ShellExecutor().run({_register(tmp_path)!r})
                    outcome = 'ran'
                except RuntimeError as e:
                    outcome = str(e)
                open({str(met)!r}, 'w').write(outcome)

            threading.Thread(target=job).start()
    """))
    root = Path(__file__).resolve().parent.parent
    run = subprocess.run(
        [sys.executable, '-m', 'pytest', str(inner), '-p', 'tests.conftest', '-p', 'no:cacheprovider',
         '-q', '--no-header', '--rootdir', str(tmp_path), '-c', '/dev/null'],
        cwd=root, capture_output=True, text=True, timeout=120)
    assert '1 passed' in run.stdout, run.stdout + run.stderr
    assert met.exists(), 'the job never ran: ' + run.stdout + run.stderr
    assert 'refused to run the real certbot' in met.read_text(), met.read_text()
    assert 'refused after the last test' in run.stderr, run.stderr
