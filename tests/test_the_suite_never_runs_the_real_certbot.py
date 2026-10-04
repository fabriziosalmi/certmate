"""Outside an e2e test, the suite refuses to run the real certbot.

The guard is `_no_real_certbot` in conftest.py. These tests call the one
launch point the application uses, `ShellExecutor.run`, the way an escaped
issuance would. The command points certbot at a closed port on the loopback
interface, so that if the guard were missing the certbot that ran would fail
there and not reach a CA.
"""
import threading

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
