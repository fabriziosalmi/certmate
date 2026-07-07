"""P1-1 (2026-07-02 audit): the APScheduler renewal jobs fire in EVERY process,
so >1 worker or multiple containers on a shared data dir would each run
check_renewals and issue duplicate ACME orders. _renewal_process_lock is a
host-local flock so only one process renews per tick."""
import fcntl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from modules.core import factory

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_with_data_dir(tmp_path):
    prev = factory._flask_app
    factory._flask_app = SimpleNamespace(config={'DATA_DIR': str(tmp_path)})
    yield tmp_path
    factory._flask_app = prev


def _hold_lock(data_dir, lock_name='.renewal.lock'):
    holder = open(Path(data_dir) / lock_name, 'w')
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return holder


def test_lock_granted_when_free(app_with_data_dir):
    with factory._renewal_process_lock() as may_run:
        assert may_run is True


def test_lock_denied_when_held_by_another_fd(app_with_data_dir):
    holder = _hold_lock(app_with_data_dir)  # simulate another process
    try:
        with factory._renewal_process_lock() as may_run:
            assert may_run is False
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lock_released_after_use(app_with_data_dir):
    with factory._renewal_process_lock() as may_run:
        assert may_run is True
    with factory._renewal_process_lock() as may_run2:   # re-acquirable
        assert may_run2 is True


def test_lock_yields_true_without_app():
    prev = factory._flask_app
    factory._flask_app = None
    try:
        with factory._renewal_process_lock() as may_run:
            assert may_run is True   # single-process default must never be blocked
    finally:
        factory._flask_app = prev


def test_renewal_job_skips_when_lock_held(app_with_data_dir):
    holder = _hold_lock(app_with_data_dir)
    try:
        with patch.object(factory, '_run_manager_job') as run:
            factory._certificate_renewal_job()
            run.assert_not_called()
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_renewal_job_runs_when_lock_free(app_with_data_dir):
    with patch.object(factory, '_run_manager_job') as run:
        factory._certificate_renewal_job()
        run.assert_called_once_with('certificates', 'check_renewals')


def test_client_renewal_job_skips_when_client_lock_held(app_with_data_dir):
    # The client-cert job guards on its OWN lock file.
    holder = _hold_lock(app_with_data_dir, '.client-renewal.lock')
    try:
        with patch.object(factory, '_run_manager_job') as run:
            factory._client_certificate_renewal_job()
            run.assert_not_called()
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


# --- FIX 2: the two scheduled renewal jobs must NOT share one lock ----------
# Before: both used '.renewal.lock', so a long-running TLS renewal held the
# lock and the client-cert sweep silently skipped for that tick — mTLS certs
# could expire unrenewed. Each job now takes a distinct lock, so holding one
# never suppresses the other.

def test_two_jobs_use_distinct_lock_files(app_with_data_dir):
    seen = []

    class _Recorder:
        def __init__(self, name):
            seen.append(name)

        def fileno(self):
            return -1  # flock will fail -> treated as "cannot lock", harmless here

        def close(self):
            pass

    def _fake_open(path, mode):
        return _Recorder(Path(path).name)

    with patch('builtins.open', _fake_open), \
            patch('fcntl.flock'):  # make locking a no-op so both "acquire"
        with factory._renewal_process_lock('.renewal.lock'):
            pass
        with factory._renewal_process_lock('.client-renewal.lock'):
            pass

    assert seen == ['.renewal.lock', '.client-renewal.lock']


def test_client_job_runs_even_when_tls_lock_held(app_with_data_dir):
    # Holding the TLS lock must NOT block the client-cert job (no cross-contention).
    holder = _hold_lock(app_with_data_dir, '.renewal.lock')
    try:
        with patch.object(factory, '_run_manager_job') as run:
            factory._client_certificate_renewal_job()
            run.assert_called_once_with('client_certificates', 'check_renewals')
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_tls_job_runs_even_when_client_lock_held(app_with_data_dir):
    # Symmetric guard: holding the client lock must NOT block the TLS job.
    holder = _hold_lock(app_with_data_dir, '.client-renewal.lock')
    try:
        with patch.object(factory, '_run_manager_job') as run:
            factory._certificate_renewal_job()
            run.assert_called_once_with('certificates', 'check_renewals')
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lock_yields_true_when_lock_file_cannot_be_opened(app_with_data_dir):
    # On ANY error acquiring the lock (here: open() fails, e.g. read-only FS),
    # the guard must fall back to the single-process default (proceed), NOT raise.
    def _boom(path, mode):
        raise OSError("read-only file system")

    with patch('builtins.open', _boom):
        with factory._renewal_process_lock() as may_run:
            assert may_run is True
