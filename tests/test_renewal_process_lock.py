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


def _hold_lock(data_dir):
    holder = open(Path(data_dir) / '.renewal.lock', 'w')
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


def test_client_renewal_job_skips_when_lock_held(app_with_data_dir):
    holder = _hold_lock(app_with_data_dir)
    try:
        with patch.object(factory, '_run_manager_job') as run:
            factory._client_certificate_renewal_job()
            run.assert_not_called()
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()
