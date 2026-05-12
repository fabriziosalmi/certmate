"""
Regresión test: create_app debe asignar el módulo-level _flask_app
antes de llamar setup_scheduler.  Sin esto, los jobs de background
de APScheduler se saltan silenciosamente.
"""
import pytest

from modules.core import factory

pytestmark = [pytest.mark.unit]


def test_create_app_populates_module_level_flask_app(monkeypatch, tmp_path):
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    app, _ = factory.create_app(test_config={'TESTING': True})
    assert factory._flask_app is app


def test_run_manager_job_handles_uninitialised_app_without_crash():
    """Branch with _flask_app == None must skip silently, not crash logger."""
    factory._flask_app = None
    # Should not raise
    factory._run_manager_job('certificates', 'check_renewals')


def test_run_manager_job_handles_missing_manager_without_crash(monkeypatch, tmp_path):
    """Branch with manager missing from MANAGERS must skip silently."""
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    app, _ = factory.create_app(test_config={'TESTING': True})
    app.config['MANAGERS'] = {}
    # Should not raise
    factory._run_manager_job('certificates', 'check_renewals')


def test_run_manager_job_swallows_manager_exception_without_crash(monkeypatch, tmp_path):
    """Branch with manager method raising must log, not propagate."""
    class Boom:
        def check_renewals(self): raise RuntimeError('simulated')

    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    app, _ = factory.create_app(test_config={'TESTING': True})
    app.config['MANAGERS'] = {'certificates': Boom()}
    # Should not raise
    factory._run_manager_job('certificates', 'check_renewals')
