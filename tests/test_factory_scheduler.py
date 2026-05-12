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
