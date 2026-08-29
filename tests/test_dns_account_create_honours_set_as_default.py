"""Creating a DNS account with set_as_default=true makes it the default.

The create route dropped the set_as_default flag the settings UI sends (only
the update route honoured it), so an operator ticking "set as default" while
adding an account had no effect (#13). This exercises the wiring end-to-end.
"""
from pathlib import Path

import pytest

from modules.core.factory import create_app

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_container(tmp_path, monkeypatch):
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    (module_dir / "factory.py").write_text("# test path anchor\n")
    monkeypatch.setattr("modules.core.factory.__file__",
                        str(module_dir / "factory.py"))
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("TESTING", "true")
    application, container = create_app()
    assert Path(container.cert_dir).resolve().is_relative_to(tmp_path)
    return application, container


@pytest.fixture
def client(app_container):
    return app_container[0].test_client()


@pytest.fixture
def container(app_container):
    return app_container[1]


def _default(container, provider='cloudflare'):
    settings = container.managers['settings'].load_settings()
    return (settings.get('default_accounts') or {}).get(provider)


def test_set_as_default_on_create_promotes_the_new_account(client, container):
    r = client.post('/api/dns/cloudflare/accounts', json={
        'name': 'production',
        'config': {'api_token': 'REAL-TOKEN'},
        'set_as_default': True,
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _default(container) == 'production'


def test_without_the_flag_a_real_account_still_promotes_over_placeholder(
        client, container):
    """CONTROL: even without the flag, the first real account claims the
    default over the empty migrated placeholder (the auto-promotion half of
    #13)."""
    r = client.post('/api/dns/cloudflare/accounts', json={
        'name': 'production',
        'config': {'api_token': 'REAL-TOKEN'},
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _default(container) == 'production'
