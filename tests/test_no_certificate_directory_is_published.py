"""No local certificate directory may sit inside the directory served at /static/.

Flask serves the static folder to anyone, signed in or not, and the image
leaves it writable by the app. A cert_dir there, given to the storage
settings, a migration or a connection test, would have put every private key
one unauthenticated GET away. The API refuses it, and a settings file that
names one anyway (edited, or restored) falls back to the default directory.
"""
import shutil
import uuid

import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]


@pytest.fixture
def served_dir():
    from modules.core.storage_backends import SERVED_STATIC_DIR
    path = SERVED_STATIC_DIR / f'probe-{uuid.uuid4().hex[:8]}'
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def admin():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return app, client


@pytest.mark.parametrize('route,body', [
    ('/api/storage/config', lambda d: {'backend': 'local_filesystem', 'cert_dir': d}),
    ('/api/storage/test', lambda d: {'backend': 'local_filesystem', 'config': {'cert_dir': d}}),
    ('/api/storage/migrate', lambda d: {'target_backend': 'local_filesystem', 'target_config': {'cert_dir': d}}),
])
def test_the_api_refuses_it(admin, served_dir, route, body):
    _app, client = admin
    answer = client.post(route, json=body(str(served_dir)))
    assert answer.status_code == 400 and answer.get_json()['code'] == 'CERT_DIR_PUBLISHED', answer.get_data(as_text=True)
    assert not served_dir.exists()


def test_a_relative_path_into_it_is_refused_too(admin, served_dir, monkeypatch):
    from modules.core.storage_backends import SERVED_STATIC_DIR
    _app, client = admin
    monkeypatch.chdir(SERVED_STATIC_DIR.parent)
    answer = client.post('/api/storage/config', json={'backend': 'local_filesystem', 'cert_dir': 'static'})
    assert answer.status_code == 400


def test_a_settings_file_that_names_it_gets_the_default(admin, served_dir):
    app, _client = admin
    manager = app.extensions['certmate_container'].managers['storage']
    assert manager.local_cert_dir({'cert_dir': str(served_dir)}) == manager._default_cert_dir


def test_any_other_directory_is_still_accepted(admin, tmp_path):
    """CONTROL: an operator's own directory keeps working."""
    _app, client = admin
    answer = client.post('/api/storage/test', json={'backend': 'local_filesystem',
                                                    'config': {'cert_dir': str(tmp_path / 'certs')}})
    assert answer.status_code == 200, answer.get_data(as_text=True)
