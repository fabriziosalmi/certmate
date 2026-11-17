"""The PFX export password can be removed, not only replaced.

Found by the UX audit of 2026-11-17: set, then the field cleared and saved,
and it was still set. A blank secret means "keep" on the server (the settings
page never refills secrets), and the help text said "Leave blank to disable".
The page now sends null when its "remove" box is ticked; this is what the
server does with each value, through the real application.
"""
import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    settings = app.extensions['certmate_container'].managers['settings']
    return client, lambda: settings.load_settings().get('pfx_password')


def _post(client, value):
    answer = client.post('/api/web/settings', json={'pfx_password': value})
    assert answer.status_code == 200, answer.get_json()


def test_null_removes_the_password(instance):
    client, stored = instance
    _post(client, 'Pfx-password-1!')
    assert stored() == 'Pfx-password-1!'
    _post(client, None)
    assert not stored()


@pytest.mark.parametrize('value', ['', '********'])
def test_a_blank_or_masked_value_keeps_it(instance, value):
    """CONTROL: the page never refills a secret, so blank must keep it."""
    client, stored = instance
    _post(client, 'Pfx-password-1!')
    _post(client, value)
    assert stored() == 'Pfx-password-1!'
