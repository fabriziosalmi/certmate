"""An admin turns the ACME server on and hands out EAB keys, and nothing else can (#476).

An EAB key is the right to create ACME accounts, so it is created through its
own admin endpoint, its HMAC key is shown once and never again (not by the
API, not by the settings, not in a share-safe backup, not in the audit log),
and a key is disabled rather than deleted, so the accounts it enrolled stay
attributable to it. The end-to-end case at the bottom is the reason for all
of it: a key made here enrols an account over ACME, and once disabled it
enrols no one more while that account keeps working.

Who may call these routes is held by the route walk
(test_each_role_reaches_what_it_is_listed_for.py): a viewer and an operator
reach none of them, and a key restricted to domains is refused
(test_a_restricted_key_meets_nothing_outside_its_domains.py).
"""
import json
import zipfile

import pytest

from tests import contract_support
from tests.acme_support import AcmeTestClient, problem

pytestmark = [pytest.mark.unit]


@pytest.fixture
def admin():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return app, client


def _create(client, **body):
    body.setdefault('allowed_identifiers', ['*.lab.internal'])
    return client.post('/api/acme/eab-keys', json=body)


def test_the_hmac_key_is_shown_once(admin):
    app, client = admin
    created = _create(client, kid='team-a', note='lab cluster')
    assert created.status_code == 201
    secret = created.get_json()['hmac_key']
    assert len(secret) == 43  # 32 random bytes, base64url without padding
    for path in ('/api/acme/eab-keys', '/api/acme/server', '/api/settings'):
        answer = client.get(path)
        assert answer.status_code == 200 and secret not in answer.get_data(as_text=True), path
    disabled = client.delete('/api/acme/eab-keys/team-a')
    assert disabled.status_code == 200 and secret not in disabled.get_data(as_text=True)
    assert 'hmac_key' not in disabled.get_json()
    entries = app.extensions['certmate_container'].managers['audit'].get_recent_entries(50)
    assert {'create_eab_key', 'disable_eab_key'} <= {e.get('operation') for e in entries}
    assert secret not in json.dumps(entries)


def test_a_share_safe_backup_does_not_carry_the_hmac_key(admin, monkeypatch):
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    app, client = admin
    secret = _create(client, kid='team-a').get_json()['hmac_key']
    managers = app.extensions['certmate_container'].managers
    managers['file_ops'].create_unified_backup(managers['settings'].load_settings(), 'manual', include_secrets=False)
    archive = sorted((managers['file_ops'].backup_dir / 'unified').glob('*.zip'))[-1]
    with zipfile.ZipFile(archive) as zf:
        assert secret not in zf.read('settings.json').decode()


def test_patterns_are_normalised_and_kept_in_order(admin):
    _app, client = admin
    created = _create(client, allowed_identifiers=['*.Lab.Internal.', 'nas.lab.internal', '*.lab.internal'])
    assert created.get_json()['allowed_identifiers'] == ['*.lab.internal', 'nas.lab.internal']


@pytest.mark.parametrize('body,because', [
    ({'allowed_identifiers': []}, 'must list the names'),
    ({'allowed_identifiers': 'lab.internal'}, "'lab.internal' is not of type 'array'"),  # request validation
    ({'allowed_identifiers': ['*']}, 'not a DNS name'),
    ({'allowed_identifiers': ['*.']}, 'not a DNS name'),
    ({'allowed_identifiers': ['a..lab.internal']}, 'not a DNS name'),
    ({'allowed_identifiers': ['under_score.lab.internal']}, 'not a DNS name'),
    ({'allowed_identifiers': ['*.lab.internal'] * 51}, 'At most 50'),
    ({'kid': 'has space'}, 'kid must be'),
    ({'kid': 'x' * 65}, 'kid must be'),
    ({'note': 'n' * 201}, 'note must be'),
])
def test_a_key_that_would_not_mean_what_it_says_is_refused(admin, body, because):
    _app, client = admin
    response = _create(client, **body)
    assert response.status_code == 400 and because in response.get_data(as_text=True), response.get_json()
    assert client.get('/api/acme/eab-keys').get_json() == {'eab_keys': []}


def test_a_kid_is_never_reused(admin):
    _app, client = admin
    assert _create(client, kid='team-a').status_code == 201
    assert client.delete('/api/acme/eab-keys/team-a').status_code == 200
    again = _create(client, kid='team-a')
    assert again.status_code == 409 and again.get_json()['code'] == 'ACME_EAB_KEY_EXISTS'


def test_a_generated_kid_is_one_a_client_can_send(admin):
    _app, client = admin
    kid = _create(client).get_json()['kid']
    assert kid.startswith('eab-') and len(kid) <= 64


def test_disabling_an_unknown_key_is_404(admin):
    _app, client = admin
    assert client.delete('/api/acme/eab-keys/nobody').status_code == 404


@pytest.mark.parametrize('body,because', [
    ({}, 'Send a JSON object'),
    ({'enabled': 'yes'}, "'yes' is not of type 'boolean'"),  # request validation
    ({'enabled': True, 'debug': True}, 'Unknown options'),
])
def test_options_are_three_booleans(admin, body, because):
    _app, client = admin
    response = client.patch('/api/acme/server', json=body)
    assert response.status_code == 400 and because in response.get_data(as_text=True)
    assert client.get('/api/acme/server').get_json()['enabled'] is False


def test_the_options_turn_the_protocol_on_and_off(admin):
    app, client = admin
    directory = 'https://localhost/acme/directory'
    assert app.test_client().get(directory).status_code == 404
    view = client.patch('/api/acme/server', json={'enabled': True}).get_json()
    assert view['enabled'] is True and view['directory_url'] == 'http://localhost/acme/directory'
    assert app.test_client().get(directory).status_code == 200
    assert app.test_client().get('http://localhost/acme/directory').status_code == 400
    client.patch('/api/acme/server', json={'allow_http': True})
    assert app.test_client().get('http://localhost/acme/directory').status_code == 200
    client.patch('/api/acme/server', json={'enabled': False})
    assert app.test_client().get(directory).status_code == 404


def test_a_key_made_here_enrols_until_it_is_disabled(admin):
    app, client = admin
    client.patch('/api/acme/server', json={'enabled': True})
    entry = _create(client, kid='team-a').get_json()

    enrolled = AcmeTestClient(app)
    assert enrolled.new_account(entry).status_code == 201
    assert client.get('/api/acme/eab-keys').get_json()['eab_keys'][0]['accounts'] == 1

    disabled = client.delete('/api/acme/eab-keys/team-a').get_json()
    assert disabled['disabled'] is True and disabled['accounts'] == 1

    refused = AcmeTestClient(app).new_account(entry)
    assert problem(refused, 'unknown or disabled') == 'unauthorized'
    assert enrolled.post(enrolled.account_url, None).status_code == 200


def test_the_server_itself_takes_only_booleans(admin):
    """Request validation stops a wrong type at the API; the server holds the
    same rule for any other caller."""
    from modules.core.acme_server import AcmeAdminError
    app, _client = admin
    server = app.extensions['certmate_container'].managers['acme_server']
    with pytest.raises(AcmeAdminError, match='true or false'):
        server.set_options({'enabled': 'yes'})
    with pytest.raises(AcmeAdminError, match='must list the names'):
        server.create_eab_key(allowed_identifiers='lab.internal')
    assert server.config()['enabled'] is False


@pytest.mark.parametrize('value,because', [
    (0, 'from 1 to 365'),
    (366, 'from 1 to 365'),
    ('30', "'30' is not of type 'integer'"),  # request validation
])
def test_the_validity_is_a_number_of_days_from_1_to_365(admin, value, because):
    _app, client = admin
    response = client.patch('/api/acme/server', json={'validity_days': value})
    assert response.status_code == 400 and because in response.get_data(as_text=True)
    assert client.get('/api/acme/server').get_json()['validity_days'] == 45


def test_the_validity_is_set(admin):
    app, client = admin
    assert client.patch('/api/acme/server', json={'validity_days': 7}).get_json()['validity_days'] == 7
    assert app.extensions['certmate_container'].managers['acme_server'].validity_days() == 7
    from modules.core.acme_server import AcmeAdminError
    with pytest.raises(AcmeAdminError, match='from 1 to 365'):
        app.extensions['certmate_container'].managers['acme_server'].set_options({'validity_days': True})
