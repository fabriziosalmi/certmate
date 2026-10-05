"""An admin key restricted to domains acts as an operator within them.

Admin reaches what belongs to the instance: settings, users, keys, storage,
backups. None of that can be matched against `allowed_domains`, so "admin,
restricted to these domains" restricts nothing an admin route does. Such a key
can no longer be created. One written by an earlier release is still honoured,
as an operator with its domains: the restriction is the part of it that is
kept. The decision is made where the caller's identity is built
(`AuthManager.effective_key_role`), so it holds on every route, including the
ones written after it.
"""
import logging
import os
import secrets

import pytest

from tests.contract_world import write_certificate
from tests.restricted_keys import stored_as_admin_with_domains

pytestmark = [pytest.mark.unit]

MINE = 'app.team.example'
THEIRS = 'app.other.example'

# Routes only an admin reaches, none of them about a domain.
ADMIN_ONLY = [
    ('GET', '/api/keys', None),
    ('POST', '/api/backups/create', {'type': 'unified'}),
    ('POST', '/api/cache/clear', {}),
    ('POST', '/api/storage/test', {'backend': 'local_filesystem', 'config': {}}),
    ('GET', '/api/users', None),
]


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('restricted-admin')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        for name in (MINE, THEIRS):
            write_certificate(tmp / 'certs' / name, name)
        legacy = stored_as_admin_with_domains(container, 'old-admin', ['*.team.example'])
        ok, admin = container.managers['auth'].create_api_key('real-admin', role='admin')
        assert ok, admin
        headers = {'instance': {'Authorization': f'Bearer {token}'},
                   'legacy': {'Authorization': f"Bearer {legacy['token']}"},
                   'admin': {'Authorization': f"Bearer {admin['token']}"}}
        yield app.test_client(), headers, container, legacy


def test_it_reaches_no_admin_route(instance):
    client, headers, _container, _legacy = instance
    for method, path, body in ADMIN_ONLY:
        response = client.open(path, method=method, headers=headers['legacy'], json=body)
        assert response.status_code == 403, (method, path, response.status_code, response.get_data(as_text=True)[:200])


def test_an_admin_key_with_no_restriction_still_does(instance):
    """CONTROL: the same routes answer an admin key that has no `allowed_domains`."""
    client, headers, _container, _legacy = instance
    for method, path, body in ADMIN_ONLY:
        response = client.open(path, method=method, headers=headers['admin'], json=body)
        assert response.status_code < 300, (method, path, response.status_code)


def test_it_does_an_operators_work_inside_its_domains_and_none_outside(instance):
    client, headers, _container, _legacy = instance
    mine = client.get(f'/api/certificates/{MINE}/download/privkey', headers=headers['legacy'])
    assert mine.status_code == 200 and b'PRIVATE KEY' in mine.data
    theirs = client.get(f'/api/certificates/{THEIRS}/download/privkey', headers=headers['legacy'])
    assert theirs.status_code == 403
    assert theirs.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'


def test_the_key_list_shows_the_role_it_acts_with(instance):
    client, headers, _container, legacy = instance
    keys = client.get('/api/keys', headers=headers['instance']).get_json()
    listed = keys.get('keys', keys)
    assert listed[legacy['id']]['role'] == 'operator'
    assert listed[legacy['id']]['allowed_domains'] == ['*.team.example']


def test_it_can_no_longer_be_created(instance):
    client, headers, container, _legacy = instance
    ok, why = container.managers['auth'].create_api_key(
        'another', role='admin', allowed_domains=['*.team.example'])
    assert ok is False and 'cannot be domain-scoped' in why
    refused = client.post('/api/keys', headers=headers['instance'],
                          json={'name': 'another', 'role': 'admin', 'allowed_domains': ['*.team.example']})
    assert refused.status_code == 400
    # An empty list locks a key out of every domain; it is a restriction too.
    ok, why = container.managers['auth'].create_api_key('locked', role='admin', allowed_domains=[])
    assert ok is False


def test_the_instance_names_such_keys_when_it_starts(instance, caplog):
    _client, _headers, container, legacy = instance
    auth = container.managers['auth']
    assert auth.restricted_admin_keys() == ['old-admin']
    from modules.factory import create_app
    with caplog.at_level(logging.WARNING):
        create_app()
    said = [r.getMessage() for r in caplog.records if 'old-admin' in r.getMessage()]
    assert said and 'acts as an operator' in said[0], [r.getMessage()[:80] for r in caplog.records]
    assert legacy['token'] not in ' '.join(r.getMessage() for r in caplog.records)


def test_a_revoked_one_is_not_named(instance):
    _client, _headers, container, _legacy = instance
    gone = stored_as_admin_with_domains(container, 'revoked-admin', ['*.team.example'])
    ok, _ = container.managers['auth'].revoke_api_key(gone['id'])
    assert ok
    assert container.managers['auth'].restricted_admin_keys() == ['old-admin']


@pytest.mark.parametrize('role,domains,acts_as', [
    ('admin', ['a.example'], 'operator'),
    ('admin', [], 'operator'),
    ('admin', None, 'admin'),
    ('operator', ['a.example'], 'operator'),
    ('viewer', ['a.example'], 'viewer'),
    ('user', None, 'operator'),
    ('nonsense', None, 'viewer'),
])
def test_the_rule(role, domains, acts_as):
    from modules.core.auth import AuthManager
    assert AuthManager.effective_key_role(role, domains) == acts_as
