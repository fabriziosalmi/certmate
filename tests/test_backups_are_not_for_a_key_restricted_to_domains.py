"""A key restricted with `allowed_domains` has no access to backups.

A backup is the whole instance: every domain's certificates and settings. A
key restricted to some domains has no claim on any part of one, the list
included, which names every domain the instance holds. The rule is the one
the client-certificate routes apply (`domain_restricted_refusal`).
"""
import os
import secrets

import pytest

from tests.contract_world import write_certificate

pytestmark = [pytest.mark.unit]

SCOPE = ['*.team.example']
THEIRS = 'shop.other.example'


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('backups-scope')
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
        write_certificate(tmp / 'certs' / THEIRS, THEIRS)
        settings = container.managers['settings']
        current = settings.load_settings()
        current['domains'] = [{'domain': THEIRS, 'dns_provider': 'cloudflare'}]
        settings.save_settings(current)
        auth = container.managers['auth']
        headers = {'instance': {'Authorization': f'Bearer {token}'}}
        for name, role, scope in (('restricted-viewer', 'viewer', SCOPE),
                                  # Minted the way keys were before `POST /api/keys`
                                  # stopped creating them, and still honoured.
                                  ('restricted-admin', 'admin', SCOPE),
                                  ('viewer', 'viewer', None)):
            ok, key = auth.create_api_key(name, role=role, allowed_domains=scope)
            assert ok, key
            headers[name] = {'Authorization': f"Bearer {key['token']}"}
        client = app.test_client()
        made = client.post('/api/backups/create', headers=headers['instance'],
                           json={'type': 'unified'})
        assert made.status_code in (200, 201), made.get_json()
        listed = client.get('/api/backups', headers=headers['instance']).get_json()
        filename = listed['unified'][0]['filename']
        yield client, headers, filename, tmp


def test_the_list_names_every_domain_which_is_the_premise(instance):
    client, headers, _filename, _tmp = instance
    assert THEIRS in client.get('/api/backups', headers=headers['instance']).get_data(as_text=True)


def test_a_restricted_viewer_does_not_get_the_list(instance):
    client, headers, _filename, _tmp = instance
    response = client.get('/api/backups', headers=headers['restricted-viewer'])
    assert response.status_code == 403, response.get_data(as_text=True)
    body = response.get_json()
    assert body['code'] == 'DOMAIN_OUT_OF_SCOPE'
    assert 'restricted to domains' in body['error'], 'the refusal lost its text to the list model'
    assert THEIRS not in response.get_data(as_text=True)


def _routes(filename):
    return [
        ('GET', '/api/backups', None),
        ('POST', '/api/backups/create', {'type': 'unified'}),
        ('GET', f'/api/backups/download/unified/{filename}', None),
        ('POST', '/api/backups/restore/unified', {'filename': filename}),
        ('DELETE', f'/api/backups/delete/unified/{filename}', None),
        ('POST', '/api/backups/upload', None),
        ('GET', '/api/web/backups', None),
        ('POST', '/api/web/backups/create', {'reason': 'manual'}),
    ]


def test_every_backup_route_refuses_a_restricted_key(instance):
    """Checked with a restricted admin key, which passes every role check, so
    the refusal seen is the restriction's and not the role's."""
    client, headers, filename, tmp = instance
    before = sorted(p.name for p in (tmp / 'backups').rglob('*.zip'))
    for method, path, body in _routes(filename):
        response = client.open(path, method=method, headers=headers['restricted-admin'], json=body)
        assert response.status_code == 403, (method, path, response.status_code, response.get_data(as_text=True)[:200])
        assert response.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE', (method, path)
    assert sorted(p.name for p in (tmp / 'backups').rglob('*.zip')) == before, \
        'a refused request created or deleted a backup'


def test_a_key_without_the_restriction_keeps_what_its_role_gives(instance):
    """CONTROL: a viewer key with no `allowed_domains` still lists, and the
    instance token still downloads."""
    client, headers, filename, _tmp = instance
    assert client.get('/api/backups', headers=headers['viewer']).status_code == 200
    archive = client.get(f'/api/backups/download/unified/{filename}', headers=headers['instance'])
    assert archive.status_code == 200 and archive.data[:2] == b'PK'
    assert client.get('/api/web/backups', headers=headers['instance']).status_code == 200


def test_what_the_instance_watches_is_the_instances_too(instance):
    """The inventory configuration lists the endpoints and domains the instance
    is set to watch: its own configuration, under the same rule."""
    client, headers, _filename, _tmp = instance
    configured = client.post('/api/inventory/config', headers=headers['instance'],
                             json={'ct_monitoring': {'enabled': True, 'domains': [THEIRS]}})
    assert configured.status_code == 200, configured.get_json()
    assert THEIRS in client.get('/api/inventory/config', headers=headers['viewer']).get_data(as_text=True)
    for who, method in (('restricted-viewer', 'GET'), ('restricted-admin', 'GET'), ('restricted-admin', 'POST')):
        response = client.open('/api/inventory/config', method=method, headers=headers[who], json={})
        assert response.status_code == 403, (who, method, response.status_code)
        assert response.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'
        assert THEIRS not in response.get_data(as_text=True)
