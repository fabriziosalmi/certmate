"""A key restricted with `allowed_domains` has no access to client certificates.

`allowed_domains` restricts a key to domains. A client certificate is not
filed under a domain: it is an identity the instance issues, and nothing in it
can be matched against a domain pattern. So a restricted key has no claim on
any of them, and every client-certificate route that takes credentials refuses
it. A key without `allowed_domains` keeps what its role gives it, and the
routes that are public by design (the CA certificate, the CRL, OCSP) stay
public.
"""
import os
import secrets

import pytest

from tests.restricted_keys import stored_as_admin_with_domains, the_downgrade_lifted

pytestmark = [pytest.mark.unit]

SCOPE = ['*.team.example']


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('client-certs-scope')
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
        auth = container.managers['auth']
        headers = {'instance': {'Authorization': f'Bearer {token}'}}
        for name, role, scope in (('restricted-viewer', 'viewer', SCOPE),
                                  ('restricted-operator', 'operator', SCOPE),
                                  ('operator', 'operator', None)):
            ok, key = auth.create_api_key(name, role=role, allowed_domains=scope)
            assert ok, key
            headers[name] = {'Authorization': f"Bearer {key['token']}"}
        # Stored as admin with `allowed_domains`, and honoured as admin for this
        # module, so it passes every role check and what refuses it is the rule
        # under test (see `the_downgrade_lifted`).
        stored = stored_as_admin_with_domains(container, 'restricted-admin', SCOPE)
        headers['restricted-admin'] = {'Authorization': f"Bearer {stored['token']}"}
        client = app.test_client()
        made = client.post('/api/client-certs/create', headers=headers['instance'],
                           json={'common_name': 'payments-service', 'cert_usage': 'api-mtls'})
        assert made.status_code == 201, made.get_json()
        with the_downgrade_lifted():
            yield client, headers, made.get_json()['identifier'], container


def _routes(identifier):
    return [
        ('GET', '/api/client-certs', None),
        ('GET', '/api/client-certs/stats', None),
        ('GET', f'/api/client-certs/{identifier}', None),
        ('GET', f'/api/client-certs/{identifier}/download/crt', None),
        ('GET', f'/api/client-certs/{identifier}/download/key', None),
        ('POST', '/api/client-certs/create', {'common_name': 'another', 'cert_usage': 'api-mtls'}),
        ('POST', '/api/client-certs/batch', {'rows': [{'common_name': 'batch-one'}]}),
        ('POST', f'/api/client-certs/{identifier}/renew', {}),
        ('POST', f'/api/client-certs/{identifier}/revoke', {'reason': 'unspecified'}),
        ('POST', '/api/client-certs/ca/reset', {'confirm': 'reset-client-ca'}),
    ]


def test_every_route_that_takes_credentials_refuses_a_restricted_key(instance):
    client, headers, identifier, _container = instance
    for method, path, body in _routes(identifier):
        # Honoured as admin here, it passes every role check, so the refusal
        # seen is the restriction's and not the role's.
        response = client.open(path, method=method, headers=headers['restricted-admin'], json=body)
        assert response.status_code == 403, (method, path, response.status_code, response.get_json())
        assert response.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE', (method, path, response.get_json())


@pytest.mark.parametrize('who', ['restricted-viewer', 'restricted-operator'])
def test_the_roles_a_restricted_key_can_actually_have_are_refused_too(instance, who):
    client, headers, identifier, _container = instance
    for path in ('/api/client-certs', f'/api/client-certs/{identifier}',
                 f'/api/client-certs/{identifier}/download/crt',
                 f'/api/client-certs/{identifier}/download/key'):
        response = client.get(path, headers=headers[who])
        assert response.status_code == 403, (who, path, response.status_code)
        assert b'PRIVATE KEY' not in response.data and b'BEGIN CERTIFICATE' not in response.data


def test_nothing_was_made_or_changed_by_the_refused_requests(instance):
    client, headers, identifier, _container = instance
    for method, path, body in _routes(identifier):
        client.open(path, method=method, headers=headers['restricted-admin'], json=body)
    listed = client.get('/api/client-certs', headers=headers['instance']).get_json()
    names = sorted(c['common_name'] for c in listed['certificates'])
    assert names == ['payments-service'], listed
    assert listed['certificates'][0].get('revoked') in (False, None)


def test_the_refusal_is_in_the_audit_log(instance):
    client, headers, _identifier, container = instance
    client.get('/api/client-certs', headers=headers['restricted-operator'])
    entries = container.managers['audit'].get_recent_entries(limit=50)
    assert any(e.get('status') == 'denied' and e.get('resource_type') == 'client_certificate'
               and e.get('user') == 'api_key:restricted-operator' for e in entries), entries[-3:]


def test_a_key_without_the_restriction_keeps_what_its_role_gives(instance):
    """CONTROL: the same requests succeed for an operator key with no
    `allowed_domains`, so the refusals are the rule and not broken routes."""
    client, headers, identifier, _container = instance
    operator = headers['operator']
    assert client.get('/api/client-certs', headers=operator).status_code == 200
    assert client.get(f'/api/client-certs/{identifier}', headers=operator).status_code == 200
    key = client.get(f'/api/client-certs/{identifier}/download/key', headers=operator)
    assert key.status_code == 200 and b'PRIVATE KEY' in key.data


def test_what_is_public_by_design_stays_public(instance):
    """CONTROL: a relying party fetches these with no credentials at all."""
    client, _headers, _identifier, _container = instance
    assert client.get('/api/client-certs/ca').status_code == 200
    assert client.get('/api/crl/download/pem').status_code == 200
