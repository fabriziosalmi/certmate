"""Setup mode accepts only the first-admin bootstrap, and audits the rest.

Setup mode serves every caller as admin until a credential exists, so a fresh
instance can be bootstrapped. The first caller can take the instance by making
the first admin, and the operator sees that: setup is then over. What a list of
refused paths kept missing was the change that does NOT end setup and outlives
it unseen: a restored backup that planted a deploy hook or an admin key; a
storage migration that copied every private key to a place the caller chose;
OIDC or DNS settings that named a file or a variable for a secret, to be sent
to a server the caller chose (the P0-1/P0-2 findings on #476's security pass).

So every write is refused except the two the first-run screen makes, and the
reads that carry key material are refused too.
"""

import pytest

from tests.test_setup_mode_only_bootstraps_the_dangerous_parts import ORIGIN, PASSWORD, _app

pytestmark = [pytest.mark.unit]


REFUSED_WRITES = [
    ('POST', '/api/backups/restore/unified', {'filename': 'x.zip'}),
    ('POST', '/api/storage/migrate', {'target_backend': 'local_filesystem', 'target_config': {'cert_dir': 'x'}}),
    ('POST', '/api/storage/config', {'backend': 'local_filesystem'}),
    ('POST', '/api/storage/test', {'backend': 'local_filesystem', 'config': {}}),
    ('POST', '/api/auth/oidc/settings', {'enabled': True, 'issuer_url': 'https://idp.invalid',
                                         'client_id': 'x', 'client_secret_file': '/etc/hostname'}),
    ('POST', '/api/settings', {'dns_providers': {'powerdns': {'api_url': 'https://x', 'api_key_file': '/etc/hostname'}}}),
    ('POST', '/api/dns/acme-dns/accounts', {'name': 'd', 'config': {'username_env': 'HOME'}}),
]


@pytest.mark.parametrize('method,path,body', REFUSED_WRITES, ids=[r[1] for r in REFUSED_WRITES])
def test_the_write_is_refused_in_setup_mode(tmp_path, monkeypatch, method, path, body):
    app, _ = _app(tmp_path, monkeypatch)
    r = app.test_client().open(path, method=method, json=body, headers=ORIGIN)
    assert r.status_code == 409 and r.get_json()['code'] == 'SETUP_BOOTSTRAP_ONLY', (
        path, r.status_code, r.get_data(as_text=True)[:200])


def test_a_secret_reference_never_reaches_a_server_the_caller_named(tmp_path, monkeypatch):
    """The P0-2 chain, blocked at step one: the OIDC write that would have CertMate
    read a file and send it to the caller's server is refused before it is stored."""
    app, container = _app(tmp_path, monkeypatch)
    r = app.test_client().post('/api/auth/oidc/settings', headers=ORIGIN, json={
        'enabled': True, 'issuer_url': 'https://attacker.invalid/realms/x', 'client_id': 'x',
        'client_secret_file': '/etc/hostname'})
    assert r.status_code == 409
    oidc = container.managers['settings'].load_settings().get('oidc') or {}
    assert 'client_secret_file' not in oidc
    assert container.managers['auth'].is_setup_mode(), 'the refused write must not have closed setup'


def test_the_first_admin_is_still_accepted(tmp_path, monkeypatch):
    """CONTROL: the one write setup mode exists for still works, and closes it."""
    app, container = _app(tmp_path, monkeypatch)
    r = app.test_client().post('/api/web/settings/users', headers=ORIGIN,
                               json={'username': 'admin', 'password': PASSWORD, 'role': 'admin'})
    assert r.status_code == 201 and r.get_json().get('local_auth_enabled') is True
    assert not container.managers['auth'].is_setup_mode()
