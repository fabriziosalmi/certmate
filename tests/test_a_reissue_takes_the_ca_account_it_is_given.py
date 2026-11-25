"""A reissue takes the CA account it is given, and later renewals follow it (#1465).

POST /api/certificates/<domain>/reissue did not read ca_account_id. With the CA
unchanged (two Private CA accounts, A and B), the reissue reused the account the
certificate recorded, whatever the edit form showed, and "Default for ..." sent
no account at all, so it kept the recorded one too.

Now an account named in the request is the one used: an id is that account, ''
is the CA's default account, and an omitted field keeps the recorded account
while the CA stays the same. An account the CA does not have is refused.

Measured with the real certbot against CertMate's own ACME server in process,
reached at two directory URLs (127.0.0.1 for account A, localhost for B), the
way tests/test_the_eab_key_stays_out_of_certbots_log.py runs it. What decides
later renewals is the server certbot writes into renewal/<domain>.conf, so that
is what is asserted, beside the account in the certificate's metadata.
"""
import json
import subprocess
import sys
import threading

import pytest

from modules.core.domain_paths import certificate_dir, renewal_conf

pytestmark = [pytest.mark.unit]

DOMAIN = 'moved.lab.internal'
RUN_CERTBOT = 'import sys; from certbot.main import main; sys.exit(main())'
URL_A = 'https://ca-a.lab.internal/acme/directory'
URL_B = 'https://ca-b.lab.internal/acme/directory'
URL_LE = 'https://acme-v02.api.letsencrypt.org/directory'


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """The app, its ACME server on loopback, two Private CA accounts on it, and
    the real certbot behind the certificate manager's shell."""
    from werkzeug.serving import make_server

    from tests import contract_support
    from tests.acme_support import enable, resolve_for_tests

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('ACME_CHALLENGES_DIR', str(tmp_path / 'challenges'))
    app, token = contract_support.build_app()
    container = app.extensions['certmate_container']
    # Let's Encrypt accounts carry no EAB key, so the server does not require one.
    entry = enable(app, allow_http=True, eab_required=False, allowed_identifiers=['*.lab.internal'])
    server = make_server('127.0.0.1', 0, app, threaded=True)
    port = server.server_port
    # Let's Encrypt's directory is a second listener on the same app: another
    # directory URL, so the renewal configuration says which CA it went to.
    le_server = make_server('127.0.0.1', 0, app, threaded=True)
    acme = container.managers['acme_server']
    acme.http01_port = port        # the app serves the webroot certbot writes to
    acme.resolve = resolve_for_tests
    served = {URL_A: f'http://127.0.0.1:{port}/acme/directory',
              URL_B: f'http://localhost:{port}/acme/directory',
              URL_LE: f'http://127.0.0.1:{le_server.server_port}/acme/directory'}

    def account(url):
        return {'name': url, 'acme_url': url, 'email': 'ops@lab.internal',
                'eab_kid': entry['kid'], 'eab_hmac': entry['hmac_key']}

    def configure(settings):
        settings['email'] = 'ops@lab.internal'
        settings['default_ca'] = 'private_ca'
        settings.setdefault('ca_providers', {})['private_ca'] = {
            'accounts': {'a': account(URL_A), 'b': account(URL_B)}}
        settings.setdefault('default_ca_accounts', {})['private_ca'] = 'a'
    container.managers['settings'].update(configure, 'test')

    def run(cmd, **kwargs):
        # The builder refuses a directory over plain HTTP, as it should, and
        # the server here has no TLS in front: only --server is pointed at it.
        cmd = list(cmd)
        cmd[cmd.index('--server') + 1] = served[cmd[cmd.index('--server') + 1]]
        kwargs.pop('timeout', None)
        return subprocess.run([sys.executable, '-c', RUN_CERTBOT, *cmd[1:]],
                              timeout=180, cwd=tmp_path, **kwargs)
    monkeypatch.setattr(container.managers['certificates'].shell_executor, 'run', run)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    le_thread = threading.Thread(target=le_server.serve_forever, daemon=True)
    le_thread.start()
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}
    try:
        yield client, headers, container, served
    finally:
        server.shutdown()
        le_server.shutdown()
        thread.join(timeout=10)
        le_thread.join(timeout=10)


def _server_in_renewal_conf(container):
    conf = renewal_conf(certificate_dir(container.managers['certificates'].cert_dir, DOMAIN), DOMAIN)
    lines = [line for line in conf.read_text(encoding='utf-8').splitlines() if line.startswith('server =')]
    return lines[0].split('=', 1)[1].strip()


def _recorded_account(container):
    metadata = certificate_dir(container.managers['certificates'].cert_dir, DOMAIN) / 'metadata.json'
    return json.loads(metadata.read_text(encoding='utf-8')).get('ca_account_id')


def _reissue(client, headers, body):
    return client.post(f'/api/certificates/{DOMAIN}/reissue', json=body, headers=headers)


def test_a_reissue_moves_the_certificate_to_the_account_it_names_and_renewals_follow(instance):
    client, headers, container, served = instance
    created = client.post('/api/certificates/create', headers=headers, json={
        'domain': DOMAIN, 'ca_provider': 'private_ca', 'ca_account_id': 'a', 'challenge_type': 'http-01'})
    assert created.status_code in (200, 201), created.get_json()
    assert _server_in_renewal_conf(container) == served[URL_A]

    moved = _reissue(client, headers, {'ca_account_id': 'b'})
    assert moved.status_code == 200, moved.get_json()
    assert _server_in_renewal_conf(container) == served[URL_B]
    assert _recorded_account(container) == 'b'

    # "Default for Private CA" is the CA's default account (a), not "unchanged".
    back = _reissue(client, headers, {'ca_account_id': ''})
    assert back.status_code == 200, back.get_json()
    assert _server_in_renewal_conf(container) == served[URL_A]
    assert _recorded_account(container) == 'a'

    # CONTROL: a reissue that names no account keeps the recorded one.
    _reissue(client, headers, {'ca_account_id': 'b'})
    kept = _reissue(client, headers, {})
    assert kept.status_code == 200, kept.get_json()
    assert _server_in_renewal_conf(container) == served[URL_B]
    assert _recorded_account(container) == 'b'


def test_global_default_moves_a_private_ca_certificate_to_the_default_ca_and_its_default_account(instance):
    """The reporter's second case: a Private CA certificate, "Global default: Let's
    Encrypt". The edit form sends the instance's default CA and '' for its account."""
    client, headers, container, served = instance
    container.managers['settings'].update(lambda s: s.__setitem__('default_ca', 'letsencrypt'), 'test')
    created = client.post('/api/certificates/create', headers=headers, json={
        'domain': DOMAIN, 'ca_provider': 'private_ca', 'ca_account_id': 'b', 'challenge_type': 'http-01'})
    assert created.status_code in (200, 201), created.get_json()
    assert _server_in_renewal_conf(container) == served[URL_B]

    moved = _reissue(client, headers, {'ca_provider': 'letsencrypt', 'ca_account_id': ''})
    assert moved.status_code == 200, moved.get_json()
    assert _server_in_renewal_conf(container) == served[URL_LE]
    metadata = json.loads((certificate_dir(container.managers['certificates'].cert_dir, DOMAIN)
                           / 'metadata.json').read_text(encoding='utf-8'))
    assert metadata.get('ca_provider') == 'letsencrypt'
    assert metadata.get('ca_account_id') in (None, 'default')


def test_a_reissue_on_an_unusable_private_ca_account_is_refused_before_certbot(instance, monkeypatch):
    """What the edit form sends when the certificate's CA is not in its list
    (#1465 round 3): no CA, and '' for the account. The reissue stays on Private
    CA and is refused there, rather than going to the default CA."""
    client, headers, container, _served = instance
    created = client.post('/api/certificates/create', headers=headers, json={
        'domain': DOMAIN, 'ca_provider': 'private_ca', 'ca_account_id': 'a', 'challenge_type': 'http-01'})
    assert created.status_code in (200, 201), created.get_json()

    def unusable(settings):
        settings['ca_providers']['private_ca']['accounts']['a'].pop('acme_url')
        settings['default_ca'] = 'letsencrypt'
    container.managers['settings'].update(unusable, 'test')
    started = []
    shell = container.managers['certificates'].shell_executor
    monkeypatch.setattr(shell, 'run', lambda cmd, **kwargs: started.append(cmd))
    refused = _reissue(client, headers, {'ca_account_id': ''})
    assert refused.status_code == 400, refused.get_json()
    assert refused.get_json()['error'] == 'Private CA ACME URL not configured'
    assert started == [], 'certbot was started'


@pytest.mark.parametrize('ca_provider, account, error', [
    ('private_ca', 'nope', "Account 'nope' not found for CA provider 'private_ca'"),
    # Let's Encrypt falls back to certbot's defaults when it has no saved
    # account; a named account it does not have is still refused.
    ('letsencrypt', 'nope', 'Selected CA account is not configured'),
    ('private_ca', 7, "7 is not of type 'string'"),
])
def test_a_reissue_refuses_an_account_the_ca_does_not_have(instance, ca_provider, account, error):
    client, headers, container, _served = instance
    directory = certificate_dir(container.managers['certificates'].cert_dir, DOMAIN)
    directory.mkdir(parents=True)
    (directory / 'cert.pem').write_text('x')
    refused = _reissue(client, headers, {'ca_provider': ca_provider, 'challenge_type': 'http-01',
                                         'ca_account_id': account})
    assert refused.status_code == 400, refused.get_json()
    assert error in json.dumps(refused.get_json())
