"""An account check says no more than it proved, and no working credential reads "failed".

The independent review of B17 (issue #1511, P39) found the first version of the
account checks overclaiming and underclaiming:

- A CA check fetched only the ACME directory, and called that "passed": any EAB
  key passed, and so did a directory that refuses every order. It is now
  `reachable`, never `passed`, with the sentence that the CA checks the account
  only when it registers.
- A directory URL that redirects failed, while the ACME client follows it. The
  check now follows up to five redirects, each over https.
- An account with no email of its own failed, while issuance uses the
  instance's email. The check uses the same fallback.
- Cloudflare's /user/tokens/verify refuses account-owned tokens. The check now
  lists one zone, which any token that can issue must be able to do; a token
  that reaches no zone fails. A pass says what it proved.
- A pass survived a change of the credential a file or a variable holds: the
  record was keyed on the stored settings only. It is now an HMAC, with the
  instance secret, over the credentials as issuance resolves them.
- A deleted account kept its record, and a corrupt record file was overwritten
  with only the newest result.

No credential here is real. The HTTPS server is this process's, on 127.0.0.1,
with a certificate from a CA made for the test.
"""
import http.server
import json
from unittest import mock

import pytest
import requests

from tests import contract_support
from tests.tls_support import TLSServer, key_pem, make_cert, pem

pytestmark = [pytest.mark.unit]

TOKEN = 'cf-' + 'a' * 37
ZONES = {'success': True, 'errors': [], 'messages': [], 'result': [{'id': 'z1', 'name': 'example.com'}]}
NO_ZONE = {'success': True, 'errors': [], 'messages': [], 'result': []}
LE_DIRECTORY = {'newAccount': 'https://ca.example/new-acct', 'newNonce': 'https://ca.example/nonce'}


class _Answer:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.headers = {}

    def json(self):
        return self._body


@pytest.fixture
def instance():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client, app.extensions['certmate_container'].managers


def _create_cf(client, config):
    answer = client.post('/api/dns/cloudflare/accounts', json={'account_id': 'prod', 'config': {'name': 'Prod', **config}})
    assert answer.status_code == 200, answer.get_json()


def _listed(client, provider='cloudflare', account_id='prod'):
    return next(a for a in client.get('/api/dns/accounts').get_json()
                if a['provider'] == provider and a['account_id'] == account_id)


def _ca_checks(client):
    return {(entry['provider'], entry['account_id']): entry['last_check']
            for entry in client.get('/api/web/settings/ca-account-checks').get_json()}


def _check_cf(client, answer):
    with mock.patch('requests.get', return_value=answer):
        return client.post('/api/dns/cloudflare/accounts/prod/check').get_json()['last_check']


# ------------------------------------------------------------------- F5, F6

def test_a_cloudflare_token_that_reaches_no_zone_fails(instance):
    client, _ = instance
    _create_cf(client, {'api_token': TOKEN})
    check = _check_cf(client, _Answer(200, NO_ZONE))
    assert check['outcome'] == 'failed'
    assert check['reason'] == 'Cloudflare accepted the token, but it reaches no zone'


def test_a_route53_pass_says_what_it_proved_and_that_the_host_identity_is_not_recorded(instance):
    client, _ = instance
    config = {'name': 'AWS', 'auth_mode': 'iam_role'}
    answer = client.post('/api/dns/route53/accounts', json={'account_id': 'aws', 'config': config})
    assert answer.status_code == 200, answer.get_json()
    with mock.patch('boto3.client'):
        check = client.post('/api/dns/route53/accounts/aws/check').get_json()['last_check']
    assert check['outcome'] == 'passed'
    assert check['reason'] == (
        "this host's AWS identity can list hosted zones; permission to change DNS records is tested "
        "when a certificate is requested. A change to that identity is not seen until the next check")


# ------------------------------------------------------------------------ F7

def test_a_pass_does_not_outlive_the_credential_its_file_held(instance, tmp_path):
    client, _ = instance
    secret = tmp_path / 'cf-token'
    secret.write_text(TOKEN, encoding='utf-8')
    _create_cf(client, {'api_token_file': str(secret)})
    assert _check_cf(client, _Answer(200, ZONES))['outcome'] == 'passed'
    assert _listed(client)['last_check']['outcome'] == 'passed'

    secret.write_text('cf-' + 'c' * 37, encoding='utf-8')
    assert _listed(client)['last_check']['outcome'] == 'never'
    secret.write_text(TOKEN, encoding='utf-8')
    assert _listed(client)['last_check']['outcome'] == 'passed'
    secret.unlink()
    assert _listed(client)['last_check']['outcome'] == 'never'


def test_a_pass_does_not_outlive_the_credential_its_variable_held(instance, monkeypatch):
    client, _ = instance
    monkeypatch.setenv('B17_CF_TOKEN', TOKEN)
    _create_cf(client, {'api_token_env': 'B17_CF_TOKEN'})
    assert _check_cf(client, _Answer(200, ZONES))['outcome'] == 'passed'
    monkeypatch.setenv('B17_CF_TOKEN', 'cf-' + 'd' * 37)
    assert _listed(client)['last_check']['outcome'] == 'never'


def test_the_record_is_an_hmac_with_the_instance_secret(instance):
    client, managers = instance
    from modules.core import account_checks
    _create_cf(client, {'api_token': TOKEN})
    _check_cf(client, _Answer(200, ZONES))
    stored = json.loads(account_checks.store_for(managers['settings']).path.read_text(encoding='utf-8'))
    fingerprint = stored['dns']['cloudflare']['prod']['fingerprint']
    assert fingerprint.startswith('hmac-sha256:'), fingerprint
    assert TOKEN not in json.dumps(stored)


# ------------------------------------------------------------------------ F4

def _hand_made_ca_account(managers, account):
    def put(settings):
        settings.setdefault('ca_providers', {})['letsencrypt'] = {'accounts': {'ops': account}}
    assert managers['settings'].update(put, 'test')


def test_a_ca_account_without_its_own_email_uses_the_instance_email_as_issuance_does(instance):
    client, managers = instance
    _hand_made_ca_account(managers, {'name': 'ops'})
    assert client.post('/api/web/settings', json={'email': 'ops@example.com'}).status_code == 200
    with mock.patch('requests.get', return_value=_Answer(200, LE_DIRECTORY)):
        check = client.post('/api/web/settings/ca-providers/letsencrypt/accounts/ops/check').get_json()['last_check']
    assert check['outcome'] == 'reachable', check


def test_a_ca_account_with_no_email_anywhere_fails(instance):
    client, managers = instance
    _hand_made_ca_account(managers, {'name': 'ops'})
    assert client.post('/api/web/settings', json={'email': ''}).status_code == 200
    with mock.patch('requests.get') as get:
        check = client.post('/api/web/settings/ca-providers/letsencrypt/accounts/ops/check').get_json()['last_check']
    get.assert_not_called()
    assert check['outcome'] == 'failed'
    assert check['reason'] == 'Neither the account nor the instance has an email address, which the CA needs'


# ------------------------------------------------------------------------ F3

@pytest.fixture
def directory_server(tmp_path, monkeypatch):
    """An ACME directory on 127.0.0.1 over HTTPS, and the CA that signed it."""
    monkeypatch.setenv('CERTMATE_CERT_DIR', str(tmp_path / 'certs'))
    ca, ca_key = make_cert('B17 Test CA', is_ca=True)
    leaf, leaf_key = make_cert('127.0.0.1', san_ip=['127.0.0.1'], issuer=ca, issuer_key=ca_key)
    (tmp_path / 'leaf.crt').write_bytes(pem(leaf))
    (tmp_path / 'leaf.key').write_bytes(key_pem(leaf_key))
    seen = []

    class Directory(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            base = f'https://127.0.0.1:{self.server.server_port}'
            hops = {'/redir': base + '/directory', '/twice': base + '/redir',
                    '/plain': f'http://127.0.0.1:{self.server.server_port}/directory', '/loop': base + '/loop'}
            if self.path == '/directory':
                body = json.dumps({'newAccount': base + '/new-acct', 'newNonce': base + '/nonce'}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
            elif self.path in hops:
                body = b''
                self.send_response(301)
                self.send_header('Location', hops[self.path])
            else:
                body = b''
                self.send_response(404)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = TLSServer(str(tmp_path / 'leaf.crt'), str(tmp_path / 'leaf.key'), Directory)
    yield {'base': f'https://127.0.0.1:{server.port}', 'ca_pem': pem(ca).decode(), 'seen': seen}
    server.close()


def _private_ca_check(client, url, ca_pem):
    saved = client.post('/api/web/settings/ca-providers/private_ca/accounts/corp?create=1',
                        json={'email': 'ops@example.com', 'acme_url': url, 'ca_cert': ca_pem})
    assert saved.status_code == 200, saved.get_json()
    return client.post('/api/web/settings/ca-providers/private_ca/accounts/corp/check').get_json()['last_check']


@pytest.mark.parametrize('path', ['/redir', '/twice'])
def test_a_directory_that_redirects_over_https_is_followed(instance, directory_server, path):
    client, _ = instance
    check = _private_ca_check(client, directory_server['base'] + path, directory_server['ca_pem'])
    assert check['outcome'] == 'reachable', check
    assert directory_server['seen'][-1] == '/directory'


def test_a_redirect_to_plain_http_is_not_followed(instance, directory_server):
    client, _ = instance
    check = _private_ca_check(client, directory_server['base'] + '/plain', directory_server['ca_pem'])
    assert check['outcome'] == 'failed'
    assert check['reason'] == '127.0.0.1 redirected to a URL that is not https, which is not followed'


def test_a_redirect_loop_stops(instance, directory_server):
    client, _ = instance
    check = _private_ca_check(client, directory_server['base'] + '/loop', directory_server['ca_pem'])
    assert check['outcome'] == 'failed'
    assert check['reason'] == '127.0.0.1 redirected more than 5 times'
    assert directory_server['seen'].count('/loop') == 6


# ------------------------------------------------------------------------ F8

def test_a_ca_directory_that_does_not_answer_says_which_timeout(instance):
    client, _ = instance
    saved = client.post('/api/web/settings/ca-providers/private_ca/accounts/corp?create=1',
                        json={'email': 'ops@example.com', 'acme_url': 'https://ca.example.test/directory'})
    assert saved.status_code == 200
    for error, said in ((requests.exceptions.ConnectTimeout(), 'ca.example.test did not answer within 5 seconds'),
                        (requests.exceptions.ReadTimeout(),
                         'ca.example.test did not finish its answer within 10 seconds')):
        with mock.patch('requests.get', side_effect=error):
            check = client.post('/api/web/settings/ca-providers/private_ca/accounts/corp/check').get_json()
        assert check['last_check']['reason'] == said


# ----------------------------------------------------------------------- F10

def test_a_save_with_a_check_logs_it_as_a_check_does(instance):
    client, _ = instance
    from modules.core import account_checks
    with mock.patch('requests.get', return_value=_Answer(200, ZONES)), \
            mock.patch.object(account_checks.logger, 'info') as info:
        answer = client.post('/api/dns/cloudflare/accounts?check=1',
                             json={'account_id': 'prod', 'config': {'name': 'Prod', 'api_token': TOKEN}})
    assert answer.status_code == 200
    lines = [call.args[0] % tuple(call.args[1:]) for call in info.call_args_list]
    assert "Credential check of dns account 'prod' of provider 'cloudflare' ended passed" in lines, lines


# ----------------------------------------------------------------------- F11

def test_deleting_an_account_removes_its_record(instance):
    client, managers = instance
    from modules.core import account_checks
    _create_cf(client, {'api_token': TOKEN})
    _check_cf(client, _Answer(200, ZONES))
    saved = client.post('/api/web/settings/ca-providers/private_ca/accounts/corp?create=1',
                        json={'email': 'ops@example.com', 'acme_url': 'https://127.0.0.1:1/directory'})
    assert saved.status_code == 200
    assert client.post('/api/web/settings/ca-providers/private_ca/accounts/corp/check').status_code == 200
    path = account_checks.store_for(managers['settings']).path
    stored = json.loads(path.read_text(encoding='utf-8'))
    assert 'prod' in stored['dns']['cloudflare'] and 'corp' in stored['ca']['private_ca']

    assert client.delete('/api/dns/cloudflare/accounts/prod').status_code == 200
    assert client.delete('/api/web/settings/ca-providers/private_ca/accounts/corp').status_code == 200
    stored = json.loads(path.read_text(encoding='utf-8'))
    assert 'prod' not in stored.get('dns', {}).get('cloudflare', {}), stored
    assert 'corp' not in stored.get('ca', {}).get('private_ca', {}), stored


def test_a_corrupt_record_file_is_kept_aside_not_overwritten(instance):
    client, managers = instance
    from modules.core import account_checks
    path = account_checks.store_for(managers['settings']).path
    path.write_text('{"dns": {"cloudflare": {"other": ', encoding='utf-8')
    _create_cf(client, {'api_token': TOKEN})
    with mock.patch.object(account_checks.logger, 'error') as error:
        _check_cf(client, _Answer(200, ZONES))
    kept = sorted(path.parent.glob('account_checks.json.corrupt-*'))
    assert len(kept) == 1, list(path.parent.iterdir())
    assert kept[0].read_text(encoding='utf-8') == '{"dns": {"cloudflare": {"other": '
    assert error.called
    assert json.loads(path.read_text(encoding='utf-8'))['dns']['cloudflare']['prod']['outcome'] == 'passed'



def test_forgetting_through_a_test_double_writes_nothing(tmp_path, monkeypatch):
    """A settings manager whose settings_file is not a path (a MagicMock in the
    route tests) has no store: forgetting through it made a directory named
    after the mock in the working directory."""
    from modules.core import account_checks
    monkeypatch.chdir(tmp_path)
    account_checks.forget_account(mock.MagicMock(), 'dns', 'cloudflare', 'prod')
    assert list(tmp_path.iterdir()) == []
