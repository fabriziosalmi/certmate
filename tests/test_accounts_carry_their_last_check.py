"""A CA or DNS account carries the result of its last credential check.

UX perception audit P39 (issue #1511, B17). A Cloudflare token Cloudflare
refuses was saved with 'Account "prod-cf" created successfully' and the tile
read "Configured, 1 account"; a private CA that did not answer failed "Check
configuration" and was saved with a green "CA account saved". Nothing in the
product could check a DNS account: POST /api/web/certificates/test-provider is
an offline shape check no page calls.

Now one read-only call checks an account (Cloudflare GET /zones?per_page=1,
Route53 ListHostedZones with MaxItems 1, a CA's ACME directory), the server
keeps the result per account, and a save asked with `?check=1` refuses a
failed check unless `save_anyway=1` is asked too. Every other DNS provider is
"not checkable" and never passes. A client cannot write a pass through any
save: only a check the server ran records one.

No credential here is real and no call leaves the machine: the HTTP and boto3
calls are mocked, and the unreachable CA is 127.0.0.1 port 1.
"""
from unittest import mock

import pytest
import requests

from modules.core.ca_manager import CAManager
from modules.core.structured_logging import sanitize_text
from tests import contract_support

pytestmark = [pytest.mark.unit]

TOKEN = 'cf-' + 'a' * 37
OTHER_TOKEN = 'cf-' + 'b' * 37
LE_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'
UNREACHABLE_CA = 'https://127.0.0.1:1/directory'


class _Answer:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


# The shape measured against the real endpoint with an invalid 40-character token.
REFUSED = _Answer(403, {'success': False, 'errors': [{'code': 9109, 'message': 'Invalid access token'}],
                        'messages': [], 'result': None})
ACTIVE = _Answer(200, {'success': True, 'errors': [], 'messages': [],
                       'result': [{'id': 'z1', 'name': 'example.com'}]})
REFUSED_REASON = 'Cloudflare answered HTTP 403: Invalid access token (code 9109)'
DNS_PASS = ('the token can read zones; permission to change DNS records is tested when a '
            'certificate is requested')
DIRECTORY = _Answer(200, {'newAccount': 'https://ca.example/new-acct', 'newNonce': 'https://ca.example/nonce'})


@pytest.fixture
def instance():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client, app.extensions['certmate_container'].managers


def _create(client, account_id='prod', token=TOKEN, provider='cloudflare', config=None, query=''):
    config = config if config is not None else {'name': account_id.title(), 'api_token': token}
    return client.post(f'/api/dns/{provider}/accounts{query}', json={'account_id': account_id, 'config': config})


def _listed(client, provider='cloudflare', account_id='prod'):
    for account in client.get('/api/dns/accounts').get_json():
        if account['provider'] == provider and account['account_id'] == account_id:
            return account
    return None


def _ca_checks(client):
    return {(entry['provider'], entry['account_id']): entry['last_check']
            for entry in client.get('/api/web/settings/ca-account-checks').get_json()}


# ------------------------------------------------------------------ DNS check

def test_a_cloudflare_token_cloudflare_refuses_is_a_failed_check_with_its_reason(instance):
    client, _ = instance
    assert _create(client).status_code == 200
    with mock.patch('requests.get', return_value=REFUSED) as get:
        answer = client.post('/api/dns/cloudflare/accounts/prod/check')
    assert answer.status_code == 200, answer.get_json()
    check = answer.get_json()['last_check']
    assert check['outcome'] == 'failed'
    assert check['reason'] == REFUSED_REASON
    assert check['at'].endswith('Z')
    # One read-only call, to the fixed URL, with a short timeout and no redirect.
    get.assert_called_once_with(
        'https://api.cloudflare.com/client/v4/zones', params={'per_page': 1},
        headers={'Authorization': f'Bearer {TOKEN}'}, timeout=(5, 10), allow_redirects=False)
    assert _listed(client)['last_check'] == check


def test_an_active_cloudflare_token_passes(instance):
    client, _ = instance
    assert _create(client).status_code == 200
    with mock.patch('requests.get', return_value=ACTIVE):
        check = client.post('/api/dns/cloudflare/accounts/prod/check').get_json()['last_check']
    assert check['outcome'] == 'passed', check
    assert check['reason'] == DNS_PASS
    assert _listed(client)['last_check']['outcome'] == 'passed'


def test_an_account_never_checked_says_so(instance):
    client, _ = instance
    assert _create(client).status_code == 200
    assert _listed(client)['last_check'] == {'outcome': 'never', 'at': None, 'reason': None}


def test_a_route53_account_is_checked_by_listing_one_hosted_zone(instance):
    client, _ = instance
    config = {'name': 'AWS', 'access_key_id': 'AKIA' + 'X' * 16, 'secret_access_key': 's' * 40,
              'region': 'eu-west-1'}
    assert _create(client, 'aws', provider='route53', config=config).status_code == 200
    with mock.patch('boto3.client') as make:
        check = client.post('/api/dns/route53/accounts/aws/check').get_json()['last_check']
    assert check['outcome'] == 'passed', check
    service, = make.call_args.args
    options = make.call_args.kwargs
    assert service == 'route53'
    assert options['aws_access_key_id'] == config['access_key_id']
    assert options['config'].connect_timeout == 5 and options['config'].read_timeout == 10
    make.return_value.list_hosted_zones.assert_called_once_with(MaxItems='1')


def test_a_route53_key_aws_refuses_is_a_failed_check_with_aws_words(instance):
    from botocore.exceptions import ClientError
    client, _ = instance
    config = {'name': 'AWS', 'access_key_id': 'AKIA' + 'X' * 16, 'secret_access_key': 's' * 40}
    assert _create(client, 'aws', provider='route53', config=config).status_code == 200
    # The shape measured against the real endpoint with an invalid key.
    refused = ClientError({'Error': {'Code': 'InvalidClientTokenId', 'Type': 'Sender',
                                     'Message': 'The security token included in the request is invalid.'},
                           'ResponseMetadata': {'HTTPStatusCode': 403}}, 'ListHostedZones')
    with mock.patch('boto3.client') as make:
        make.return_value.list_hosted_zones.side_effect = refused
        check = client.post('/api/dns/route53/accounts/aws/check').get_json()['last_check']
    assert check['outcome'] == 'failed'
    assert check['reason'] == ('AWS answered InvalidClientTokenId: '
                               'The security token included in the request is invalid.')


def test_any_other_provider_is_not_checkable_makes_no_call_and_never_passes(instance):
    client, _ = instance
    config = {'name': 'DO', 'api_token': 'd' * 40}
    assert _create(client, 'do', provider='digitalocean', config=config).status_code == 200
    assert _listed(client, 'digitalocean', 'do')['last_check']['outcome'] == 'not_checkable'
    with mock.patch('requests.get') as get, mock.patch('boto3.client') as make:
        check = client.post('/api/dns/digitalocean/accounts/do/check').get_json()['last_check']
    assert check['outcome'] == 'not_checkable'
    get.assert_not_called()
    make.assert_not_called()


def test_a_token_given_by_reference_is_read_as_issuance_reads_it(instance, tmp_path):
    client, managers = instance
    secret = tmp_path / 'cf-token'
    secret.write_text(OTHER_TOKEN + '\n', encoding='utf-8')
    assert _create(client, config={'name': 'Prod', 'api_token_file': str(secret)}).status_code == 200
    resolved, _ = managers['dns'].get_dns_provider_account_config('cloudflare', 'prod')
    with mock.patch('requests.get', return_value=ACTIVE) as get:
        check = client.post('/api/dns/cloudflare/accounts/prod/check').get_json()['last_check']
    assert check['outcome'] == 'passed'
    assert get.call_args.kwargs['headers'] == {'Authorization': f"Bearer {resolved['api_token']}"}
    assert resolved['api_token'] == OTHER_TOKEN

    secret.unlink()
    with mock.patch('requests.get') as get:
        check = client.post('/api/dns/cloudflare/accounts/prod/check').get_json()['last_check']
    get.assert_not_called()
    assert check['outcome'] == 'failed'
    # The cause first, then the path: the 200-character bound cuts the path (review R2).
    assert check['reason'] == f'api_token could not be read (No such file or directory): {secret}', check


def test_the_reason_is_one_bounded_line_without_the_credential(instance):
    client, _ = instance
    assert _create(client).status_code == 200
    echo = _Answer(400, {'success': False, 'errors': [
        {'code': 6003, 'message': f'Bad token {TOKEN}\nsecond line ' + 'z' * 400}]})
    with mock.patch('requests.get', return_value=echo):
        check = client.post('/api/dns/cloudflare/accounts/prod/check').get_json()['last_check']
    assert check['outcome'] == 'failed'
    assert TOKEN not in check['reason']
    assert '\n' not in check['reason'] and len(check['reason']) <= 200
    assert check['reason'].startswith('Cloudflare answered HTTP 400: Bad token ******** second line')


@pytest.mark.parametrize('error, said', [
    (requests.exceptions.ConnectTimeout(), 'api.cloudflare.com did not answer within 5 seconds'),
    (requests.exceptions.ReadTimeout(), 'api.cloudflare.com did not finish its answer within 10 seconds'),
    (requests.exceptions.ConnectionError(), 'Could not connect to api.cloudflare.com (ConnectionError)'),
])
def test_a_check_that_cannot_run_is_a_failed_check(instance, error, said):
    client, _ = instance
    assert _create(client).status_code == 200
    with mock.patch('requests.get', side_effect=error):
        check = client.post('/api/dns/cloudflare/accounts/prod/check').get_json()['last_check']
    assert check == {**check, 'outcome': 'failed', 'reason': said}


def test_checking_needs_an_admin_and_an_account(instance):
    client, _ = instance
    assert _create(client).status_code == 200
    key = client.post('/api/keys', json={'name': 'checks-viewer', 'role': 'viewer'}).get_json()
    viewer = client.application.test_client()
    viewer.environ_base['HTTP_AUTHORIZATION'] = f"Bearer {key['token']}"
    with mock.patch('requests.get', return_value=ACTIVE) as get:
        assert viewer.post('/api/dns/cloudflare/accounts/prod/check').status_code == 403
        assert viewer.post('/api/web/settings/ca-providers/letsencrypt/accounts/default/check').status_code == 403
        assert viewer.get('/api/web/settings/ca-account-checks').status_code == 403
        missing = client.post('/api/dns/cloudflare/accounts/nobody/check')
    get.assert_not_called()
    assert missing.status_code == 404 and missing.get_json()['code'] == 'DNS_ACCOUNT_NOT_FOUND'


# ------------------------------------------------------------ save with check

def test_a_save_whose_check_fails_saves_nothing(instance):
    client, managers = instance
    with mock.patch('requests.get', return_value=REFUSED):
        answer = _create(client, query='?check=1')
    assert answer.status_code == 422
    body = answer.get_json()
    assert body['code'] == 'ACCOUNT_CHECK_FAILED'
    assert body['error'] == 'The check failed: ' + REFUSED_REASON
    assert body['last_check']['outcome'] == 'failed'
    assert managers['dns'].stored_account('cloudflare', 'prod') is None


def test_save_anyway_saves_the_account_and_keeps_the_failed_check(instance):
    client, managers = instance
    with mock.patch('requests.get', return_value=REFUSED):
        answer = _create(client, query='?check=1&save_anyway=1')
    assert answer.status_code == 200, answer.get_json()
    assert answer.get_json()['last_check']['outcome'] == 'failed'
    assert managers['dns'].stored_account('cloudflare', 'prod')['api_token'] == TOKEN
    listed = _listed(client)['last_check']
    assert listed['outcome'] == 'failed' and listed['reason'] == REFUSED_REASON


def test_a_save_whose_check_passes_keeps_the_pass(instance):
    client, _ = instance
    with mock.patch('requests.get', return_value=ACTIVE):
        answer = _create(client, query='?check=1')
    assert answer.status_code == 200
    assert answer.get_json()['last_check']['outcome'] == 'passed'
    assert _listed(client)['last_check']['outcome'] == 'passed'


def test_a_provider_with_no_check_saves_without_asking(instance):
    client, managers = instance
    with mock.patch('requests.get') as get:
        answer = _create(client, 'do', provider='digitalocean', config={'name': 'DO', 'api_token': 'd' * 40},
                         query='?check=1')
    get.assert_not_called()
    assert answer.status_code == 200
    assert answer.get_json()['last_check']['outcome'] == 'not_checkable'
    assert managers['dns'].stored_account('digitalocean', 'do') is not None


def test_an_update_with_check_checks_the_account_it_saves(instance):
    """The edit form sends the masked placeholder for a secret it did not
    change: the check runs on the stored token, as the save keeps it."""
    client, _ = instance
    assert _create(client).status_code == 200
    with mock.patch('requests.get', return_value=ACTIVE) as get:
        answer = client.put('/api/dns/cloudflare/accounts/prod?check=1',
                            json={'name': 'Production', 'api_token': '********'})
    assert answer.status_code == 200, answer.get_json()
    assert get.call_args.kwargs['headers'] == {'Authorization': f'Bearer {TOKEN}'}
    assert _listed(client)['last_check']['outcome'] == 'passed'


def test_a_changed_account_is_never_checked_again_until_it_is(instance):
    client, _ = instance
    with mock.patch('requests.get', return_value=ACTIVE):
        assert _create(client, query='?check=1').status_code == 200
    assert _listed(client)['last_check']['outcome'] == 'passed'
    # A rename keeps it: the credentials checked are the same.
    assert client.put('/api/dns/cloudflare/accounts/prod', json={'name': 'Renamed'}).status_code == 200
    assert _listed(client)['last_check']['outcome'] == 'passed'
    # A new token without a check is not the token that passed.
    assert client.put('/api/dns/cloudflare/accounts/prod', json={'api_token': OTHER_TOKEN}).status_code == 200
    assert _listed(client)['last_check']['outcome'] == 'never'


# ------------------------------------------------- a pass cannot be written

FORGED = {'outcome': 'passed', 'at': '2026-11-19T00:00:00Z', 'reason': None}


@pytest.mark.parametrize('path', ['/api/web/settings', '/api/settings'])
def test_no_settings_save_can_record_a_pass(instance, path):
    client, _ = instance
    assert _create(client).status_code == 200
    forged = client.post(path, json={
        'dns_providers': {'cloudflare': {'accounts': {'prod': {'last_check': FORGED}}}},
        'ca_providers': {'letsencrypt': {'accounts': {'default': {
            'email': 'ops@example.com', 'last_check': FORGED}}}},
    })
    assert forged.status_code < 500, forged.get_json()
    assert _listed(client)['last_check']['outcome'] != 'passed'
    assert _ca_checks(client)[('letsencrypt', 'default')]['outcome'] != 'passed'
    # The account routes neither: the DNS update merges what it is sent.
    assert client.put('/api/dns/cloudflare/accounts/prod', json={'last_check': FORGED}).status_code == 200
    assert _listed(client)['last_check']['outcome'] != 'passed'


# ------------------------------------------------------------------ CA check

def _private_ca(client, query='?create=1', url=UNREACHABLE_CA):
    return client.post(f'/api/web/settings/ca-providers/private_ca/accounts/corp{query}',
                       json={'email': 'ops@example.com', 'acme_url': url})


def test_an_unreachable_private_ca_is_a_failed_check(instance):
    client, _ = instance
    assert _private_ca(client).status_code == 200
    answer = client.post('/api/web/settings/ca-providers/private_ca/accounts/corp/check')
    assert answer.status_code == 200
    check = answer.get_json()['last_check']
    assert check['outcome'] == 'failed'
    assert check['reason'] == 'Could not connect to 127.0.0.1 (ConnectionError)'
    assert _ca_checks(client)[('private_ca', 'corp')] == check


def test_a_ca_save_whose_check_fails_asks_and_save_anyway_keeps_the_failure(instance):
    client, managers = instance
    refused = _private_ca(client, '?create=1&check=1')
    assert refused.status_code == 422
    assert refused.get_json()['error'] == 'The check failed: Could not connect to 127.0.0.1 (ConnectionError)'
    assert ('private_ca', 'corp') not in _ca_checks(client)
    assert 'private_ca' not in (managers['settings'].load_settings().get('ca_providers') or {})

    saved = _private_ca(client, '?create=1&check=1&save_anyway=1')
    assert saved.status_code == 200, saved.get_json()
    assert saved.get_json()['last_check']['outcome'] == 'failed'
    assert _ca_checks(client)[('private_ca', 'corp')]['outcome'] == 'failed'


@pytest.mark.parametrize('path, body, status', [
    ('private_ca/accounts/corp?create=1', {'acme_url': UNREACHABLE_CA}, 400),            # no email
    ('private_ca/accounts/corp?create=1', {'email': 'ops@example.com', 'acme_url': UNREACHABLE_CA,
                                           'surprise': 'x'}, 400),                        # unknown field
    ('private_ca/accounts/-bad?create=1', {'email': 'ops@example.com', 'acme_url': UNREACHABLE_CA}, 400),
    ('private_ca/accounts/taken?create=1', {'email': 'ops@example.com', 'acme_url': UNREACHABLE_CA}, 409),
    ('private_ca/accounts/corp?create=1', {'email': 'ops@example.com', 'acme_url': UNREACHABLE_CA,
                                           'acme_profile': 'not a profile!'}, 400),
    ('no_such_ca/accounts/corp?create=1', {'email': 'ops@example.com'}, 400),
])
def test_a_ca_account_the_save_refuses_is_refused_before_any_check(instance, path, body, status):
    """Every refusal the save would give comes before the outbound call (review F9)."""
    client, _ = instance
    def put(settings):
        settings.setdefault('ca_providers', {})['private_ca'] = {'accounts': {'taken': {
            'email': 'ops@example.com', 'acme_url': UNREACHABLE_CA}}}
    assert instance[1]['settings'].update(put, 'test')
    with mock.patch('requests.get') as get, mock.patch('requests.Session.get') as session_get:
        answer = client.post(f'/api/web/settings/ca-providers/{path}&check=1', json=body)
    get.assert_not_called()
    session_get.assert_not_called()
    assert answer.status_code == status, answer.get_json()


def test_a_lets_encrypt_account_whose_directory_answers_is_reachable_not_passed(instance):
    client, _ = instance
    saved = client.post('/api/web/settings/ca-providers/letsencrypt/accounts/ops?create=1',
                        json={'email': 'ops@example.com'})
    assert saved.status_code == 200
    assert _ca_checks(client)[('letsencrypt', 'ops')]['outcome'] == 'never'
    with mock.patch('requests.get', return_value=DIRECTORY) as get:
        check = client.post('/api/web/settings/ca-providers/letsencrypt/accounts/ops/check').get_json()['last_check']
    # The directory answering proves nothing about the account (review F2).
    assert check['outcome'] == 'reachable', check
    assert check['reason'] == 'The CA checks the account only when it registers'
    assert get.call_args.args == (LE_DIRECTORY,)
    assert get.call_args.kwargs['timeout'] == (5, 10) and get.call_args.kwargs['allow_redirects'] is False


def test_an_eab_given_by_reference_is_read_as_issuance_reads_it(instance, monkeypatch):
    client, managers = instance
    monkeypatch.setenv('B17_ZEROSSL_HMAC', 'h' * 43)
    account = {'email': 'ops@example.com', 'eab_kid': 'kid-0123456789', 'eab_hmac_env': 'B17_ZEROSSL_HMAC'}
    assert CAManager(None).validate_ca_configuration('zerossl', account) == (True, 'Configuration is valid')

    def put(settings):
        settings.setdefault('ca_providers', {})['zerossl'] = {'accounts': {'zs': account}}
    assert managers['settings'].update(put, 'test')
    with mock.patch('requests.get', return_value=DIRECTORY):
        check = client.post('/api/web/settings/ca-providers/zerossl/accounts/zs/check').get_json()['last_check']
    assert check['outcome'] == 'reachable', check
    assert check['reason'] == 'The CA checks the account and its EAB key only when it registers'
    assert 'h' * 43 not in check['reason']


def test_the_check_log_line_is_not_redacted_and_the_store_is_private(instance):
    from modules.core import account_checks
    client, managers = instance
    assert _create(client).status_code == 200
    with mock.patch('requests.get', return_value=REFUSED), \
            mock.patch.object(account_checks.logger, 'info') as info:
        client.post('/api/dns/cloudflare/accounts/prod/check')
    template, *values = info.call_args.args
    line = template % tuple(values)
    assert line == "Credential check of dns account 'prod' of provider 'cloudflare' ended failed"
    assert sanitize_text(line) == line
    store = account_checks.store_for(managers['settings']).path
    assert store.stat().st_mode & 0o777 == 0o600
    assert TOKEN not in store.read_text(encoding='utf-8')
