"""A referenced secret is read only from a small regular text file, and a
settings save that was written answers success whatever the read-back meets.

Found in review of the UX perception audit fix for P19. Since the settings
save reads back what it wrote (`not_in_effect`), it reads secret references.
A reference to a file that was not UTF-8 raised UnicodeDecodeError, which
`secret_refs` did not turn into a SecretReferenceError: the save was written
and answered 500 "Failed to update settings", and issuance with that account
crashed the same way. A reference to a FIFO or a device would have been read
forever.

Now `secret_refs` opens without blocking and reads only a regular file of at
most 64 KiB holding UTF-8 text, and every failure is a SecretReferenceError
naming its problem. The read-back never fails the save it follows: a value it
could not check says so (`by: unchecked`).
"""
import json
import os
import secrets
import time

import pytest

from modules.core.dns_providers import DNSManager
from modules.core.secret_refs import MAX_SECRET_FILE_BYTES, SecretReferenceError, resolve_field
from tests.test_the_configuration_file_declares_accounts import _manager

pytestmark = [pytest.mark.unit]


def _problem(config, field='api_token'):
    with pytest.raises(SecretReferenceError) as caught:
        resolve_field(config, field)
    return caught.value.problem


def test_a_missing_file_is_missing(tmp_path):
    assert _problem({'api_token_file': str(tmp_path / 'absent')}) == 'missing'


def test_a_directory_is_not_a_file(tmp_path):
    assert _problem({'api_token_file': str(tmp_path)}) == 'not_a_file'


def test_a_fifo_is_refused_at_once_instead_of_read_forever(tmp_path):
    fifo = tmp_path / 'pipe'
    os.mkfifo(fifo)
    started = time.monotonic()
    assert _problem({'api_token_file': str(fifo)}) == 'not_a_file'
    assert time.monotonic() - started < 2


def test_a_device_is_not_a_file():
    assert _problem({'api_token_file': '/dev/zero'}) == 'not_a_file'


def test_a_file_larger_than_the_cap_is_too_large(tmp_path):
    big = tmp_path / 'big'
    big.write_bytes(b'a' * (MAX_SECRET_FILE_BYTES + 1))
    assert _problem({'api_token_file': str(big)}) == 'too_large'


def test_a_file_at_the_cap_is_read(tmp_path):
    """CONTROL: the cap is a limit, not an off-by-one."""
    full = tmp_path / 'full'
    full.write_bytes(b'a' * MAX_SECRET_FILE_BYTES)
    assert resolve_field({'api_token_file': str(full)}, 'api_token') == 'a' * MAX_SECRET_FILE_BYTES


def test_a_file_that_is_not_text_is_not_text(tmp_path):
    binary = tmp_path / 'binary'
    binary.write_bytes(b'\xff\xfe\x00binary')
    assert _problem({'api_token_file': str(binary)}) == 'not_text'


def test_an_empty_file_is_empty(tmp_path):
    empty = tmp_path / 'empty'
    empty.write_text('  \n')
    assert _problem({'api_token_file': str(empty)}) == 'empty'


def test_an_unset_variable_is_unset(monkeypatch):
    monkeypatch.delenv('NO_SUCH_TOKEN_VARIABLE', raising=False)
    assert _problem({'api_token_env': 'NO_SUCH_TOKEN_VARIABLE'}) == 'unset'


# --- on the issuance path -----------------------------------------------------

@pytest.mark.parametrize('make', ['not_text', 'fifo'])
def test_issuance_gets_no_account_rather_than_a_crash_or_a_hang(tmp_path, monkeypatch, make):
    """get_dns_provider_account_config is what issuance calls for its DNS account."""
    manager = _manager(tmp_path, monkeypatch)
    path = tmp_path / 'secret'
    if make == 'fifo':
        os.mkfifo(path)
    else:
        path.write_bytes(b'\xff\xfe\x00binary')
    assert manager.atomic_update({'dns_providers': {'cloudflare': {'accounts': {'default': {
        'api_token_file': str(path)}}}}})
    started = time.monotonic()
    assert DNSManager(manager).get_dns_provider_account_config('cloudflare') == (None, None)
    assert time.monotonic() - started < 2


# --- over HTTP: a written save answers success ---------------------------------

@pytest.fixture
def instance(tmp_path):
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp_path / sub))
        for var in ('CLOUDFLARE_TOKEN', 'LETSENCRYPT_EMAIL', 'CERTMATE_CONFIG_FILE'):
            patch.delenv(var, raising=False)
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        from modules.factory import create_app
        app, container = create_app()
        yield app.test_client(), {'Authorization': f'Bearer {token}'}, container, tmp_path


WIZARD = {'email': 'ops@example.org', 'challenge_type': 'dns-01', 'dns_provider': 'cloudflare',
          'dns_providers': {'cloudflare': {'accounts': {'default': {'api_token': 'typed-token-0123456789'}}}}}


@pytest.mark.parametrize('route', ['/api/web/settings', '/api/settings'])
def test_a_save_beside_a_reference_that_is_not_text_answers_success_and_names_it(instance, route):
    client, headers, _container, tmp = instance
    binary = tmp / 'cf-token'
    binary.write_bytes(b'\xff\xfe\x00binary')
    first = client.post(route, headers=headers, json={'dns_providers': {'cloudflare': {'accounts': {
        'default': {'api_token_file': str(binary)}}}}})
    assert first.status_code == 200, first.get_json()
    answer = client.post(route, headers=headers, json=WIZARD)
    assert answer.status_code == 200, answer.get_json()
    assert {'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'api_token_file',
            'problem': 'not_text'} in answer.get_json()['not_in_effect']
    stored = json.loads((tmp / 'data' / 'settings.json').read_text())
    assert stored['email'] == 'ops@example.org'


def test_a_read_back_that_fails_answers_success_with_the_value_unchecked(instance, monkeypatch):
    client, headers, _container, _tmp = instance

    def fails(*args, **kwargs):
        raise ValueError('a defect in the read-back')
    monkeypatch.setattr(DNSManager, 'get_dns_provider_account_config', fails)
    answer = client.post('/api/web/settings', headers=headers, json=WIZARD)
    assert answer.status_code == 200, answer.get_json()
    assert answer.get_json()['not_in_effect'] == [
        {'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'unchecked'}]
