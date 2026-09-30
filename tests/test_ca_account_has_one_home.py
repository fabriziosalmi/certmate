"""A CA account's data lives in one place: `ca_providers[p]['accounts']`.

Once a provider has `accounts`, get_ca_config reads only those. Any flat
key left beside them (`email`, `eab_kid`, `eab_hmac`, ...) is a copy that
nothing reads and nothing updates: rotating the EAB secret in the account
left the old secret on disk for good, and deleting the account left its
secret behind. These tests pin every way such a copy could arise, on a real
SettingsManager and the real settings file, and check the file's bytes,
not a helper's return value.

They also pin the audit trail of account changes and the charset of a new
account ID, which lands in URLs, certificate metadata and log lines.
"""

import json
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.ca_manager import CAManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager
from modules.web.settings_routes import register_settings_routes

pytestmark = [pytest.mark.unit]

URL = '/api/web/settings/ca-providers/'
OLD_SECRET = 'old-hmac-that-must-go'
NEW_SECRET = 'new-hmac-after-rotation'


@pytest.fixture
def settings_manager(tmp_path):
    dirs = {name: tmp_path / name for name in ('certificates', 'data', 'backups', 'logs')}
    for d in dirs.values():
        d.mkdir()
    file_ops = FileOperations(cert_dir=dirs['certificates'], data_dir=dirs['data'],
                              backup_dir=dirs['backups'], logs_dir=dirs['logs'])
    return SettingsManager(file_ops=file_ops, settings_file=dirs['data'] / 'settings.json')


def _seed(settings_manager, payload):
    settings_manager.settings_file.write_text(json.dumps(payload))


def _on_disk(settings_manager):
    return settings_manager.settings_file.read_text()


def _legacy_zerossl():
    return {'default_ca': 'letsencrypt', 'email': 'ops@example.com', 'domains': [],
            'ca_providers': {
                'letsencrypt': {'email': 'ops@example.com'},
                'zerossl': {'email': 'z@example.com', 'eab_kid': 'kid-1', 'eab_hmac': OLD_SECRET},
            }}


def _client(settings_manager, audit=None):
    app = Flask(__name__)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda fn: fn
    managers = {'audit': audit} if audit else {}
    register_settings_routes(app, managers, None, auth, settings_manager, MagicMock())
    return app.test_client()


def test_adding_an_account_moves_the_flat_credentials_instead_of_copying_them(settings_manager):
    _seed(settings_manager, _legacy_zerossl())
    response = _client(settings_manager).post(URL + 'zerossl/accounts/second?create=1', json={
        'email': 's@example.com', 'eab_kid': 'kid-2', 'eab_hmac': 'second-hmac'})
    assert response.status_code == 200, response.get_json()

    zerossl = json.loads(_on_disk(settings_manager))['ca_providers']['zerossl']
    assert set(zerossl) == {'accounts'}
    assert zerossl['accounts']['default']['eab_hmac'] == OLD_SECRET
    assert _on_disk(settings_manager).count(OLD_SECRET) == 1


def test_a_rotated_secret_leaves_no_copy_of_the_old_one(settings_manager):
    _seed(settings_manager, _legacy_zerossl())
    client = _client(settings_manager)
    assert client.post(URL + 'zerossl/accounts/second?create=1', json={
        'email': 's@example.com', 'eab_kid': 'kid-2', 'eab_hmac': 'second-hmac'}).status_code == 200
    assert client.post(URL + 'zerossl/accounts/default', json={
        'eab_hmac': NEW_SECRET}).status_code == 200

    assert OLD_SECRET not in _on_disk(settings_manager)
    config, used = CAManager(settings_manager).get_ca_config('zerossl', 'default')
    assert (used, config['eab_hmac']) == ('default', NEW_SECRET)


def test_a_deleted_account_leaves_no_secret_behind(settings_manager):
    _seed(settings_manager, _legacy_zerossl())
    client = _client(settings_manager)
    assert client.post(URL + 'zerossl/accounts/second?create=1', json={
        'email': 's@example.com', 'eab_kid': 'kid-2', 'eab_hmac': 'second-hmac'}).status_code == 200
    assert client.delete(URL + 'zerossl/accounts/default').status_code == 200

    assert OLD_SECRET not in _on_disk(settings_manager)
    assert set(json.loads(_on_disk(settings_manager))['ca_providers']['zerossl']) == {'accounts'}


def test_copies_already_on_disk_are_dropped_on_load_without_changing_what_is_used(settings_manager):
    # What a build of the account editor before this fix left behind.
    _seed(settings_manager, {'default_ca': 'zerossl', 'domains': [],
                             'default_ca_accounts': {'zerossl': 'default'},
                             'ca_providers': {'zerossl': {
                                 'email': 'z@example.com', 'eab_kid': 'kid-1', 'eab_hmac': OLD_SECRET,
                                 'accounts': {'default': {'email': 'z@example.com',
                                                          'eab_kid': 'kid-1', 'eab_hmac': NEW_SECRET}}}}})

    settings = settings_manager.load_settings()

    assert set(settings['ca_providers']['zerossl']) == {'accounts'}
    assert OLD_SECRET not in _on_disk(settings_manager)
    assert CAManager(settings_manager).get_ca_config('zerossl')[0]['eab_hmac'] == NEW_SECRET


def test_a_flat_settings_write_reaches_the_account_that_is_used(settings_manager):
    # An API script or a stale settings tab still posts the flat shape.
    # Merged beside `accounts` it was accepted with 200 and never read.
    _seed(settings_manager, {'default_ca': 'zerossl', 'domains': [],
                             'default_ca_accounts': {'zerossl': 'prod'},
                             'ca_providers': {'zerossl': {'accounts': {
                                 'default': {'email': 'd@example.com', 'eab_kid': 'kid-d', 'eab_hmac': 'd-hmac'},
                                 'prod': {'email': 'p@example.com', 'eab_kid': 'kid-p', 'eab_hmac': OLD_SECRET}}}}})

    assert settings_manager.atomic_update({'ca_providers': {'zerossl': {'eab_hmac': NEW_SECRET}}})

    on_disk = json.loads(_on_disk(settings_manager))['ca_providers']['zerossl']
    assert set(on_disk) == {'accounts'}
    assert on_disk['accounts']['prod']['eab_hmac'] == NEW_SECRET
    assert on_disk['accounts']['prod']['eab_kid'] == 'kid-p'
    assert on_disk['accounts']['default']['eab_hmac'] == 'd-hmac'
    assert CAManager(settings_manager).get_ca_config('zerossl')[0]['eab_hmac'] == NEW_SECRET


def test_a_flat_write_to_a_flat_provider_is_left_alone(settings_manager):
    _seed(settings_manager, _legacy_zerossl())
    assert settings_manager.atomic_update({'ca_providers': {'zerossl': {'eab_hmac': NEW_SECRET}}})
    zerossl = json.loads(_on_disk(settings_manager))['ca_providers']['zerossl']
    assert 'accounts' not in zerossl
    assert zerossl['eab_hmac'] == NEW_SECRET


def test_staging_still_inherits_the_lets_encrypt_account(settings_manager):
    _seed(settings_manager, {'default_ca': 'letsencrypt', 'domains': [],
                             'ca_providers': {'letsencrypt': {
                                 'email': 'stale@example.com',
                                 'accounts': {'default': {'email': 'live@example.com'}}}}})
    settings_manager.load_settings()
    config, _ = CAManager(settings_manager).get_ca_config('letsencrypt_staging')
    assert config['email'] == 'live@example.com'


def test_account_changes_are_audited_without_the_secret(settings_manager):
    _seed(settings_manager, _legacy_zerossl())
    audit = MagicMock()
    client = _client(settings_manager, audit)
    assert client.post(URL + 'zerossl/accounts/second?create=1', json={
        'email': 's@example.com', 'eab_kid': 'kid-2', 'eab_hmac': NEW_SECRET}).status_code == 200
    assert client.post(URL + 'zerossl/accounts/second', json={'eab_hmac': 'another'}).status_code == 200
    assert client.delete(URL + 'zerossl/accounts/second').status_code == 200

    calls = [c.kwargs for c in audit.log_operation.call_args_list]
    assert [(c['operation'], c['resource_id'], c['status']) for c in calls] == [
        ('create_ca_account', 'zerossl:second', 'success'),
        ('update_ca_account', 'zerossl:second', 'success'),
        ('delete_ca_account', 'zerossl:second', 'success'),
    ]
    assert calls[0]['details'] == {'fields': ['eab_hmac', 'eab_kid', 'email']}
    assert calls[1]['details'] == {'fields': ['eab_hmac']}
    assert NEW_SECRET not in repr(audit.mock_calls)
    assert 'another' not in repr(audit.mock_calls)


def test_a_refused_write_is_audited_as_a_failure(settings_manager):
    _seed(settings_manager, _legacy_zerossl())
    audit = MagicMock()
    settings_manager.update = MagicMock(return_value=False)
    response = _client(settings_manager, audit).post(URL + 'zerossl/accounts/second?create=1', json={
        'email': 's@example.com', 'eab_kid': 'kid-2', 'eab_hmac': NEW_SECRET})
    assert response.status_code == 500
    assert audit.log_operation.call_args.kwargs['status'] == 'failure'


@pytest.mark.parametrize('account_id', [
    '<img src=x>', 'bad id', 'line\nbreak', '.hidden', '-dash', 'x' * 65, 'ùnicode'])
def test_a_new_account_id_is_held_to_a_plain_charset(settings_manager, account_id):
    _seed(settings_manager, _legacy_zerossl())
    response = _client(settings_manager).post(
        URL + 'letsencrypt/accounts/' + account_id.replace('\n', '%0A') + '?create=1',
        json={'email': 'n@example.com'})
    assert response.status_code in (400, 404), response.get_json()
    assert 'accounts' not in json.loads(_on_disk(settings_manager))['ca_providers']['letsencrypt']


@pytest.mark.parametrize('account_id', ['prod', 'Prod-2', 'team.a_1', 'x' * 64])
def test_plain_account_ids_are_accepted(settings_manager, account_id):
    _seed(settings_manager, _legacy_zerossl())
    response = _client(settings_manager).post(
        URL + 'letsencrypt/accounts/' + account_id + '?create=1', json={'email': 'n@example.com'})
    assert response.status_code == 200, response.get_json()


def test_an_existing_account_with_an_old_style_id_can_still_be_edited_and_deleted(settings_manager):
    _seed(settings_manager, {'default_ca': 'letsencrypt', 'domains': [],
                             'ca_providers': {'letsencrypt': {'accounts': {
                                 'default': {'email': 'd@example.com'},
                                 'Team A': {'email': 'a@example.com'}}}}})
    client = _client(settings_manager)
    assert client.post(URL + 'letsencrypt/accounts/Team%20A', json={
        'email': 'a2@example.com'}).status_code == 200
    assert client.delete(URL + 'letsencrypt/accounts/Team%20A').status_code == 200
