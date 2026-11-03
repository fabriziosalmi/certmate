"""Accounts declared in CERTMATE_CONFIG_FILE are applied on every read and never saved (#1317).

A deployment configured from code names its DNS and CA accounts in a JSON file.
The file is the only source of those accounts: they win over a saved account
with the same id, they are not written to settings.json or to a backup, and a
file that cannot be used stops the start instead of starting half configured.
"""
import json

import pytest

from modules.core import managed_configuration
from modules.core.file_operations import FileOperations
from modules.core.settings import ManagedConfigurationUnusable, SettingsManager, SettingsUnreadableError, _is_secret_key

pytestmark = [pytest.mark.unit]

VALID = {
    'version': 1,
    'dns_providers': {'gandi': {'accounts': {'prod': {'name': 'Prod', 'api_token_file': '/run/secrets/gandi'}}}},
    'ca_providers': {'private_ca': {'accounts': {'stepca': {
        'name': 'step-ca', 'acme_url': 'https://ca.internal.example/acme/acme/directory',
        'eab_hmac_env': 'STEPCA_HMAC'}}}},
}


def _write(tmp_path, document, name='config.json'):
    path = tmp_path / name
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    return str(path)


def _refusal(tmp_path, document):
    with pytest.raises(managed_configuration.ManagedConfigurationError) as caught:
        managed_configuration.load(_write(tmp_path, document), is_secret_key=_is_secret_key)
    return str(caught.value)


def _manager(tmp_path, monkeypatch, config=None):
    monkeypatch.delenv('CERTMATE_CONFIG_FILE', raising=False)
    monkeypatch.delenv('LETSENCRYPT_EMAIL', raising=False)
    monkeypatch.delenv('CLOUDFLARE_TOKEN', raising=False)
    if config is not None:
        monkeypatch.setenv('CERTMATE_CONFIG_FILE', config)
    for name in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / name).mkdir(exist_ok=True)
    files = FileOperations(cert_dir=tmp_path / 'certificates', data_dir=tmp_path / 'data',
                           backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')
    return SettingsManager(files, tmp_path / 'data' / 'settings.json')


def _account(settings, kind, provider, account_id):
    return (settings.get(kind, {}).get(provider, {}).get('accounts', {}) or {}).get(account_id)


# --- the file -----------------------------------------------------------------

def test_a_valid_file_is_read_with_its_accounts(tmp_path):
    loaded = managed_configuration.load(_write(tmp_path, VALID), is_secret_key=_is_secret_key)

    assert loaded.accounts['dns_providers']['gandi']['prod']['api_token_file'] == '/run/secrets/gandi'
    assert ('ca_providers', 'private_ca', 'accounts', 'stepca') in loaded.account_paths


@pytest.mark.parametrize('document, names', [
    ('{ not json', 'not valid JSON'),
    ('[]', 'one JSON object'),
    ({'version': 2}, '"version" must be 1'),
    ({'dns_providers': {}}, '"version" must be 1'),
    ({'version': 1, 'surprise': {}}, 'unknown key "surprise"'),
    ({'version': 1, 'storage_backend': {}}, 'storage backend is not supported'),
    ({'version': 1, 'dns_providers': {'Gandi': {'accounts': {}}}}, 'provider name'),
    ({'version': 1, 'dns_providers': {'gandi': {'accounts': {'bad id': {'name': 'x'}}}}}, 'account id'),
    ({'version': 1, 'dns_providers': {'gandi': {'accounts': {'prod': {}}}}}, 'non-empty object'),
    ({'version': 1, 'dns_providers': {'gandi': {'accounts': {'prod': {'name': 'x'}}, 'extra': 1}}}, 'one key'),
])
def test_a_file_that_cannot_be_used_is_refused_with_the_reason(tmp_path, document, names):
    message = _refusal(tmp_path, document)

    assert names in message
    assert 'Refusing to start' in message


def test_a_secret_inside_a_nested_object_is_refused_too(tmp_path):
    message = _refusal(tmp_path, {'version': 1, 'dns_providers': {
        'gandi': {'accounts': {'prod': {'options': {'api_key': 'nested-value'}}}}}})

    assert 'dns_providers.gandi.accounts.prod.options.api_key' in message
    assert 'nested-value' not in message


def test_a_kind_that_is_not_an_object_is_refused(tmp_path):
    assert '"dns_providers" must be an object' in _refusal(tmp_path, {'version': 1, 'dns_providers': []})


def test_a_file_larger_than_the_limit_is_refused_without_being_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(managed_configuration, 'MAX_BYTES', 64)

    assert 'larger than 64 bytes' in _refusal(tmp_path, VALID)


def test_a_secret_written_in_the_file_is_refused_and_the_message_does_not_carry_it(tmp_path):
    message = _refusal(tmp_path, {'version': 1, 'dns_providers': {
        'gandi': {'accounts': {'prod': {'api_token': 'hunter2-the-value'}}}}})

    assert 'dns_providers.gandi.accounts.prod.api_token' in message
    assert 'api_token_file' in message and 'api_token_env' in message
    assert 'hunter2-the-value' not in message


def test_a_reference_must_name_something(tmp_path):
    message = _refusal(tmp_path, {'version': 1, 'dns_providers': {
        'gandi': {'accounts': {'prod': {'api_token_file': ''}}}}})

    assert 'api_token_file' in message and 'reference' in message


def test_a_missing_file_stops_the_start(tmp_path, monkeypatch):
    with pytest.raises(ManagedConfigurationUnusable) as caught:
        _manager(tmp_path, monkeypatch, config=str(tmp_path / 'absent.json'))

    assert isinstance(caught.value, SettingsUnreadableError)
    assert 'absent.json' in str(caught.value)


# --- the settings ---------------------------------------------------------------

def test_without_the_variable_nothing_changes(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    manager.save_settings(manager.load_settings(use_cache=False), backup_reason=None)

    assert _account(manager.load_settings(use_cache=False), 'dns_providers', 'gandi', 'prod') is None


def test_the_declared_accounts_are_in_the_settings_from_the_first_read(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, config=_write(tmp_path, VALID))

    first = manager.load_settings(use_cache=False)     # the first read of an empty data directory
    again = manager.load_settings(use_cache=False)

    for settings in (first, again):
        assert _account(settings, 'dns_providers', 'gandi', 'prod')['api_token_file'] == '/run/secrets/gandi'
        assert _account(settings, 'ca_providers', 'private_ca', 'stepca')['name'] == 'step-ca'


def test_a_declared_account_is_never_written_to_the_file(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, config=_write(tmp_path, VALID))
    settings = manager.load_settings(use_cache=False)
    settings['scheduler_marker'] = 'saved'

    assert manager.save_settings(settings, backup_reason=None)

    on_disk = json.loads(manager.settings_file.read_text())
    assert on_disk['scheduler_marker'] == 'saved'
    assert _account(on_disk, 'dns_providers', 'gandi', 'prod') is None
    assert _account(on_disk, 'ca_providers', 'private_ca', 'stepca') is None
    assert 'internal.example' not in manager.settings_file.read_text()


def test_a_saved_account_with_the_same_id_is_replaced_in_memory_and_kept_on_disk(tmp_path, monkeypatch):
    plain = _manager(tmp_path, monkeypatch)
    settings = plain.load_settings(use_cache=False)
    settings['dns_providers']['gandi'] = {'accounts': {'prod': {'name': 'Saved', 'api_token': 'saved-token'}}}
    assert plain.save_settings(settings, backup_reason=None)

    manager = _manager(tmp_path, monkeypatch, config=_write(tmp_path, VALID))
    loaded = manager.load_settings(use_cache=False)
    assert _account(loaded, 'dns_providers', 'gandi', 'prod') == VALID['dns_providers']['gandi']['accounts']['prod']
    loaded['scheduler_marker'] = 'saved'
    assert manager.save_settings(loaded, backup_reason=None)

    kept = _account(json.loads(manager.settings_file.read_text()), 'dns_providers', 'gandi', 'prod')
    assert kept['api_token'] == 'saved-token'


def test_the_backup_taken_before_a_save_does_not_hold_the_declared_accounts(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, config=_write(tmp_path, VALID))
    manager.save_settings(manager.load_settings(use_cache=False), backup_reason=None)
    seen = {}

    def create_unified_backup(settings, reason, **kwargs):
        seen['settings'] = settings
        return True

    monkeypatch.setattr(manager.file_ops, 'create_unified_backup', create_unified_backup)
    assert manager.save_settings(manager.load_settings(use_cache=False), backup_reason='ui_save')

    assert _account(seen['settings'], 'dns_providers', 'gandi', 'prod') is None
    assert 'internal.example' not in json.dumps(seen['settings'])
