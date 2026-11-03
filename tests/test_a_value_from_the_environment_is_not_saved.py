"""A value the environment supplies at load is never written to settings.json (#1397).

load_settings() overlays LETSENCRYPT_EMAIL and CLOUDFLARE_TOKEN onto what it
returns. Any save of that result wrote them to the file, so the value saved
through the interface was lost and a token delivered through a Secret ended up
on the data volume. The file must keep what was saved, and unsetting the
variable must bring it back.
"""
import json

import pytest

from modules.core import settings as settings_module
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

TOKEN_PATH = ('dns_providers', 'cloudflare', 'accounts', 'default', 'api_token')


@pytest.fixture
def manager(tmp_path, monkeypatch):
    for variable in ('LETSENCRYPT_EMAIL', 'CLOUDFLARE_TOKEN'):
        monkeypatch.delenv(variable, raising=False)
    for name in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / name).mkdir()
    files = FileOperations(cert_dir=tmp_path / 'certificates', data_dir=tmp_path / 'data',
                           backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')
    manager = SettingsManager(files, tmp_path / 'data' / 'settings.json')
    # The first load of an instance without a file writes the template and
    # returns before any overlay: the cases below start from a saved file.
    assert manager.save_settings(manager.load_settings(use_cache=False), backup_reason=None)
    return manager


def _on_disk(manager):
    return json.loads(manager.settings_file.read_text())


def _save_through_the_interface(manager, **ui):
    settings = manager.load_settings(use_cache=False)
    settings.update(ui)
    assert manager.save_settings(settings, backup_reason=None)


def _token(document):
    return settings_module._value_at(document, TOKEN_PATH)


def test_the_email_saved_through_the_interface_survives_a_save_made_with_the_variable_set(manager, monkeypatch):
    _save_through_the_interface(manager, email='ui@example.com')
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'env@example.com')

    loaded = manager.load_settings(use_cache=False)
    assert loaded['email'] == 'env@example.com'
    _save_through_the_interface(manager, scheduler_marker='saved')

    assert _on_disk(manager)['email'] == 'ui@example.com'
    assert _on_disk(manager)['scheduler_marker'] == 'saved'


def test_unsetting_the_variable_returns_the_saved_email(manager, monkeypatch):
    _save_through_the_interface(manager, email='ui@example.com')
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'env@example.com')
    _save_through_the_interface(manager, scheduler_marker='saved')
    monkeypatch.delenv('LETSENCRYPT_EMAIL')

    assert manager.load_settings(use_cache=False)['email'] == 'ui@example.com'


def test_a_token_from_the_environment_never_reaches_the_file(manager, monkeypatch):
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'env-token')

    assert _token(manager.load_settings(use_cache=False)) == 'env-token'
    _save_through_the_interface(manager, scheduler_marker='saved')

    assert 'env-token' not in manager.settings_file.read_text()
    # The file holds the empty default the settings migration writes, not the token.
    assert _token(_on_disk(manager)) == ''


def test_the_token_saved_through_the_interface_is_kept(manager, monkeypatch):
    settings = manager.load_settings(use_cache=False)
    settings['dns_providers'] = {'cloudflare': {'accounts': {'default': {'api_token': 'ui-token'}}}}
    assert manager.save_settings(settings, backup_reason=None)
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'env-token')

    _save_through_the_interface(manager, scheduler_marker='saved')

    assert _token(_on_disk(manager)) == 'ui-token'


def test_a_value_changed_to_something_else_is_the_operators_and_is_kept(manager, monkeypatch):
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'env@example.com')

    _save_through_the_interface(manager, email='changed@example.com')

    assert _on_disk(manager)['email'] == 'changed@example.com'


def test_every_overlay_in_the_table_is_one_the_load_applies(manager, monkeypatch):
    """The table that save_settings() undoes must be the set load_settings() applies."""
    for variable, path, _normalised in settings_module._ENV_OVERLAYS:
        monkeypatch.setenv(variable, f'value-of-{variable}')
        loaded = manager.load_settings(use_cache=False)
        assert settings_module._value_at(loaded, path) == f'value-of-{variable}', variable
        monkeypatch.delenv(variable)


def test_a_key_the_file_never_had_is_removed_again_with_the_dicts_the_overlay_made(monkeypatch):
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'env-token')
    overlaid = {'email': 'a@example.com',
                'dns_providers': {'cloudflare': {'accounts': {'default': {'api_token': 'env-token'}}}}}

    written = settings_module._put_back_environment_overlay(overlaid, on_disk={'email': 'a@example.com'})

    assert written == {'email': 'a@example.com'}
    assert overlaid['dns_providers']['cloudflare']['accounts']['default']['api_token'] == 'env-token'


def test_an_address_the_save_normalises_is_still_recognised_as_the_environments(manager, monkeypatch):
    """save_settings() strips and lower-cases the address before the file is written."""
    _save_through_the_interface(manager, email='ui@example.com')
    monkeypatch.setenv('LETSENCRYPT_EMAIL', ' Env@Example.COM ')

    _save_through_the_interface(manager, scheduler_marker='saved')

    assert _on_disk(manager)['email'] == 'ui@example.com'


def test_a_file_that_cannot_be_read_is_not_overwritten_while_the_environment_supplies_values(manager, monkeypatch):
    manager.settings_file.write_text('{ not json')
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'env@example.com')

    assert manager.save_settings({'email': 'env@example.com', 'domains': []}, backup_reason=None) is False
    assert manager.settings_file.read_text() == '{ not json'


def test_an_empty_file_has_nothing_to_lose_and_is_written(manager, monkeypatch):
    manager.settings_file.write_text('')
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'env@example.com')

    assert manager.save_settings({'email': 'env@example.com', 'domains': []}, backup_reason=None) is True
    assert _on_disk(manager).get('email') in ('', None)


def test_the_backup_taken_before_a_save_holds_what_was_saved_not_the_environment(manager, monkeypatch):
    _save_through_the_interface(manager, email='ui@example.com')
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'env@example.com')
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'env-token')
    seen = {}

    def create_unified_backup(settings, reason, **kwargs):
        seen['settings'] = settings
        return True

    monkeypatch.setattr(manager.file_ops, 'create_unified_backup', create_unified_backup)
    settings = manager.load_settings(use_cache=False)
    assert manager.save_settings(settings, backup_reason='ui_save')

    assert seen['settings']['email'] == 'ui@example.com'
    assert 'env-token' not in json.dumps(seen['settings'])
