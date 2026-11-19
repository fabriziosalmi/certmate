"""A settings save names what it set that something else decides instead.

UX perception audit, 2026-11-18 (P19), found in review: the first-run wizard
said "Settings saved" and listed "DNS Provider: Cloudflare" when the account
it wrote is declared by CERTMATE_CONFIG_FILE, so the token typed was never
written at all. The same holds, differently, for a value an environment
variable replaces whenever the settings are read (LETSENCRYPT_EMAIL,
CLOUDFLARE_TOKEN: kept in the file and not used), and for credentials typed
into an account that is not the one its provider issues with by default.
The save's answer now carries `not_in_effect`, names only, never a value.
"""
import json

import pytest

from modules.core.dns_providers import DNSManager
from modules.core.settings import settings_not_in_effect
from tests.test_the_configuration_file_declares_accounts import _manager, _write

pytestmark = [pytest.mark.unit]

WIZARD = {'email': 'ops@example.org', 'challenge_type': 'dns-01', 'auto_renew': True, 'setup_completed': True,
          'dns_provider': 'cloudflare',
          'dns_providers': {'cloudflare': {'accounts': {'default': {'api_token': 'typed-in-the-wizard'}}}}}
DECLARED = {'version': 1, 'dns_providers': {'cloudflare': {'accounts': {'default': {
    'name': 'Declared', 'api_token_env': 'DECLARED_CF_TOKEN'}}}}}


def _save(manager, written=WIZARD):
    assert manager.atomic_update(json.loads(json.dumps(written)))
    return settings_not_in_effect(manager, DNSManager(manager), written)


def test_an_account_the_configuration_file_declares_is_named_and_not_saved(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, _write(tmp_path, DECLARED))
    monkeypatch.setenv('DECLARED_CF_TOKEN', 'from-the-environment')
    found = _save(manager)
    assert found == [{'setting': 'dns_providers.cloudflare.accounts.default', 'by': 'CERTMATE_CONFIG_FILE'}]
    assert 'typed-in-the-wizard' not in (tmp_path / 'data' / 'settings.json').read_text()


def test_a_token_cloudflare_token_replaces_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'from-the-environment')
    found = _save(manager)
    assert found == [{'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'CLOUDFLARE_TOKEN'}]
    # Measured: kept in the file, replaced on every read.
    loaded = manager.load_settings()
    assert loaded['dns_providers']['cloudflare']['accounts']['default']['api_token'] == 'from-the-environment'


def test_an_email_letsencrypt_email_replaces_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'pinned@example.org')
    found = _save(manager)
    assert found == [{'setting': 'email', 'by': 'LETSENCRYPT_EMAIL'}]


def test_the_same_email_as_the_environment_s_is_in_effect(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'OPS@example.org')
    assert _save(manager) == []


def test_credentials_in_an_account_that_is_not_the_default_are_named_with_the_one_used(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    assert manager.atomic_update({'dns_providers': {'cloudflare': {'accounts': {'prod': {'api_token': 'prod-token'}}}},
                                  'default_accounts': {'cloudflare': 'prod'}})
    found = _save(manager)
    assert found == [{'setting': 'dns_providers.cloudflare.accounts.default',
                      'by': 'default_accounts.cloudflare', 'account': 'prod'}]


def test_a_plain_save_has_nothing_out_of_effect(tmp_path, monkeypatch):
    """CONTROL: no environment, no configuration file, the default account."""
    manager = _manager(tmp_path, monkeypatch)
    assert _save(manager) == []
