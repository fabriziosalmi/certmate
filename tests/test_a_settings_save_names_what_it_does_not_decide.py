"""A settings save names each email or DNS credential it wrote whose value in
effect is another, and what decides it.

UX perception audit, 2026-11-18 (P19), found in review: the first-run wizard
said "Settings saved" and listed "DNS Provider: Cloudflare" when the account
it wrote is declared by CERTMATE_CONFIG_FILE, so the token typed was never
written at all. Listing the override sources by hand missed more: a token
written into an account that takes it from a reference (api_token_env), a
flat write and the legacy cloudflare_token key under CLOUDFLARE_TOKEN.

So the save reads back each value it wrote the way issuance reads it
(DNSManager.get_dns_provider_account_config, the settings read path for the
email), compares digests, and answers `not_in_effect` with every one that
differs, names only, never a credential value. A value written into a second
account is in effect for the certificates that name it, and is not listed.
"""
import json

import pytest

from modules.core.dns_providers import DNSManager
from modules.core.settings import settings_not_in_effect
from tests.test_the_configuration_file_declares_accounts import _manager, _write

pytestmark = [pytest.mark.unit]

TYPED = 'typed-in-the-wizard'
WIZARD = {'email': 'ops@example.org', 'challenge_type': 'dns-01', 'auto_renew': True, 'setup_completed': True,
          'dns_provider': 'cloudflare',
          'dns_providers': {'cloudflare': {'accounts': {'default': {'api_token': TYPED}}}}}
TOKEN_SETTING = 'dns_providers.cloudflare.accounts.default.api_token'
DECLARED = {'version': 1, 'dns_providers': {'cloudflare': {'accounts': {'default': {
    'name': 'Declared', 'api_token_env': 'DECLARED_CF_TOKEN'}}}}}


def _save(manager, written=WIZARD):
    assert manager.atomic_update(json.loads(json.dumps(written)))
    found = settings_not_in_effect(manager, DNSManager(manager), written)
    assert TYPED not in json.dumps(found)
    return found


def test_an_account_the_configuration_file_declares_is_named_and_not_saved(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch, _write(tmp_path, DECLARED))
    monkeypatch.setenv('DECLARED_CF_TOKEN', 'from-the-environment')
    assert _save(manager) == [{'setting': TOKEN_SETTING, 'by': 'CERTMATE_CONFIG_FILE'}]
    assert TYPED not in (tmp_path / 'data' / 'settings.json').read_text()


def test_a_token_cloudflare_token_replaces_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'from-the-environment')
    assert _save(manager) == [{'setting': TOKEN_SETTING, 'by': 'CLOUDFLARE_TOKEN'}]
    # Measured: kept in the file, replaced on every read.
    loaded = manager.load_settings()
    assert loaded['dns_providers']['cloudflare']['accounts']['default']['api_token'] == 'from-the-environment'


def test_a_token_written_where_the_account_takes_it_from_a_reference_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('SOME_REF', 'from-the-reference')
    assert manager.atomic_update({'dns_providers': {'cloudflare': {'accounts': {'default': {
        'api_token_env': 'SOME_REF'}}}}})
    assert _save(manager) == [{'setting': TOKEN_SETTING, 'by': 'api_token_env'}]


def test_a_flat_token_write_under_cloudflare_token_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'from-the-environment')
    found = _save(manager, {'dns_provider': 'cloudflare', 'dns_providers': {'cloudflare': {'api_token': TYPED}}})
    assert found == [{'setting': 'dns_providers.cloudflare.api_token', 'by': 'CLOUDFLARE_TOKEN'}]


def test_the_legacy_cloudflare_token_key_under_cloudflare_token_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('CLOUDFLARE_TOKEN', 'from-the-environment')
    assert _save(manager, {'cloudflare_token': TYPED}) == [{'setting': 'cloudflare_token', 'by': 'CLOUDFLARE_TOKEN'}]


def test_an_email_letsencrypt_email_replaces_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'pinned@example.org')
    assert _save(manager) == [{'setting': 'email', 'by': 'LETSENCRYPT_EMAIL'}]


def test_the_same_email_as_the_environment_s_is_in_effect(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv('LETSENCRYPT_EMAIL', 'OPS@example.org')
    assert _save(manager) == []


def test_credentials_in_a_second_account_are_in_effect_for_what_names_it(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    assert manager.atomic_update({'dns_providers': {'cloudflare': {'accounts': {'default': {'api_token': 'one'}}}}})
    found = _save(manager, {'dns_providers': {'cloudflare': {'accounts': {'prod': {'api_token': TYPED}}}}})
    assert found == []


def test_a_plain_save_has_nothing_out_of_effect(tmp_path, monkeypatch):
    """CONTROL: no environment, no configuration file, no reference."""
    manager = _manager(tmp_path, monkeypatch)
    assert _save(manager) == []


# --- review round 3 ----------------------------------------------------------

def test_an_email_the_default_ca_account_has_its_own_of_is_named(tmp_path, monkeypatch):
    """Issuance takes the default CA account's email before the contact email."""
    manager = _manager(tmp_path, monkeypatch)
    assert manager.atomic_update({'ca_providers': {'letsencrypt': {'accounts': {'default': {
        'email': 'ca-account@example.org'}}}}})
    assert _save(manager, {'email': 'typed@example.org'}) == [
        {'setting': 'email', 'by': 'ca_providers.letsencrypt.accounts.default.email'}]


def test_an_email_for_a_default_ca_that_is_not_configured_is_named(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    assert manager.atomic_update({'default_ca': 'zerossl'})
    assert _save(manager, {'email': 'typed@example.org'}) == [{'setting': 'email', 'by': 'default_ca'}]


def test_a_token_whose_account_reads_an_unreadable_file_names_it_unreadable(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    assert manager.atomic_update({'dns_providers': {'cloudflare': {'accounts': {'default': {
        'api_token_file': str(tmp_path / 'no-such-token')}}}}})
    assert _save(manager) == [{'setting': TOKEN_SETTING, 'by': 'api_token_file', 'readable': False}]


def test_route53_keys_under_an_iam_role_are_named_by_the_mode(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    assert manager.atomic_update({'dns_providers': {'route53': {'accounts': {'default': {'auth_mode': 'iam_role'}}}}})
    found = _save(manager, {'dns_providers': {'route53': {'accounts': {'default': {
        'access_key_id': 'AKIAEXAMPLE', 'secret_access_key': TYPED}}}}})
    assert {entry['by'] for entry in found} == {'auth_mode'} and len(found) == 2
