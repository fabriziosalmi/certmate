"""A storage backend credential can name where it lives, like a DNS token.

DNS provider tokens and the OIDC client secret already accept a `<field>_file`
or `<field>_env` reference instead of a cleartext literal (modules/core/
secret_refs.py), so the secret never sits in settings.json. The storage
backends (HashiCorp Vault / OpenBao token, the Azure client secret, the AWS
keys, the Infisical credentials) did not: StorageManager now runs each
backend's config through the same resolver before it builds the backend.

An unresolvable reference must not quietly build a backend with an empty
credential: that is the existing loud fall back to local disk, which /health
reports as degraded (see test_storage_fallback_health.py).
"""
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import StorageManager

pytestmark = [pytest.mark.unit]

_VAULT = 'https://vault.example:8200'


def _mgr(storage_config):
    sm = MagicMock()
    sm.load_settings.return_value = {'certificate_storage': storage_config}
    return StorageManager(sm)


def test_a_vault_token_can_come_from_a_mounted_file(tmp_path):
    token_file = tmp_path / 'vault-token'
    # The trailing newline that `kubectl create secret --from-file` and
    # `docker secret` both write must not reach the backend as part of the token.
    token_file.write_text('s.ROOTTOKEN\n')
    mgr = _mgr({'backend': 'hashicorp_vault',
                'hashicorp_vault': {'vault_url': _VAULT,
                                    'vault_token_file': str(token_file)}})
    assert mgr.get_fallback_backend() is None
    assert mgr.get_backend().vault_token == 's.ROOTTOKEN'


def test_a_vault_token_can_come_from_an_env_var(monkeypatch):
    monkeypatch.setenv('CERTMATE_TEST_VAULT_TOKEN', 's.ENVTOKEN')
    mgr = _mgr({'backend': 'hashicorp_vault',
                'hashicorp_vault': {'vault_url': _VAULT,
                                    'vault_token_env': 'CERTMATE_TEST_VAULT_TOKEN'}})
    assert mgr.get_fallback_backend() is None
    assert mgr.get_backend().vault_token == 's.ENVTOKEN'


def test_a_reference_beats_a_stale_literal(tmp_path):
    token_file = tmp_path / 'vault-token'
    token_file.write_text('s.NEWTOKEN')
    mgr = _mgr({'backend': 'hashicorp_vault',
                'hashicorp_vault': {'vault_url': _VAULT,
                                    'vault_token': 's.OLD-LITERAL',
                                    'vault_token_file': str(token_file)}})
    assert mgr.get_backend().vault_token == 's.NEWTOKEN'


def test_an_unresolvable_reference_falls_back_loud_not_to_an_empty_token(tmp_path):
    missing = tmp_path / 'does-not-exist'
    mgr = _mgr({'backend': 'hashicorp_vault',
                'hashicorp_vault': {'vault_url': _VAULT,
                                    'vault_token_file': str(missing)}})
    # The missing file makes resolve raise, which is the existing loud fall
    # back, NOT a Vault backend built with an empty token.
    assert mgr.get_fallback_backend() == 'hashicorp_vault'
    assert mgr.get_backend() is not None


def test_the_mechanism_is_not_vault_specific(tmp_path):
    secret_file = tmp_path / 'azure-client-secret'
    secret_file.write_text('azure-client-secret-value')
    mgr = _mgr({'backend': 'azure_keyvault',
                'azure_keyvault': {'vault_url': 'https://kv.vault.azure.net/',
                                   'client_id': 'cid', 'tenant_id': 'tid',
                                   'client_secret_file': str(secret_file)}})
    assert mgr.get_fallback_backend() is None
    assert mgr.get_backend().client_secret == 'azure-client-secret-value'
