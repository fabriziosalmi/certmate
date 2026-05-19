"""
Regression tests: saving settings with a blank secret field must preserve
the previously-saved secret instead of overwriting it with an empty string.

The Settings UI deliberately does not repopulate inputs for credential
fields (``client_secret``, ``vault_token``, ``secret_access_key``, ...)
when it loads the form, so a save that didn't re-type those secrets
arrives with ``''``. The previous behaviour was:

* ``_strip_masked_values`` only stripped the ``'********'`` sentinel, so
  the empty string went through.
* ``atomic_update`` did a shallow ``{**existing, **incoming}`` merge, so
  the entire ``certificate_storage`` subtree was replaced by the partial
  payload and the on-disk secret was lost.

Fixed by treating empty strings on secret-named keys the same as the
masked sentinel, and by deep-merging ``certificate_storage`` /
``ca_providers`` against the on-disk state in ``atomic_update``.
"""

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import (
    SettingsManager,
    _deep_merge_dict,
    _is_secret_key,
    _strip_masked_values,
)


pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    return SettingsManager(
        file_ops=file_ops, settings_file=data_dir / "settings.json"
    )


def test_is_secret_key_recognises_credential_field_names():
    assert _is_secret_key('client_secret')
    assert _is_secret_key('vault_token')
    assert _is_secret_key('secret_access_key')
    assert _is_secret_key('api_bearer_token')
    assert _is_secret_key('eab_hmac_key')


def test_is_secret_key_skips_global_keytype_defaults():
    # These match the 'key' regex but carry algorithm names like 'rsa',
    # not credentials — empty must NOT be treated as preserve.
    assert not _is_secret_key('default_key_type')
    assert not _is_secret_key('default_key_size')
    assert not _is_secret_key('default_elliptic_curve')


def test_strip_masked_values_drops_empty_secret_field():
    cleaned = _strip_masked_values({
        'certificate_storage': {
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://kv.example.net/',
                'tenant_id': 't-1',
                'client_id': 'c-1',
                # Blank because the UI didn't repopulate it on load.
                'client_secret': '',
            },
        },
    })
    assert 'client_secret' not in cleaned['certificate_storage']['azure_keyvault']
    assert cleaned['certificate_storage']['azure_keyvault']['vault_url'] \
        == 'https://kv.example.net/'


def test_strip_keeps_empty_value_when_field_is_not_a_secret():
    cleaned = _strip_masked_values({
        'certificate_storage': {
            'cert_dir': '',
        },
    })
    # cert_dir isn't a secret — a deliberate clear must come through.
    assert cleaned['certificate_storage']['cert_dir'] == ''


def test_deep_merge_preserves_sibling_subtrees():
    existing = {
        'backend': 'azure_keyvault',
        'azure_keyvault': {
            'vault_url': 'https://kv.example.net/',
            'tenant_id': 't-1',
            'client_id': 'c-1',
            'client_secret': 'super-secret-stored',
        },
        'aws_secrets_manager': {
            'region': 'eu-west-1',
            'access_key_id': 'AKIA...',
            'secret_access_key': 'untouched-aws-secret',
        },
    }
    overlay = {
        'backend': 'azure_keyvault',
        'azure_keyvault': {
            'vault_url': 'https://kv.example.net/',
            'tenant_id': 't-1',
            'client_id': 'c-1',
            # client_secret intentionally absent — strip already ran.
        },
    }
    merged = _deep_merge_dict(existing, overlay)
    assert merged['azure_keyvault']['client_secret'] == 'super-secret-stored'
    # Sibling backend config preserved (shallow merge would've dropped it).
    assert merged['aws_secrets_manager']['secret_access_key'] \
        == 'untouched-aws-secret'


def test_atomic_update_preserves_secret_when_blank_resubmitted(settings_manager):
    """End-to-end: persist a config with a secret, then re-save with the
    UI's blank-secret payload — the secret must survive."""
    settings_manager.atomic_update({
        'certificate_storage': {
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://kv.example.net/',
                'tenant_id': 't-1',
                'client_id': 'c-1',
                'client_secret': 'super-secret-stored',
            },
        },
    })

    # The same payload the UI POSTs after the user toggled an unrelated
    # field, with masked/blank secrets passed through _strip_masked_values.
    ui_payload = _strip_masked_values({
        'certificate_storage': {
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://kv.example.net/',
                'tenant_id': 't-1',
                'client_id': 'c-1',
                'client_secret': '',
            },
        },
    })
    settings_manager.atomic_update(ui_payload)

    after = settings_manager.load_settings()
    assert (after['certificate_storage']['azure_keyvault']['client_secret']
            == 'super-secret-stored')


def test_atomic_update_lets_caller_explicitly_change_secret(settings_manager):
    """A new, non-empty secret value must still overwrite. Preserve
    semantics only kick in for the sentinel and the blank string."""
    settings_manager.atomic_update({
        'certificate_storage': {
            'backend': 'azure_keyvault',
            'azure_keyvault': {'client_secret': 'old'},
        },
    })
    settings_manager.atomic_update({
        'certificate_storage': {
            'backend': 'azure_keyvault',
            'azure_keyvault': {'client_secret': 'rotated'},
        },
    })
    after = settings_manager.load_settings()
    assert (after['certificate_storage']['azure_keyvault']['client_secret']
            == 'rotated')
