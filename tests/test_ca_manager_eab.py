"""
Regression tests: EAB credentials saved by the settings UI must reach
certbot.

The settings UI (collectCAProviderSettings in static/js/settings.js)
stores External Account Binding credentials as ``eab_kid`` /
``eab_hmac``, while CAManager read only the canonical ``eab_key_id`` /
``eab_hmac_key`` spellings. Every EAB CA configured through the web UI
therefore failed at issuance time with "EAB credentials not configured".

On top of that, ``eab_hmac`` did not match the secret-name regex in
modules/core/settings.py, so the HMAC key was returned unmasked by
GET /api/web/settings and overwritten with ``''`` on every save where
the user didn't re-type it.

CAManager now accepts both spellings, and ``hmac`` joined the
secret-name pattern (masked on GET, blank-on-save preserves the
on-disk value).
"""

import os
import stat

import pytest

from modules.core.ca_manager import CAManager
from modules.core.settings import (
    _is_secret_key,
    _strip_masked_values,
    mask_secrets_in_settings,
    SECRET_MASK_SENTINEL,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def temp_files(tmp_path, monkeypatch):
    """The caller's list of files to remove; the EAB file lands under tmp_path."""
    monkeypatch.chdir(tmp_path)
    files = []
    yield files
    for path in files:
        if os.path.exists(path):
            os.unlink(path)


def eab_config_of(cmd, temp_files):
    """The EAB pair certbot will read: the -c file, which the caller owns."""
    path = cmd[cmd.index('-c') + 1]
    assert path in temp_files
    with open(path, encoding='utf-8') as handle:
        return dict(line.split(' = ', 1) for line in handle.read().splitlines())


@pytest.fixture
def ca_manager():
    # The EAB lookup paths never touch the settings manager — the
    # account config is passed in explicitly.
    return CAManager(settings_manager=None)


def test_get_eab_credentials_canonical_spelling(ca_manager):
    kid, hmac = ca_manager.get_eab_credentials('zerossl', {
        'eab_key_id': 'kid-canonical',
        'eab_hmac_key': 'hmac-canonical',
    })
    assert (kid, hmac) == ('kid-canonical', 'hmac-canonical')


def test_get_eab_credentials_ui_spelling(ca_manager):
    # What collectCAProviderSettings actually saves.
    kid, hmac = ca_manager.get_eab_credentials('zerossl', {
        'eab_kid': 'kid-from-ui',
        'eab_hmac': 'hmac-from-ui',
    })
    assert (kid, hmac) == ('kid-from-ui', 'hmac-from-ui')


def test_get_eab_credentials_ui_spelling_wins_over_stale_canonical(ca_manager):
    # The settings form is the only surface that rotates credentials;
    # a leftover hand-edited canonical pair must not shadow it forever.
    kid, hmac = ca_manager.get_eab_credentials('zerossl', {
        'eab_key_id': 'kid-stale', 'eab_hmac_key': 'hmac-stale',
        'eab_kid': 'kid-rotated', 'eab_hmac': 'hmac-rotated',
    })
    assert (kid, hmac) == ('kid-rotated', 'hmac-rotated')


def test_get_eab_credentials_empty_ui_value_falls_back_to_canonical(ca_manager):
    # Every UI save writes eab_kid (possibly '') for every provider;
    # an empty UI value must not mask a working canonical pair.
    kid, hmac = ca_manager.get_eab_credentials('zerossl', {
        'eab_kid': '', 'eab_key_id': 'kid-canonical',
        'eab_hmac_key': 'hmac-canonical',
    })
    assert (kid, hmac) == ('kid-canonical', 'hmac-canonical')


def test_private_ca_partial_eab_warns_and_omits(ca_manager, caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger='modules.core.ca_manager'):
        kid, hmac = ca_manager.get_eab_credentials('private_ca', {
            'eab_kid': 'only-half-of-the-pair',
        })
    assert (kid, hmac) == (None, None)
    assert any('Incomplete EAB credentials' in r.message for r in caplog.records)


def test_get_eab_credentials_missing_raises(ca_manager):
    with pytest.raises(ValueError, match='EAB credentials not configured'):
        ca_manager.get_eab_credentials('zerossl', {'email': 'a@b.it'})


def test_build_certbot_command_emits_eab_flags_from_ui_config(ca_manager, temp_files):
    cmd, _env = ca_manager.build_certbot_command(
        domain='example.com',
        email='admin@example.com',
        ca_provider='zerossl',
        dns_provider='cloudflare',
        dns_config={},
        account_config={'eab_kid': 'ui-kid', 'eab_hmac': 'ui-hmac'},
        temp_files=temp_files,
    )
    assert eab_config_of(cmd, temp_files) == {'eab-kid': 'ui-kid', 'eab-hmac-key': 'ui-hmac'}


def test_private_ca_optional_eab_reaches_certbot(ca_manager, temp_files):
    # The Private CA panel offers optional EAB fields ("if required by
    # your CA") — e.g. a public EAB-enforcing CA like Actalis configured
    # through the generic entry. Those credentials were collected and
    # saved but never emitted, because the EAB block only ran for
    # providers with requires_eab=True.
    cmd, _env = ca_manager.build_certbot_command(
        domain='example.com',
        email='admin@example.com',
        ca_provider='private_ca',
        dns_provider='cloudflare',
        dns_config={},
        account_config={
            'acme_url': 'https://acme-api.actalis.com/acme/directory',
            'eab_kid': 'pc-kid',
            'eab_hmac': 'pc-hmac',
        },
        temp_files=temp_files,
    )
    assert eab_config_of(cmd, temp_files) == {'eab-kid': 'pc-kid', 'eab-hmac-key': 'pc-hmac'}
    assert '--server' in cmd
    assert cmd[cmd.index('--server') + 1] == 'https://acme-api.actalis.com/acme/directory'


def test_private_ca_without_eab_omits_flags(ca_manager):
    cmd, _env = ca_manager.build_certbot_command(
        domain='example.com',
        email='admin@example.com',
        ca_provider='private_ca',
        dns_provider='cloudflare',
        dns_config={},
        account_config={'acme_url': 'https://step-ca.internal:9000/acme/directory'},
    )
    assert '--eab-kid' not in cmd
    assert '--eab-hmac-key' not in cmd
    assert '-c' not in cmd


def test_the_eab_pair_is_never_on_the_command_line(ca_manager, temp_files):
    """#1461: certbot logs its command line ("Arguments: [...]") to
    <cert>/logs/letsencrypt.log on every run. The pair goes in a 0600 config
    file, which certbot reads and does not log; the caller owns the file."""
    cmd, _env = ca_manager.build_certbot_command(
        domain='example.com', email='admin@example.com', ca_provider='zerossl',
        dns_provider='cloudflare', dns_config={},
        account_config={'eab_kid': 'kid-on-disk', 'eab_hmac': 'hmac-on-disk'},
        temp_files=temp_files,
    )
    assert not [part for part in cmd if 'kid-on-disk' in part or 'hmac-on-disk' in part], cmd
    assert '--eab-kid' not in cmd and '--eab-hmac-key' not in cmd
    path = cmd[cmd.index('-c') + 1]
    assert temp_files == [path]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_builder_with_no_owner_for_the_file_refuses(ca_manager):
    """A credentials file nobody removes is a key left on disk."""
    with pytest.raises(ValueError, match='temp_files'):
        ca_manager.build_certbot_command(
            domain='example.com', email='admin@example.com', ca_provider='zerossl',
            dns_provider='cloudflare', dns_config={},
            account_config={'eab_kid': 'k', 'eab_hmac': 'h'})


def test_a_line_break_in_a_credential_cannot_add_a_setting(ca_manager, temp_files):
    """The file is certbot config: a value with a newline would be a second key."""
    with pytest.raises(ValueError, match='line break'):
        ca_manager.build_certbot_command(
            domain='example.com', email='admin@example.com', ca_provider='zerossl',
            dns_provider='cloudflare', dns_config={},
            account_config={'eab_kid': 'k', 'eab_hmac': 'h\nserver = https://evil.example/dir'},
            temp_files=temp_files)
    assert temp_files == []


def test_non_eab_public_ca_ignores_stray_eab_fields(ca_manager):
    # Let's Encrypt must never receive externalAccountBinding, even if
    # leftover EAB fields linger in the saved provider config.
    kid, hmac = ca_manager.get_eab_credentials('letsencrypt', {
        'eab_kid': 'stray', 'eab_hmac': 'stray',
    })
    assert (kid, hmac) == (None, None)


def test_validate_ca_configuration_accepts_ui_spelling(ca_manager):
    ok, msg = ca_manager.validate_ca_configuration('zerossl', {
        'eab_kid': 'ui-kid', 'eab_hmac': 'ui-hmac',
    })
    assert ok, msg


def test_validate_ca_configuration_rejects_missing_eab(ca_manager):
    ok, msg = ca_manager.validate_ca_configuration('zerossl', {})
    assert not ok
    assert 'EAB' in msg


def test_eab_hmac_is_secret_named_but_kid_is_not():
    assert _is_secret_key('eab_hmac')
    assert _is_secret_key('eab_hmac_key')
    # The Key ID is an account identifier the UI repopulates on load.
    assert not _is_secret_key('eab_kid')


def test_mask_secrets_masks_ui_saved_eab_hmac():
    masked = mask_secrets_in_settings({
        'ca_providers': {
            'zerossl': {'eab_kid': 'kid', 'eab_hmac': 'topsecret', 'email': 'a@b.it'},
        },
    })
    provider = masked['ca_providers']['zerossl']
    assert provider['eab_hmac'] == SECRET_MASK_SENTINEL
    assert provider['eab_kid'] == 'kid'
    assert provider['email'] == 'a@b.it'


def test_strip_masked_values_preserves_blank_eab_hmac():
    # The UI never repopulates the HMAC field, so each save posts ''.
    # Blank on a secret-named key means "keep the on-disk value".
    cleaned = _strip_masked_values({
        'ca_providers': {
            'zerossl': {'eab_kid': 'kid', 'eab_hmac': '', 'email': 'a@b.it'},
        },
    })
    assert 'eab_hmac' not in cleaned['ca_providers']['zerossl']
    assert cleaned['ca_providers']['zerossl']['eab_kid'] == 'kid'
