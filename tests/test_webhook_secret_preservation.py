"""Masked webhook secrets/tokens survive a settings round-trip.

The notifications UI renders existing secrets as '********' and POSTs the whole
webhooks list back. Without per-item restore, an untouched secret is written to
disk as the literal sentinel — silently breaking the channel. These tests pin
the restore rule (identity match, index fallback, sentinel-only).
"""
import pytest

from modules.core.settings import (
    SECRET_MASK_SENTINEL as MASK,
    _restore_masked_list_secrets,
)

pytestmark = [pytest.mark.unit]


def test_masked_token_preserved_from_prior():
    old = [{'name': 'tg', 'type': 'telegram', 'url': '', 'token': 'REAL-BOT-TOKEN', 'chat_id': '42'}]
    new = [{'name': 'tg', 'type': 'telegram', 'url': '', 'token': MASK, 'chat_id': '42'}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['token'] == 'REAL-BOT-TOKEN'


def test_retyped_token_overrides_prior():
    old = [{'name': 'g', 'type': 'gotify', 'url': 'https://g', 'token': 'OLD'}]
    new = [{'name': 'g', 'type': 'gotify', 'url': 'https://g', 'token': 'NEW'}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['token'] == 'NEW'


def test_blank_token_left_as_is_so_user_can_clear():
    old = [{'name': 'n', 'type': 'ntfy', 'url': 'https://ntfy.sh/t', 'token': 'OLD'}]
    new = [{'name': 'n', 'type': 'ntfy', 'url': 'https://ntfy.sh/t', 'token': ''}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['token'] == ''


def test_new_webhook_with_no_prior_drops_masked_field():
    # A masked secret with no source to restore from must not persist '********'.
    new = [{'name': 'fresh', 'type': 'generic', 'url': 'https://x', 'secret': MASK}]
    _restore_masked_list_secrets([], new)
    assert 'secret' not in new[0]


def test_identity_match_survives_reorder_and_delete():
    old = [
        {'name': 'a', 'type': 'gotify', 'url': 'https://a', 'token': 'TA'},
        {'name': 'b', 'type': 'gotify', 'url': 'https://b', 'token': 'TB'},
    ]
    # User deleted 'a' and kept 'b' (now index 0) without re-typing its token.
    new = [{'name': 'b', 'type': 'gotify', 'url': 'https://b', 'token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['token'] == 'TB'  # identity, not index, picks the right secret


def test_a_renamed_webhook_drops_the_masked_secret_not_guesses_it():
    """When the identity (type, name) no longer matches any prior entry, the
    masked secret is DROPPED — never restored by list position. Guessing by
    position copied a different webhook's credential into the survivor and sent
    it to the wrong endpoint (#11)."""
    old = [{'name': 'old-name', 'type': 'gotify', 'url': 'https://g', 'token': 'KEEP'}]
    new = [{'name': 'new-name', 'type': 'gotify', 'url': 'https://g', 'token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert 'token' not in new[0] or new[0]['token'] != 'KEEP'


def test_non_secret_fields_untouched():
    old = [{'name': 'n', 'type': 'ntfy', 'url': 'https://ntfy.sh/t', 'priority': 'high', 'token': 'T'}]
    new = [{'name': 'n', 'type': 'ntfy', 'url': 'https://ntfy.sh/t', 'priority': 'urgent', 'token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['priority'] == 'urgent'  # non-secret edit preserved
    assert new[0]['token'] == 'T'          # secret restored


def test_duplicate_identity_webhooks_drop_masked_secrets():
    # Two webhooks sharing (type, name) are AMBIGUOUS: with no stable id, list
    # order is all that is left to match on, and a reorder/deletion would
    # restore the wrong one's secret — the cross-endpoint leak (type,name) was
    # chosen to avoid. So masked secrets are dropped, not guessed by position.
    old = [
        {'name': 'dup', 'type': 'generic', 'url': 'https://a', 'secret': 'S1'},
        {'name': 'dup', 'type': 'generic', 'url': 'https://b', 'secret': 'S2'},
    ]
    new = [
        {'name': 'dup', 'type': 'generic', 'url': MASK, 'secret': MASK},
        {'name': 'dup', 'type': 'generic', 'url': MASK, 'secret': MASK},
    ]
    _restore_masked_list_secrets(old, new)
    assert all('secret' not in w or w['secret'] != 'S1' for w in new)
    assert all('secret' not in w or w['secret'] != 'S2' for w in new)
