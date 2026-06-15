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


def test_index_fallback_when_identity_changed():
    old = [{'name': 'old-name', 'type': 'gotify', 'url': 'https://g', 'token': 'KEEP'}]
    # User renamed the webhook but left the token masked -> fall back to index.
    new = [{'name': 'new-name', 'type': 'gotify', 'url': 'https://g', 'token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['token'] == 'KEEP'


def test_non_secret_fields_untouched():
    old = [{'name': 'n', 'type': 'ntfy', 'url': 'https://ntfy.sh/t', 'priority': 'high', 'token': 'T'}]
    new = [{'name': 'n', 'type': 'ntfy', 'url': 'https://ntfy.sh/t', 'priority': 'urgent', 'token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['priority'] == 'urgent'  # non-secret edit preserved
    assert new[0]['token'] == 'T'          # secret restored


def test_duplicate_identity_webhooks_keep_distinct_secrets():
    # Two webhooks sharing (type, url, name): each masked secret must restore
    # from its OWN prior (consume-once), not both collapse onto the first.
    old = [
        {'name': 'dup', 'type': 'generic', 'url': 'https://x', 'secret': 'S1'},
        {'name': 'dup', 'type': 'generic', 'url': 'https://x', 'secret': 'S2'},
    ]
    new = [
        {'name': 'dup', 'type': 'generic', 'url': 'https://x', 'secret': MASK},
        {'name': 'dup', 'type': 'generic', 'url': 'https://x', 'secret': MASK},
    ]
    _restore_masked_list_secrets(old, new)
    assert [w['secret'] for w in new] == ['S1', 'S2']
