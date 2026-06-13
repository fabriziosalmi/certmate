"""The first-run wizard must be dismissible durably (across browsers).

The Skip/X/Esc/backdrop affordances POST {wizard_dismissed: true} to
/api/web/settings so the wizard does not re-appear on another device or
after localStorage is cleared. This pins that the flag is an accepted
writable setting (distinct from setup_completed, which stays truthful for
recovery/downgrade detection) and lives in the default template.
"""
import pytest

from modules.core.settings import (
    validate_settings_post,
    PUBLIC_SETTINGS_WRITABLE_KEYS,
)

pytestmark = [pytest.mark.unit]


def test_wizard_dismissed_is_a_writable_setting():
    assert 'wizard_dismissed' in PUBLIC_SETTINGS_WRITABLE_KEYS


def test_post_accepts_wizard_dismissed():
    filtered, rejected, unknown = validate_settings_post({'wizard_dismissed': True})
    assert filtered.get('wizard_dismissed') is True
    assert not rejected and not unknown


def test_wizard_dismissed_does_not_touch_setup_completed():
    """Dismissing the wizard must NOT imply setup is complete: a POST of
    just wizard_dismissed leaves setup_completed alone."""
    filtered, _, _ = validate_settings_post({'wizard_dismissed': True})
    assert 'setup_completed' not in filtered
