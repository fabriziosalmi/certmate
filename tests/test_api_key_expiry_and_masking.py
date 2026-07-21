"""Secrets are masked completely, and API-key expiry is a date, not a string.

Regression tests for #432, two independent auth papercuts.

1. ``MaskedString`` revealed the first four and last four characters of every
   secret it touched — roughly twenty fields, including DNS API tokens and the
   Google service-account key — and ``GET /api/settings``, where those fields
   live, is readable by the **viewer** role. The web settings route already
   masked the same values as a flat sentinel, so the API was the weaker of two
   answers about identical data.

2. An API key's ``expires_at`` was stored verbatim and compared as a STRING.
   ``"31/12/2026"`` sorts after every ISO timestamp, so such a key never
   expired; and a JSON *number* raised an uncaught ``TypeError`` inside
   ``authenticate_api_token``, which 401s **every** bearer token on the
   instance — a denial of service one character wide.
"""

from datetime import timedelta

import pytest

from modules.api.models import MaskedString
from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SECRET_MASK_SENTINEL, SettingsManager
from modules.core.utils import utc_now


pytestmark = [pytest.mark.unit]


@pytest.fixture
def auth(tmp_path):
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    sm = SettingsManager(file_ops=FileOperations(*dirs),
                         settings_file=dirs[1] / "settings.json")
    sm.load_settings()
    am = AuthManager(sm)
    am.set_hmac_key("test-secret-for-hmac")
    return am


# --- masking ---------------------------------------------------------------

def test_a_secret_is_masked_completely():
    field = MaskedString()
    token = 'cf_liveTOKENvalue1234'
    masked = field.format(token)
    assert masked == SECRET_MASK_SENTINEL
    for fragment in (token[:4], token[-4:]):
        assert fragment not in masked


def test_masking_matches_the_settings_route_convention():
    """Two masks for the same data is how one of them ends up weaker."""
    assert MaskedString().format('anything') == SECRET_MASK_SENTINEL


def test_an_empty_value_is_left_alone():
    """An unset credential must stay visibly unset, not look configured."""
    assert MaskedString().format('') == ''
    assert MaskedString().format(None) is None


# --- expiry on write -------------------------------------------------------

def test_a_non_iso_expiry_is_rejected_at_creation(auth):
    ok, err = auth.create_api_key('eu-automation', role='viewer',
                                  expires_at='31/12/2026')
    assert ok is False
    assert 'ISO-8601' in err


def test_a_numeric_expiry_is_rejected_at_creation(auth):
    ok, err = auth.create_api_key('epoch-key', role='viewer',
                                  expires_at=1798761600)
    assert ok is False
    assert 'ISO-8601' in err


def test_a_valid_expiry_is_normalised_to_naive_utc(auth):
    ok, result = auth.create_api_key('ci', role='viewer',
                                     expires_at='2027-01-31T23:59:59+02:00')
    assert ok is True
    stored = auth.list_api_keys()[result['id']]['expires_at']
    assert stored == '2027-01-31T21:59:59'  # +02:00 -> UTC, no offset kept


def test_no_expiry_stays_no_expiry(auth):
    ok, result = auth.create_api_key('forever', role='viewer')
    assert ok is True
    assert auth.list_api_keys()[result['id']]['expires_at'] is None


# --- expiry on read --------------------------------------------------------

def _key(expires_at):
    return {'name': 'k', 'expires_at': expires_at}


def test_expiry_is_compared_as_a_date_not_a_string(auth):
    past = (utc_now() - timedelta(days=1)).isoformat()
    future = (utc_now() + timedelta(days=1)).isoformat()
    assert auth._api_key_expired(_key(past)) is True
    assert auth._api_key_expired(_key(future)) is False


def test_a_legacy_non_iso_expiry_fails_closed(auth):
    """It used to mean 'never expires' — the opposite of what was written."""
    assert auth._api_key_expired(_key('31/12/2026')) is True


def test_a_numeric_expiry_on_disk_does_not_break_every_token(auth):
    """The DoS: this raised TypeError inside the authentication loop."""
    assert auth._api_key_expired(_key(1798761600)) is True


def test_a_key_with_no_expiry_never_expires(auth):
    assert auth._api_key_expired(_key(None)) is False
    assert auth._api_key_expired(_key('')) is False


def test_an_offset_aware_expiry_is_compared_correctly(auth):
    future = (utc_now() + timedelta(hours=2)).isoformat() + '+00:00'
    assert auth._api_key_expired(_key(future)) is False


def test_authentication_rejects_an_expired_key(auth):
    ok, result = auth.create_api_key('short-lived', role='operator')
    assert ok is True
    token = result['token']
    assert auth.authenticate_api_token(token) is not None

    # Expire it on disk the way time would.
    def _expire(settings):
        settings['api_keys'][result['id']]['expires_at'] = (
            utc_now() - timedelta(seconds=1)).isoformat()

    auth.settings_manager.update(_expire, 'expire_key')
    assert auth.authenticate_api_token(token) is None


def test_the_listing_agrees_with_the_auth_path(auth):
    """The UI badge and reality must not disagree."""
    ok, result = auth.create_api_key('ci', role='viewer')
    assert ok is True

    def _corrupt(settings):
        settings['api_keys'][result['id']]['expires_at'] = '31/12/2026'

    auth.settings_manager.update(_corrupt, 'corrupt_expiry')

    assert auth.list_api_keys()[result['id']]['is_expired'] is True
    assert auth.authenticate_api_token(result['token']) is None


def test_the_exact_payload_the_ui_sends_is_accepted(auth):
    """settings-apikeys.js sends new Date(<input type=date>).toISOString(),
    i.e. '2027-01-31T00:00:00.000Z' — milliseconds and a Z suffix."""
    ok, result = auth.create_api_key('from-ui', role='viewer',
                                     expires_at='2027-01-31T00:00:00.000Z')
    assert ok is True, result
    assert auth.list_api_keys()[result['id']]['expires_at'] == '2027-01-31T00:00:00'
