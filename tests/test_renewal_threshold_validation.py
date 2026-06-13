"""renewal_threshold_days must never silently disable renewal.

A 0/negative/non-numeric threshold makes `days_left <= threshold`
permanently False — no certificate ever renews — or raises TypeError in
the renewal worker. Two layers guard against this:

  - write path: validate_settings_post() rejects an out-of-range or
    non-numeric value at the API boundary so it never persists;
  - read path: CertificateManager._coerce_renewal_threshold_days()
    clamps any value that slipped in via a hand-edited settings.json.
"""

import pytest

from modules.core.settings import validate_settings_post
from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


# --- write path ------------------------------------------------------------

@pytest.mark.parametrize("bad", [0, -5, 366, 1000])
def test_validate_rejects_out_of_range(bad):
    with pytest.raises(ValueError):
        validate_settings_post({"renewal_threshold_days": bad})


@pytest.mark.parametrize("bad", ["abc", None, [], {}])
def test_validate_rejects_non_numeric(bad):
    with pytest.raises(ValueError):
        validate_settings_post({"renewal_threshold_days": bad})


@pytest.mark.parametrize("good,expected", [(1, 1), (30, 30), (365, 365), ("45", 45)])
def test_validate_accepts_and_coerces_in_range(good, expected):
    filtered, rejected, unknown = validate_settings_post({"renewal_threshold_days": good})
    assert filtered["renewal_threshold_days"] == expected
    assert not rejected and not unknown


def test_noop_echo_of_existing_value_is_not_revalidated():
    """A GET-then-POST-back of an already-persisted (even legacy) value is a
    no-op echo and must pass straight through without a spurious 400."""
    filtered, rejected, unknown = validate_settings_post(
        {"renewal_threshold_days": 30}, current={"renewal_threshold_days": 30}
    )
    assert "renewal_threshold_days" not in filtered  # dropped as echo
    assert not rejected and not unknown


# --- read path -------------------------------------------------------------

@pytest.mark.parametrize("settings,expected", [
    ({}, 30),                                   # absent -> default
    ({"renewal_threshold_days": 30}, 30),       # valid passthrough
    ({"renewal_threshold_days": "30"}, 30),     # stringified JSON number
    ({"renewal_threshold_days": 0}, 1),         # clamp up from zero
    ({"renewal_threshold_days": -10}, 1),       # clamp up from negative
    ({"renewal_threshold_days": 999}, 365),     # clamp down
    ({"renewal_threshold_days": "junk"}, 30),   # uncoercible -> default
    (None, 30),                                  # not a dict -> default
])
def test_coerce_renewal_threshold_days(settings, expected):
    assert CertificateManager._coerce_renewal_threshold_days(settings) == expected


def test_zero_threshold_does_not_disable_renewal_via_cache_key():
    """The cache key reflects the coerced threshold, not the raw 0, so a
    near-expiry cert is never bucketed under an always-False threshold."""
    key = CertificateManager._certificate_info_cache_key("ex.com", {"renewal_threshold_days": 0})
    assert "renewal_threshold_days=1" in key
