"""One rule decides when a certificate renews, and everything reads it (#393).

The rule is modules/core/renewal_policy.py. These are its table (lifetimes of 160 hours, 45,
90 and 180 days, with and without a window), the property each part exists for, and the check
that the certificate's answer (`needs_renewal`, `renews_at`) is that rule on a real certificate.
"""
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core import renewal_policy as policy

pytestmark = [pytest.mark.unit]

NOW = datetime(2026, 10, 3, 3, 0, 0)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)


def _validity(lifetime, issued_ago=timedelta(0)):
    not_before = NOW - issued_ago
    return not_before, not_before + lifetime


@pytest.mark.parametrize('lifetime, threshold, left, reason', [
    (90 * DAY, 30, 30 * DAY, policy.REASON_THRESHOLD),     # as always
    (90 * DAY, 45, 45 * DAY, policy.REASON_THRESHOLD),     # as since #966
    (90 * DAY, 46, 30 * DAY, policy.REASON_LIFETIME),      # over half: the lifetime rule
    (45 * DAY, 30, 15 * DAY, policy.REASON_LIFETIME),      # tlsserver: a third
    (45 * DAY, 20, 20 * DAY, policy.REASON_THRESHOLD),     # a threshold that fits is honoured
    (160 * HOUR, 30, 80 * HOUR, policy.REASON_LIFETIME),   # shortlived: half, under 10 days
    (180 * DAY, 30, 30 * DAY, policy.REASON_THRESHOLD),    # as always
    (365 * DAY, 30, 30 * DAY, policy.REASON_THRESHOLD),
])
def test_the_margin_for_each_lifetime(lifetime, threshold, left, reason):
    not_before, not_after = _validity(lifetime)
    instant, why = policy.renews_at(not_before, not_after, threshold)
    assert why == reason
    assert not_after - instant == left


def test_nothing_changes_for_a_ninety_day_certificate_with_the_defaults():
    """The promise of #393: a Let's Encrypt `classic` certificate renews when it always did,
    30 days before expiry, which is also certbot 5.8's two-thirds rule."""
    not_before, not_after = _validity(90 * DAY)
    assert policy.renews_at(not_before, not_after, 30)[0] == not_after - 30 * DAY
    assert policy.lifetime_margin_seconds(90 * 86400) == 30 * 86400


def _window(renew_at, end):
    return {'status': 'window', 'renew_at': policy.stamp(renew_at), 'window_end': policy.stamp(end)}


def test_a_window_brings_a_renewal_forward():
    not_before, not_after = _validity(90 * DAY, issued_ago=30 * DAY)
    instant, why = policy.renews_at(not_before, not_after, 30, _window(NOW - HOUR, NOW + DAY))
    assert why == policy.REASON_ARI and instant == NOW - HOUR


def test_a_window_postpones_a_renewal():
    not_before, not_after = _validity(90 * DAY, issued_ago=65 * DAY)      # 25 days left
    later = NOW + 5 * DAY
    instant, why = policy.renews_at(not_before, not_after, 30, _window(later, later + DAY))
    assert why == policy.REASON_ARI and instant == later


@pytest.mark.parametrize('lifetime, floor', [
    (90 * DAY, 15 * DAY), (45 * DAY, 7.5 * DAY), (160 * HOUR, 160 * HOUR / 6)])
def test_no_window_postpones_past_the_floor(lifetime, floor):
    not_before, not_after = _validity(lifetime)
    far = not_after + 300 * DAY
    instant, why = policy.renews_at(not_before, not_after, 30, _window(far, far + DAY))
    assert why == policy.REASON_ARI_FLOOR
    assert abs((not_after - instant) - floor) < timedelta(seconds=1)


def test_no_window_postpones_past_its_own_end():
    not_before, not_after = _validity(90 * DAY, issued_ago=30 * DAY)
    end = NOW + 10 * DAY
    instant, why = policy.renews_at(not_before, not_after, 30, _window(end + DAY, end))
    assert why == policy.REASON_ARI_ENDED and instant == end


@pytest.mark.parametrize('window', [
    None, {}, {'status': 'unavailable', 'renew_at': None}, {'status': 'disabled'},
    {'status': 'window', 'renew_at': None}, {'status': 'window', 'renew_at': 'not a date'}, 'junk'])
def test_anything_but_a_window_leaves_the_threshold_to_decide(window):
    not_before, not_after = _validity(90 * DAY)
    assert policy.renews_at(not_before, not_after, 30, window) == policy.renews_at(not_before, not_after, 30)


def test_the_instant_shown_is_the_instant_decided_on():
    """#962 found a shown instant a second earlier than the one acted on. Both are whole
    seconds, rounded up, so a sweep at exactly the shown second renews."""
    not_before = NOW + timedelta(microseconds=250_000)
    not_after = not_before + 45 * DAY
    instant, _ = policy.renews_at(not_before, not_after, 30)
    assert instant.microsecond == 0
    assert policy.parse_instant(policy.stamp(instant)) == instant
    assert instant >= not_after - 15 * DAY


def test_the_minimum_age_is_a_week_or_a_third_of_the_lifetime():
    assert policy.early_min_age_seconds(90 * 86400) == 7 * 86400
    assert policy.early_min_age_seconds(160 * 3600) == 160 * 3600 / 3


@pytest.mark.parametrize('text, expected', [
    ('2026-11-03T08:41:10Z', datetime(2026, 11, 3, 8, 41, 10)),
    ('2026-11-03T08:41:10', datetime(2026, 11, 3, 8, 41, 10)),
    ('2026-11-03T10:41:10+02:00', datetime(2026, 11, 3, 8, 41, 10)),
    ('', None), (None, None), ('tomorrow', None), (42, None)])
def test_an_instant_is_read_in_every_form_the_records_hold(text, expected):
    assert policy.parse_instant(text) == expected


def test_the_readers_take_the_decision_from_the_answer():
    info = {'renews_at': '2026-10-02T03:00:00Z', 'expiry_date': '2026-10-17 03:00:00'}
    assert policy.due(info, now=NOW) is True
    assert policy.due(dict(info, renews_at='2026-10-04T03:00:00Z'), now=NOW) is False
    assert policy.due({'renews_at': None}, now=NOW) is None
    assert policy.margin_days(info) == 15
    assert policy.margin_days({'renews_at': None, 'expiry_date': '2026-10-17 03:00:00'}) is None


# --- the certificate's answer is the rule, on a real certificate --------------------------------

def _certificate(tmp_path, domain, lifetime, left):
    from modules.core.utils import utc_now

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    not_after = utc_now() + left
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(not_after - lifetime).not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    (tmp_path / domain).mkdir()
    (tmp_path / domain / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize('lifetime, left, threshold, due', [
    (45 * DAY, 20 * DAY, 30, False),     # was "due" for two weeks before #393
    (45 * DAY, 14 * DAY, 30, True),
    (90 * DAY, 31 * DAY, 30, False),
    (90 * DAY, 29 * DAY, 30, True),
    (160 * HOUR, 100 * HOUR, 30, False),  # was "due" from the moment it was issued
    (160 * HOUR, 70 * HOUR, 30, True),
])
def test_the_answer_says_what_the_sweep_will_do(tmp_path, lifetime, left, threshold, due):
    from modules.core.certificates import CertificateManager
    from modules.core.utils import DeploymentStatusCache

    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    manager.ca_manager = None
    manager._certificate_info_cache = DeploymentStatusCache()
    raw = _certificate(tmp_path, 'rule.example.test', lifetime, left)

    info = manager._parse_certificate_info('rule.example.test', raw, {'dns_provider': 'cloudflare'},
                                           settings={'renewal_threshold_days': threshold})

    assert info['needs_renewal'] is due
    assert policy.due(info) is due
    expires = datetime.strptime(info['expiry_date'], '%Y-%m-%d %H:%M:%S')
    expected_margin = policy.margin(int(lifetime.total_seconds()), threshold)[0]
    assert abs((expires - policy.parse_instant(info['renews_at'])).total_seconds() - expected_margin) <= 1
