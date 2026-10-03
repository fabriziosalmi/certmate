"""A renewal threshold above 30 days renews when it says (#966, part 2), under the one rule of
#393 (modules/core/renewal_policy.py).

`renewal_threshold_days` goes up to 365, but certbot has its own gate: without
`--force-renewal` it renews only inside 30 days of expiry, and CertMate never
told it otherwise. Measured on 2026-09-27 with the real binary: 60, 45 and 31
days left all came back "not yet due". So a threshold of 45 behaved as 30.

Decision on #966 (option 1): when the threshold, and only the threshold, calls
a certificate due while certbot would refuse (30 days or more left), the
renewal is forced, as the ARI path already does. Two guards:

* at most `early_renewals_per_sweep` forced renewals per sweep (default 10,
  clamped 1-50), so raising the threshold on a large estate does not become
  one night of orders against the CA;
* a certificate younger than a week (since #393: or a third of its lifetime,
  whichever is less) is never renewed early, so a miscomputed expiry costs at
  most one renewal a week instead of one a night.

A certificate that `needs_renewal` for another reason (a missing or mismatched
served key) is not forced: those repair themselves from the lineage (measured
on #966, scenarios A and C), and a forced renewal would ship a new key for
nothing.

Since #393 CertMate decides and certbot executes: every renewal decided by time is forced, not
only the early ones, so certbot's own gate takes no part. The guards apply to an EARLY renewal,
one the operator's threshold brings ahead of the lifetime rule; a threshold above half the
lifetime does not count at all (the lifetime rule decides), and the minimum age is a week or a
third of the lifetime, whichever is less.
"""
import datetime
from unittest.mock import MagicMock

import pytest

from modules.core import renewal_policy
from modules.core.certificates import CertificateManager
from modules.core.utils import utc_now

pytestmark = [pytest.mark.unit]

DAY = 86400


def _manager(tmp_path, *, seconds_left, age_days=60, key_state='present',
             needs_renewal=None, fail=(), lifetime_days=90):
    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    lefts = seconds_left if isinstance(seconds_left, dict) else None
    now = utc_now()

    def validity(domain):
        left = lefts[domain] if lefts else seconds_left
        not_after = now + datetime.timedelta(seconds=left)
        return not_after - datetime.timedelta(days=lifetime_days), not_after

    def info(domain, settings=None, use_cache=True):
        # What get_certificate_info answers: the decision of renewal_policy, plus a key problem.
        left = lefts[domain] if lefts else seconds_left
        threshold = CertificateManager._coerce_renewal_threshold_days(settings)
        instant, _ = renewal_policy.renews_at(*validity(domain), threshold)
        due = utc_now() >= instant or key_state != 'present'
        return {'exists': True, 'seconds_left': left, 'days_left': left // DAY,
                'private_key_state': key_state, 'renews_at': renewal_policy.stamp(instant),
                'renewal_info': None,
                'needs_renewal': due if needs_renewal is None else needs_renewal}

    manager._served_validity = MagicMock(side_effect=validity)
    manager._refresh_renewal_info = MagicMock(return_value=None)

    manager.get_certificate_info = MagicMock(side_effect=info)
    calls = []

    def renew(domain, force=False):
        calls.append((domain, force))
        if domain in fail:
            raise RuntimeError('Renewal failed: urn:ietf:params:acme:error:serverInternal')
        left = lefts[domain] if lefts else seconds_left
        # certbot's own gate, as measured: not due at 30 days or more, unforced.
        if left >= 30 * DAY and not force:
            return {'success': True, 'renewed': False}
        return {'success': True, 'renewed': True}

    manager.renew_certificate = MagicMock(side_effect=renew)
    manager._certificate_age_seconds = MagicMock(return_value=age_days * DAY)
    manager._audit_scheduled_renew = MagicMock()
    manager._record_renewal_metrics = MagicMock()
    manager._publish_failed_event = MagicMock()
    manager._publish_renewed_event = MagicMock()
    return manager, calls


def _summary():
    return {'checked': 0, 'renewed': 0, 'failed': 0, 'skipped_busy': 0,
            'skipped_not_due': 0, 'ari_advanced': 0, 'ari_postponed': 0, 'reissue_required': 0,
            'auto_reissued': 0, 'early_forced': 0, 'early_deferred': 0}


def _sweep(manager, domains, settings):
    summary = _summary()
    for d in domains:
        manager._renew_if_due(d, settings, summary)
    return summary


def test_a_threshold_of_45_renews_at_40_days_left(tmp_path):
    manager, calls = _manager(tmp_path, seconds_left=40 * DAY)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 45})
    assert calls == [('a.example.com', True)]
    assert summary['renewed'] == 1 and summary['early_forced'] == 1
    assert summary['skipped_not_due'] == 0


def test_the_boundary_is_certbot_s_not_the_rounded_day_count(tmp_path):
    """30 days and a few hours left: days_left says 30, certbot says not due.
    It must be forced, or it lands in skipped_not_due again."""
    manager, calls = _manager(tmp_path, seconds_left=30 * DAY + 3600)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 31})
    assert calls == [('a.example.com', True)]
    assert summary['renewed'] == 1


def test_a_renewal_decided_by_time_is_forced_even_inside_certbot_s_window(tmp_path):
    """#393: CertMate decides, so certbot is told to renew. Before, certbot "kept its say" inside
    its own window, which is how its rule (2/3 of the lifetime in 5.8) came to decide instead."""
    manager, calls = _manager(tmp_path, seconds_left=20 * DAY)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 45})
    assert calls == [('a.example.com', True)]
    assert summary['renewed'] == 1 and summary['early_forced'] == 0


def test_the_default_threshold_changes_nothing(tmp_path):
    manager, calls = _manager(tmp_path, seconds_left=40 * DAY)
    summary = _sweep(manager, ['a.example.com'], {})
    assert calls == []
    assert summary['renewed'] == 0 and summary['early_forced'] == 0


@pytest.mark.parametrize('key_state', ['missing', 'mismatched'])
def test_a_key_problem_is_not_a_reason_to_force(tmp_path, key_state):
    """needs_renewal is forced true for these, but they repair from the
    lineage; forcing would ship a new key for nothing."""
    manager, calls = _manager(tmp_path, seconds_left=60 * DAY, key_state=key_state)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 30})
    assert calls == [('a.example.com', False)]
    assert summary['early_forced'] == 0 and summary['skipped_not_due'] == 1


def test_a_threshold_above_half_the_lifetime_does_not_renew_a_fresh_certificate(tmp_path):
    """A threshold at or above the lifetime used to call a fresh certificate due every night,
    and only the age guard held it. Since #393 such a threshold means nothing for this
    certificate and the lifetime rule decides: 85 days left of 90 is not due."""
    manager, calls = _manager(tmp_path, seconds_left=85 * DAY, age_days=5)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 365})
    assert calls == []
    assert summary['early_deferred'] == 0 and summary['renewed'] == 0


def test_a_certificate_younger_than_the_minimum_age_is_never_forced_early(tmp_path):
    """Guard 2, which the rule now keeps for inconsistent data only: an early renewal leaves at
    most half the lifetime, so a consistent certificate is at least that old. The age is read
    from notBefore apart from the expiry, and a certificate that says it is 5 days old with
    40 of 90 days left is not one to force."""
    manager, calls = _manager(tmp_path, seconds_left=40 * DAY, age_days=5)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 45})
    assert calls == []
    assert summary['early_deferred'] == 1 and summary['renewed'] == 0


def test_an_unknown_age_does_not_block_a_due_renewal(tmp_path):
    manager, calls = _manager(tmp_path, seconds_left=40 * DAY)
    manager._certificate_age_seconds.return_value = None
    _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 45})
    assert calls == [('a.example.com', True)]


def test_the_cap_holds_and_the_rest_wait(tmp_path):
    domains = [f'd{i}.example.com' for i in range(12)]
    manager, calls = _manager(tmp_path, seconds_left=40 * DAY)
    summary = _sweep(manager, domains, {'renewal_threshold_days': 45})
    assert summary['early_forced'] == 10 and summary['early_deferred'] == 2
    assert [d for d, _ in calls] == domains[:10]


def test_a_certificate_inside_certbot_s_window_is_not_held_by_the_cap(tmp_path):
    """The cap is for early renewals only: an urgent one never waits."""
    lefts = {f'e{i}.example.com': 40 * DAY for i in range(3)}
    lefts['urgent.example.com'] = 5 * DAY
    manager, calls = _manager(tmp_path, seconds_left=lefts)
    summary = _sweep(manager, list(lefts), {'renewal_threshold_days': 45,
                                            'early_renewals_per_sweep': 1})
    assert ('urgent.example.com', True) in calls
    assert summary['early_forced'] == 1 and summary['early_deferred'] == 2


def test_a_failed_forced_attempt_counts_against_the_cap(tmp_path):
    """The cap is on orders sent to the CA, not on successes."""
    manager, calls = _manager(tmp_path, seconds_left=40 * DAY, fail=('a.example.com',))
    summary = _sweep(manager, ['a.example.com', 'b.example.com'],
                     {'renewal_threshold_days': 45, 'early_renewals_per_sweep': 1})
    assert calls == [('a.example.com', True)]
    assert summary['failed'] == 1 and summary['early_deferred'] == 1


@pytest.mark.parametrize('raw,expected', [(0, 1), (999, 50), ('x', 10), (None, 10), ('7', 7)])
def test_the_cap_is_clamped(raw, expected):
    assert CertificateManager._early_renewal_cap({'early_renewals_per_sweep': raw}) == expected


def test_the_age_is_read_from_the_certificate(tmp_path):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'age.example.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=3))
            .not_valid_after(now + datetime.timedelta(days=87))
            .sign(key, hashes.SHA256()))
    (tmp_path / 'age.example.com').mkdir()
    (tmp_path / 'age.example.com' / 'cert.pem').write_bytes(
        cert.public_bytes(serialization.Encoding.PEM))
    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    age = manager._certificate_age_seconds('age.example.com')
    assert 3 * DAY - 60 <= age <= 3 * DAY + 60
    assert manager._certificate_age_seconds('absent.example.com') is None


def test_exactly_thirty_days_left_is_forced(tmp_path):
    """At exactly the lifetime rule's 30 days a renewal is due by time and forced, and it is not
    early: the cap does not hold it."""
    manager, calls = _manager(tmp_path, seconds_left=30 * DAY)
    summary = _sweep(manager, ['a.example.com'], {'renewal_threshold_days': 45})
    assert calls == [('a.example.com', True)]
    assert summary['early_forced'] == 0


def test_only_a_renewal_the_threshold_brings_ahead_of_the_lifetime_rule_is_early():
    """The rule the guards apply to, on its own terms (renewal_policy.is_early)."""
    now = utc_now()
    not_after = now + datetime.timedelta(days=40)
    not_before = not_after - datetime.timedelta(days=90)
    assert renewal_policy.is_early(not_before, not_after, 45, now) is True
    assert renewal_policy.is_early(not_before, not_after, 30, now) is False       # not due yet
    later = now + datetime.timedelta(days=15)                                      # 25 days left
    assert renewal_policy.is_early(not_before, not_after, 45, later) is False     # the lifetime rule
    assert renewal_policy.is_early(not_before, not_after, 60, now) is False       # over half: ignored
