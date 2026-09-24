"""Regression guard: scheduled client-certificate renewal must not run away.

check_renewals() used to select candidates via list_client_certificates(
revoked=False), which filters ONLY on 'revoked'. After a renewal created cert
B and marked cert A superseded_by=B (leaving A revoked=False,
renewal_enabled=True, expires_at unchanged), the next daily sweep re-renewed A
-> C -> D forever: one fresh CA-signed key+cert per run, filling the disk.

check_renewals now skips any cert that is superseded or already expired, and
renew_certificate disables renewal on the superseded cert. These tests pin all
three properties, including the two-run count that the runaway violated.

Driven against a real (self-signed) private CA, no network — same pattern as
test_client_certificate_lifecycle.py.
"""
import json
from datetime import timedelta

import pytest

from modules.core.client_certificates import ClientCertificateManager
from modules.core.private_ca import PrivateCAGenerator
from modules.core.utils import utc_now

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    pca = PrivateCAGenerator(tmp_path_factory.mktemp("ca"))
    assert pca.initialize() is True
    return pca


@pytest.fixture
def mgr(ca, tmp_path):
    return ClientCertificateManager(tmp_path / "client-certs", ca)


def _create(mgr, cn):
    ok, err, data = mgr.create_client_certificate(common_name=cn)
    assert ok is True, f"create failed: {err}"
    return data["identifier"]


def _meta_path(mgr, ident):
    return next(mgr.client_certs_dir.glob(f"*/{ident}/metadata.json"))


def _patch_meta(mgr, ident, **fields):
    path = _meta_path(mgr, ident)
    meta = json.loads(path.read_text())
    meta.update(fields)
    path.write_text(json.dumps(meta))


def _count(mgr):
    return len(mgr.list_client_certificates())


def test_superseded_cert_is_not_renewed(mgr):
    ident = _create(mgr, "superseded.example.com")
    # Reproduce the exact bug state: superseded but still revoked=False,
    # renewal_enabled=True, and within the renewal threshold so that WITHOUT
    # the superseded guard it would be re-renewed.
    _patch_meta(
        mgr, ident,
        superseded_by="superseded.example.com-deadbeef",
        renewal_enabled=True,
        expires_at=(utc_now() + timedelta(days=1)).isoformat(),
    )

    before = _count(mgr)
    checked, renewed, idents = mgr.check_renewals()

    assert renewed == 0
    assert ident not in idents
    assert _count(mgr) == before  # no new cert issued


def test_expired_cert_is_not_renewed(mgr):
    ident = _create(mgr, "expired.example.com")
    # Already past expiry, not superseded, renewal still enabled.
    _patch_meta(
        mgr, ident,
        renewal_enabled=True,
        expires_at=(utc_now() - timedelta(days=1)).isoformat(),
    )

    before = _count(mgr)
    checked, renewed, idents = mgr.check_renewals()

    assert renewed == 0
    assert ident not in idents
    assert _count(mgr) == before


def test_within_threshold_cert_renews_exactly_once_across_two_runs(mgr):
    ident = _create(mgr, "due.example.com")
    # Inside the 30-day threshold but NOT yet expired -> a legitimate renewal.
    _patch_meta(mgr, ident, expires_at=(utc_now() + timedelta(days=1)).isoformat())

    before = _count(mgr)  # == 1 (just this cert)

    # First sweep renews it once.
    _, renewed1, idents1 = mgr.check_renewals()
    assert renewed1 == 1 and ident in idents1

    # The old cert is now superseded (and renewal disabled); the freshly issued
    # cert is a full year out. A SECOND sweep must renew NOTHING.
    _, renewed2, idents2 = mgr.check_renewals()
    assert renewed2 == 0 and idents2 == []

    # The whole point of the fix: exactly ONE new cert exists after two runs,
    # not one-per-run forever.
    assert _count(mgr) - before == 1

    old_meta = mgr.get_certificate_metadata(ident)
    assert old_meta["superseded_by"]           # marked superseded
    assert old_meta["renewal_enabled"] is False  # belt-and-braces guard set


# --- the runaway the guards above did not cover (#591 re-triage) ---------
#
# Every test above creates with the DEFAULT 365-day validity and moves
# `expires_at` by hand. So the replacement is always a year out and a second
# sweep naturally renews nothing — which is why
# test_within_threshold_cert_renews_exactly_once_across_two_runs passes and
# says so in its own comment ("the freshly issued cert is a full year out").
#
# The case it cannot reach: `renewal_threshold_days` is written as 30 at
# creation and never reconsidered against the certificate's own validity,
# while `_inherited_days_valid` makes the replacement reuse that validity. A
# certificate at or below 30 days is therefore born inside its own renewal
# window, and so is everything it produces. Measured before the fix: a 10-day
# certificate renewed on EVERY sweep — seven runs, seven renewals, eight
# CA-signed keys on disk, with nothing pruning them.

def _create_with(mgr, cn, days_valid):
    ok, err, data = mgr.create_client_certificate(common_name=cn,
                                                  days_valid=days_valid)
    assert ok is True, f"create failed: {err}"
    return data["identifier"]


def test_a_short_lived_cert_is_not_renewed_the_moment_it_exists(mgr):
    """THE regression. Seven sweeps over a fresh 10-day certificate."""
    _create_with(mgr, "ten.example.com", 10)

    for _ in range(7):
        _, renewed, _ = mgr.check_renewals()
        assert renewed == 0, "a freshly issued certificate was renewed"

    assert _count(mgr) == 1, f"{_count(mgr)} certificates after seven sweeps"


def test_a_short_lived_cert_still_renews_when_it_is_actually_due(mgr):
    """CONTROL, and the one that matters most: a fix that simply stopped
    renewing short certificates would pass the test above and silently break
    auto-renewal — which is the whole feature, and the direction #395 is
    heading with six-day certificates."""
    ident = _create_with(mgr, "due.example.com", 10)

    # A third of ten days is three, so it is not due at four and is at three.
    _patch_meta(mgr, ident,
                expires_at=(utc_now() + timedelta(days=4)).isoformat())
    _, renewed, _ = mgr.check_renewals()
    assert renewed == 0, "renewed a day early"

    _patch_meta(mgr, ident,
                expires_at=(utc_now() + timedelta(days=3)).isoformat())
    _, renewed, idents = mgr.check_renewals()
    assert renewed == 1 and ident in idents


def test_the_replacement_is_not_due_on_the_next_sweep(mgr):
    """The runaway's actual shape: it was never one bad renewal, it was that
    every replacement arrived already due."""
    ident = _create_with(mgr, "chain.example.com", 10)
    _patch_meta(mgr, ident,
                expires_at=(utc_now() + timedelta(days=1)).isoformat())

    _, first, _ = mgr.check_renewals()
    assert first == 1
    _, second, _ = mgr.check_renewals()

    assert second == 0, "the replacement was due the moment it was issued"
    assert _count(mgr) == 2


@pytest.mark.parametrize("days_valid,expected", [
    (365, 30),    # the configured value already leaves room: unchanged
    (90, 30),     # ditto
    (30, 10),     # exactly at the threshold — the case that ran away
    (10, 3),
    (6, 2),       # the shape #395 is heading for
    (3, 1),
    (2, None),    # a third rounds to zero: a nightly sweep cannot manage it
    (1, None),
])
def test_the_threshold_leaves_the_replacement_room(mgr, days_valid, expected):
    """A third of the validity, so a replacement has two thirds of its life
    before it is due again. `None` is a refusal, not a silent skip: the sweep
    logs which certificate and why."""
    assert ClientCertificateManager._effective_renewal_threshold(
        {"days_valid": days_valid, "renewal_threshold_days": 30}) == expected


def test_an_unreadable_threshold_falls_back_rather_than_raising(mgr):
    """CONTROL on the parse: settings written by hand, or by an older
    version, must not take the sweep down for every other certificate."""
    for bad in (None, "", "abc", [30], True):
        assert ClientCertificateManager._effective_renewal_threshold(
            {"days_valid": 365, "renewal_threshold_days": bad}) == 30
