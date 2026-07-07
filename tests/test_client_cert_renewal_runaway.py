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
