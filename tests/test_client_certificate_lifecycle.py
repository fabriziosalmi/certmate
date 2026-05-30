"""End-to-end lifecycle coverage for ClientCertificateManager.

modules/core/client_certificates.py was ~15% covered: only RBAC was exercised,
not the issue/list/get/revoke/renew/stats lifecycle. These tests drive the real
manager against a real (self-signed) private CA — issuance signs with the
``cryptography`` library, no network — so they cover the actual code paths, not
mocks.

The 4096-bit CA keygen is the only slow bit, so it is generated once per module
and shared; each test gets its own client-cert directory for isolation.
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


def _create(mgr, cn="api.example.com", **kw):
    ok, err, data = mgr.create_client_certificate(common_name=cn, **kw)
    assert ok is True, f"create failed: {err}"
    return data


class TestCreate:
    def test_create_issues_signed_cert_with_files_and_metadata(self, mgr):
        data = _create(mgr, cn="svc.example.com", email="svc@example.com")
        ident = data["identifier"]
        assert ident.startswith("svc.example.com-")
        meta = data["metadata"]
        assert meta["common_name"] == "svc.example.com"
        assert meta["revoked"] is False
        assert meta["extended_key_usage"] == ["clientAuth"]
        assert int(meta["serial_number"]) > 0
        # Files really landed on disk.
        crt = mgr.get_certificate_file(ident, "crt")
        key = mgr.get_certificate_file(ident, "key")
        assert crt and crt.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key and b"PRIVATE KEY" in key

    @pytest.mark.parametrize("cn", ["", "   "])
    def test_blank_common_name_rejected(self, mgr, cn):
        ok, err, data = mgr.create_client_certificate(common_name=cn)
        assert ok is False and data is None and "Common name" in err

    def test_overlong_common_name_rejected(self, mgr):
        ok, err, _ = mgr.create_client_certificate(common_name="x" * 65)
        assert ok is False and "64 characters" in err

    @pytest.mark.parametrize("days", [0, -5, 999999])
    def test_out_of_range_validity_rejected(self, mgr, days):
        ok, err, _ = mgr.create_client_certificate(common_name="a.example.com", days_valid=days)
        assert ok is False and "days_valid" in err


class TestListAndGet:
    def test_list_and_metadata_round_trip(self, mgr):
        d1 = _create(mgr, cn="one.example.com")
        d2 = _create(mgr, cn="two.example.com")
        listed = {c["identifier"] for c in mgr.list_client_certificates()}
        assert {d1["identifier"], d2["identifier"]} <= listed
        meta = mgr.get_certificate_metadata(d1["identifier"])
        assert meta and meta["common_name"] == "one.example.com"

    def test_get_metadata_unknown_returns_none(self, mgr):
        assert mgr.get_certificate_metadata("nope-00000000") is None

    def test_get_file_unknown_returns_none(self, mgr):
        assert mgr.get_certificate_file("nope-00000000", "crt") is None


class TestRevoke:
    def test_revoke_marks_and_filters(self, mgr):
        ident = _create(mgr, cn="revoke-me.example.com")["identifier"]
        ok, err = mgr.revoke_certificate(ident, reason="keyCompromise")
        assert ok is True and err is None
        meta = mgr.get_certificate_metadata(ident)
        assert meta["revoked"] is True and meta["reason_revoked"] == "keyCompromise"
        assert ident not in {c["identifier"] for c in mgr.list_client_certificates(revoked=False)}
        assert ident in {c["identifier"] for c in mgr.list_client_certificates(revoked=True)}

    def test_revoke_unknown_returns_false(self, mgr):
        ok, err = mgr.revoke_certificate("nope-00000000")
        assert ok is False and "not found" in err


class TestRenew:
    def test_renew_supersedes_original(self, mgr):
        ident = _create(mgr, cn="renew.example.com")["identifier"]
        ok, err, new_data = mgr.renew_certificate(ident)
        assert ok is True and err is None
        new_ident = new_data["identifier"]
        assert new_ident != ident
        old_meta = mgr.get_certificate_metadata(ident)
        assert old_meta["superseded_by"] == new_ident
        # The renewed cert shares the identity but has a fresh serial.
        assert new_data["metadata"]["common_name"] == "renew.example.com"
        assert new_data["metadata"]["serial_number"] != old_meta["serial_number"]

    def test_cannot_renew_revoked(self, mgr):
        ident = _create(mgr, cn="revoked-renew.example.com")["identifier"]
        mgr.revoke_certificate(ident)
        ok, err, data = mgr.renew_certificate(ident)
        assert ok is False and data is None and "revoked" in err.lower()


class TestRenewalSweepAndStats:
    def test_check_renewals_renews_near_expiry(self, mgr):
        ident = _create(mgr, cn="expiring.example.com")["identifier"]
        # Force the cert to look near-expiry by rewriting its persisted expiry.
        meta_path = next(mgr.client_certs_dir.glob(f"*/{ident}/metadata.json"))
        meta = json.loads(meta_path.read_text())
        meta["expires_at"] = (utc_now() + timedelta(days=1)).isoformat()  # inside the 30d threshold
        meta_path.write_text(json.dumps(meta))

        checked, renewed, idents = mgr.check_renewals()
        assert checked >= 1
        assert renewed >= 1 and ident in idents

    def test_statistics_counts(self, mgr):
        a = _create(mgr, cn="stat-a.example.com")["identifier"]
        _create(mgr, cn="stat-b.example.com")
        mgr.revoke_certificate(a)
        stats = mgr.get_statistics()
        assert stats["total"] >= 2
        assert stats["revoked"] >= 1
        assert stats["active"] == stats["total"] - stats["revoked"]
        assert "api-mtls" in stats["by_usage"]
