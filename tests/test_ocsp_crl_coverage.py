"""
Coverage-focused unit tests for modules/core/ocsp_crl.{OCSPResponder, CRLManager}.

Before this file the module sat at 0% coverage. OCSP and CRL together are
the revocation infrastructure — if either returns the wrong answer for a
revoked serial, a compromised client cert keeps validating against trust
stores that consult the CRL or OCSP responder. That is a silent security
bypass with no log line, so unit-level pinning of every status branch is
the only way to catch a regression before it ships.

The tests use real (but minimal) PrivateCAGenerator instances and a
MagicMock for client_cert_manager — the manager's wire shape is small
(`list_client_certificates(revoked=...)` returns a list of dicts), so
mocking it is cheaper than wiring a full database fixture and just as
faithful to the contract.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509

from modules.core.ocsp_crl import OCSPResponder, CRLManager
from modules.core.private_ca import PrivateCAGenerator


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_ca(tmp_path_factory):
    """A single real PrivateCAGenerator shared across the module — the 4096-
    bit RSA keygen happens once, not 20 times."""
    ca_dir = tmp_path_factory.mktemp("ocsp_crl_ca")
    ca = PrivateCAGenerator(ca_dir=ca_dir)
    assert ca.initialize() is True
    return ca


@pytest.fixture
def cert_manager_with(monkeypatch):
    """Factory returning a MagicMock client_cert_manager whose
    list_client_certificates() returns a configurable cert list."""
    def _factory(certs):
        mgr = MagicMock()
        # The OCSP / CRL code passes `revoked=...` as a kwarg in some calls
        # and no arg in others; respect both by returning the full list and
        # letting the implementation filter.
        def _list(revoked=None):
            if revoked is True:
                return [c for c in certs if c.get('revoked')]
            return certs
        mgr.list_client_certificates.side_effect = _list
        return mgr
    return _factory


# ---------------------------------------------------------------------------
# OCSPResponder.get_cert_status — the single most security-critical method
# in the file. Every branch needs an explicit assertion.
# ---------------------------------------------------------------------------


class TestOCSPGetCertStatus:
    def test_good_status_for_active_cert(self, real_ca, cert_manager_with):
        mgr = cert_manager_with([
            {'serial_number': '12345', 'revoked': False},
        ])
        responder = OCSPResponder(real_ca, mgr)
        status = responder.get_cert_status(12345)
        assert status['status'] == 'good'
        assert status['serial_number'] == 12345
        assert status['this_update'] is not None

    def test_revoked_status_carries_revocation_metadata(self, real_ca, cert_manager_with):
        """A revoked status must include revoked_at + reason — without
        those, downstream OCSP clients fall back to 'unspecified' or
        worse, treat the response as malformed."""
        mgr = cert_manager_with([
            {
                'serial_number': '99',
                'revoked': True,
                'revoked_at': '2026-05-15T12:00:00Z',
                'reason_revoked': 'keyCompromise',
            },
        ])
        responder = OCSPResponder(real_ca, mgr)
        status = responder.get_cert_status(99)
        assert status['status'] == 'revoked'
        assert status['revoked_at'] == '2026-05-15T12:00:00Z'
        assert status['reason'] == 'keyCompromise'

    def test_unknown_status_for_missing_serial(self, real_ca, cert_manager_with):
        """Unknown ≠ Good. A serial we've never seen MUST surface as
        unknown — returning 'good' for an unknown serial would let an
        attacker present a forged cert against the OCSP probe."""
        mgr = cert_manager_with([
            {'serial_number': '1', 'revoked': False},
        ])
        responder = OCSPResponder(real_ca, mgr)
        status = responder.get_cert_status(99999)
        assert status['status'] == 'unknown'
        assert status['serial_number'] == 99999

    def test_revoked_reason_defaults_to_unspecified(self, real_ca, cert_manager_with):
        """If the stored revocation record forgot to record a reason, OCSP
        must still emit 'unspecified' rather than crashing or omitting."""
        mgr = cert_manager_with([
            {'serial_number': '7', 'revoked': True, 'revoked_at': 'x'},
        ])
        responder = OCSPResponder(real_ca, mgr)
        status = responder.get_cert_status(7)
        assert status['reason'] == 'unspecified'

    def test_manager_failure_returns_unknown_not_good(self, real_ca):
        """If the underlying cert manager raises, OCSP must NOT report 'good'
        (which would silently bless every cert during an outage). Return
        an explicit 'unknown' with error."""
        mgr = MagicMock()
        mgr.list_client_certificates.side_effect = RuntimeError("db down")
        responder = OCSPResponder(real_ca, mgr)
        status = responder.get_cert_status(42)
        assert status['status'] == 'unknown'
        assert 'error' in status


# ---------------------------------------------------------------------------
# OCSPResponder.generate_ocsp_response — pure data shaping.
# ---------------------------------------------------------------------------


class TestOCSPGenerateResponse:
    def test_successful_response_for_good_status(self, real_ca, cert_manager_with):
        responder = OCSPResponder(real_ca, cert_manager_with([]))
        resp = responder.generate_ocsp_response({
            'serial_number': 1,
            'status': 'good',
            'this_update': '2026-05-15T12:00:00Z',
            'next_update': None,
        })
        assert resp['response_status'] == 'successful'
        assert resp['certificate_status'] == 'good'
        assert resp['certificate_serial'] == 1
        # `revocation_*` keys must NOT appear on a 'good' response.
        assert 'revocation_time' not in resp
        assert 'revocation_reason' not in resp

    def test_revoked_response_carries_revocation_fields(self, real_ca, cert_manager_with):
        responder = OCSPResponder(real_ca, cert_manager_with([]))
        resp = responder.generate_ocsp_response({
            'serial_number': 2,
            'status': 'revoked',
            'this_update': '2026-05-15T12:00:00Z',
            'next_update': None,
            'revoked_at': '2026-05-15T11:00:00Z',
            'reason': 'keyCompromise',
        })
        assert resp['response_status'] == 'successful'
        assert resp['certificate_status'] == 'revoked'
        assert resp['revocation_time'] == '2026-05-15T11:00:00Z'
        assert resp['revocation_reason'] == 'keyCompromise'

    def test_malformed_input_yields_internal_error_response(self, real_ca, cert_manager_with):
        responder = OCSPResponder(real_ca, cert_manager_with([]))
        # Missing 'status' key — must not raise, must surface internal_error.
        resp = responder.generate_ocsp_response({'serial_number': 1})
        assert resp['response_status'] == 'internal_error'

    def test_response_advertises_certmate_responder_name(self, real_ca, cert_manager_with):
        """OCSP clients use the responder name in logs / UI. The literal
        string is a contract — changing it breaks any external monitoring
        that filters on it."""
        responder = OCSPResponder(real_ca, cert_manager_with([]))
        resp = responder.generate_ocsp_response({
            'serial_number': 1, 'status': 'good',
        })
        assert resp['responder_name'] == 'CertMate OCSP Responder'


# ---------------------------------------------------------------------------
# CRLManager.get_revoked_serials — input sanitisation matters.
# ---------------------------------------------------------------------------


class TestCRLGetRevokedSerials:
    def test_returns_only_revoked_serials(self, real_ca, cert_manager_with, tmp_path):
        mgr = cert_manager_with([
            {'serial_number': '1', 'revoked': False},
            {'serial_number': '2', 'revoked': True},
            {'serial_number': '3', 'revoked': True},
        ])
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        assert sorted(crl_mgr.get_revoked_serials()) == [2, 3]

    def test_skips_invalid_serial_strings(self, real_ca, cert_manager_with, tmp_path):
        """A bad row in the cert store (corrupted serial) must NOT poison
        the whole CRL — skip the bad entry and CRL the rest."""
        mgr = cert_manager_with([
            {'serial_number': 'not-an-int', 'revoked': True},
            {'serial_number': '42', 'revoked': True},
            {'serial_number': None, 'revoked': True},
        ])
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        assert crl_mgr.get_revoked_serials() == [42]

    def test_skips_zero_serials(self, real_ca, cert_manager_with, tmp_path):
        """Serial 0 is reserved (RFC 5280 §4.1.2.2 forbids it). If the store
        contains a zero (legacy data, default), don't emit it in the CRL."""
        mgr = cert_manager_with([
            {'serial_number': '0', 'revoked': True},
            {'serial_number': '5', 'revoked': True},
        ])
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        assert crl_mgr.get_revoked_serials() == [5]

    def test_manager_failure_returns_empty_not_raise(self, real_ca, tmp_path):
        """A DB failure on get_revoked_serials must NOT bubble up — it
        would crash the CRL endpoint. Return [] and log; an empty CRL is
        a safer failure mode than no CRL."""
        mgr = MagicMock()
        mgr.list_client_certificates.side_effect = RuntimeError("db down")
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        assert crl_mgr.get_revoked_serials() == []


# ---------------------------------------------------------------------------
# CRLManager.update_crl + get_crl_pem/get_crl_der + get_crl_info.
# ---------------------------------------------------------------------------


class TestCRLLifecycle:
    def test_update_crl_returns_pem_for_no_revoked(self, real_ca, cert_manager_with, tmp_path):
        crl_mgr = CRLManager(real_ca, cert_manager_with([]), tmp_path / "crl")
        crl_pem = crl_mgr.update_crl()
        assert crl_pem is not None
        assert crl_pem.startswith(b"-----BEGIN X509 CRL-----")

    def test_update_crl_lists_revoked_serials(self, real_ca, cert_manager_with, tmp_path):
        mgr = cert_manager_with([
            {'serial_number': '111', 'revoked': True},
            {'serial_number': '222', 'revoked': True},
        ])
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        crl_pem = crl_mgr.update_crl()
        crl = x509.load_pem_x509_crl(crl_pem)
        present = {entry.serial_number for entry in crl}
        assert present == {111, 222}

    def test_get_crl_der_round_trip_through_pem(self, real_ca, cert_manager_with, tmp_path):
        mgr = cert_manager_with([{'serial_number': '7', 'revoked': True}])
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        crl_mgr.update_crl()
        der = crl_mgr.get_crl_der()
        assert der is not None
        # DER is binary — must not start with the PEM header.
        assert not der.startswith(b"-----BEGIN")
        # And must parse back as a CRL.
        from cryptography import x509 as _x
        from cryptography.hazmat.primitives import serialization as _s
        crl = _x.load_der_x509_crl(der)
        assert 7 in {e.serial_number for e in crl}

    def test_get_crl_pem_auto_generates_if_missing(self, real_ca, cert_manager_with, tmp_path):
        """First call to get_crl_pem with no CRL on disk MUST trigger an
        update — otherwise dashboards calling /crl on a freshly-started
        instance would 404 forever instead of bootstrapping."""
        # Earlier tests in this class persist a CRL via update_crl(); strip
        # it so we test the actual "no CRL yet" code path.
        real_ca.crl_path.unlink(missing_ok=True)
        crl_mgr = CRLManager(real_ca, cert_manager_with([]), tmp_path / "crl")
        assert real_ca.get_crl_pem() is None
        pem = crl_mgr.get_crl_pem()
        assert pem is not None
        assert pem.startswith(b"-----BEGIN X509 CRL-----")

    def test_get_crl_info_returns_no_crl_when_unavailable(self, real_ca, cert_manager_with, tmp_path):
        """When neither disk nor regeneration can produce a CRL,
        get_crl_info must NOT raise — surface 'no_crl' so the UI shows a
        friendly state. Strip the on-disk CRL AND block regeneration."""
        real_ca.crl_path.unlink(missing_ok=True)
        mgr = MagicMock()
        mgr.list_client_certificates.side_effect = RuntimeError("db down")
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        original = real_ca.generate_crl
        real_ca.generate_crl = lambda _serials: None
        try:
            info = crl_mgr.get_crl_info()
            assert info['status'] in ('no_crl', 'error')
        finally:
            real_ca.generate_crl = original

    def test_get_crl_info_reports_revoked_count_and_issuer(self, real_ca, cert_manager_with, tmp_path):
        mgr = cert_manager_with([
            {'serial_number': '1', 'revoked': True},
            {'serial_number': '2', 'revoked': True},
            {'serial_number': '3', 'revoked': False},
        ])
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        crl_mgr.update_crl()
        info = crl_mgr.get_crl_info()
        assert info['status'] == 'available'
        assert info['revoked_count'] == 2
        assert 'CertMate CA' in info['issuer']

    def test_get_crl_der_returns_none_when_no_crl(self, real_ca, tmp_path):
        """When neither disk nor regeneration can produce a CRL, get_crl_der
        must return None — never a partial / placeholder DER blob that
        downstream parsers would mis-interpret. Strip the on-disk CRL and
        block regeneration."""
        real_ca.crl_path.unlink(missing_ok=True)
        mgr = MagicMock()
        mgr.list_client_certificates.return_value = []
        crl_mgr = CRLManager(real_ca, mgr, tmp_path / "crl")
        original = real_ca.generate_crl
        real_ca.generate_crl = lambda _serials: None
        try:
            assert crl_mgr.get_crl_der() is None
        finally:
            real_ca.generate_crl = original


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
