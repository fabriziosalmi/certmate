"""Client-certificate renewal must keep the validity, and never break a CSR identity.

Regression tests for #422. `renew_certificate` called
`create_client_certificate` without `days_valid` and with
`generate_key=True` unconditionally:

1. A 730-day certificate came back as a 365-day one — the operator's chosen
   validity silently halved on every renewal.
2. A certificate issued from a client-supplied CSR (`csr_required: True`) was
   "renewed" into a brand-new CertMate-generated keypair the client does not
   hold, while the original was stamped `superseded_by` +
   `renewal_enabled=False`. The working mTLS identity then expired with no
   further renewal and nothing to use in its place.
"""

from datetime import timedelta
from unittest.mock import MagicMock

import pytest

from modules.core.client_certificates import ClientCertificateManager
from modules.core.utils import utc_now


pytestmark = [pytest.mark.unit]


@pytest.fixture
def mgr(tmp_path):
    return ClientCertificateManager(
        client_certs_dir=tmp_path / "client", private_ca=MagicMock()
    )


def _metadata(**overrides):
    created = utc_now()
    md = {
        'identifier': 'alice-1',
        'common_name': 'alice',
        'email': 'alice@example.com',
        'organization': 'CertMate',
        'organizational_unit': 'Users',
        'cert_usage': 'api-mtls',
        'created_at': created.isoformat(),
        'expires_at': (created + timedelta(days=730)).isoformat(),
        'days_valid': 730,
        'csr_required': False,
        'revoked': False,
        'renewal_enabled': True,
    }
    md.update(overrides)
    return md


# --- validity inheritance --------------------------------------------------

def test_persisted_days_valid_is_used(mgr):
    assert mgr._inherited_days_valid(_metadata(days_valid=730)) == 730


def test_legacy_certificates_derive_validity_from_the_dates(mgr):
    """Issued before days_valid existed: don't reset them to the default."""
    md = _metadata()
    del md['days_valid']
    assert mgr._inherited_days_valid(md) == 730


def test_unusable_metadata_falls_back_to_the_default(mgr):
    assert mgr._inherited_days_valid({}) == 365
    assert mgr._inherited_days_valid(_metadata(days_valid=0)) == 730  # derived
    assert mgr._inherited_days_valid(
        {'days_valid': 'soon', 'created_at': 'x', 'expires_at': 'y'}) == 365


def test_a_boolean_is_not_a_duration(mgr):
    """bool is an int subclass — True must not become a 1-day certificate."""
    md = _metadata(days_valid=True)
    assert mgr._inherited_days_valid(md) == 730  # falls through to the dates


def test_renewal_passes_the_inherited_validity(mgr):
    mgr.get_certificate_metadata = MagicMock(return_value=_metadata())
    created = MagicMock(return_value=(True, None, {'identifier': 'alice-2'}))
    mgr.create_client_certificate = created

    ok, err, _ = mgr.renew_certificate('alice-1')

    assert (ok, err) == (True, None)
    assert created.call_args.kwargs['days_valid'] == 730, \
        "the operator's 730-day validity was reset to the default"


# --- CSR-issued identities -------------------------------------------------

def test_a_csr_issued_certificate_is_not_renewed_server_side(mgr):
    mgr.get_certificate_metadata = MagicMock(
        return_value=_metadata(csr_required=True))
    mgr.create_client_certificate = MagicMock()

    ok, err, data = mgr.renew_certificate('alice-1')

    assert ok is False
    assert data is None
    assert 'CSR' in err and 'private key' in err
    mgr.create_client_certificate.assert_not_called()


def test_a_refused_csr_renewal_does_not_supersede_the_working_certificate(mgr, tmp_path):
    """The original must stay renewable-by-hand and in service."""
    md = _metadata(csr_required=True)
    mgr.get_certificate_metadata = MagicMock(return_value=md)
    mgr.create_client_certificate = MagicMock()

    mgr.renew_certificate('alice-1')

    assert 'superseded_by' not in md
    assert md['renewal_enabled'] is True


def test_the_scheduled_sweep_skips_csr_certificates_with_a_clear_warning(mgr, caplog):
    """Otherwise every nightly tick writes an identical audit failure."""
    expiring = _metadata(
        csr_required=True,
        expires_at=(utc_now() + timedelta(days=5)).isoformat(),
        renewal_threshold_days=30,
    )
    mgr.list_client_certificates = MagicMock(return_value=[expiring])
    mgr.renew_certificate = MagicMock()

    with caplog.at_level('WARNING'):
        checked, renewed, ids = mgr.check_renewals()

    assert (checked, renewed, ids) == (1, 0, [])
    mgr.renew_certificate.assert_not_called()
    assert any('fresh CSR' in r.getMessage() for r in caplog.records)


def test_a_normal_expiring_certificate_is_still_auto_renewed(mgr):
    expiring = _metadata(
        expires_at=(utc_now() + timedelta(days=5)).isoformat(),
        renewal_threshold_days=30,
    )
    mgr.list_client_certificates = MagicMock(return_value=[expiring])
    mgr.renew_certificate = MagicMock(return_value=(True, None, {'identifier': 'alice-2'}))
    mgr._audit_scheduled_renew = MagicMock()

    checked, renewed, ids = mgr.check_renewals()

    assert (checked, renewed, ids) == (1, 1, ['alice-1'])
