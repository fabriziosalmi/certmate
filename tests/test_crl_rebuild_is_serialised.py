"""Concurrent revocations of different certs must not drop a serial from the CRL.

revoke_certificate rebuilds the entire crl.pem from the full revoked set, but
held only the per-IDENTIFIER metadata lock. Two revocations of different certs
take different identifier locks, so nothing serialised the global rebuild: one
thread could read the revoked set before the other committed and write crl.pem
in an order that dropped the other's serial from the signed CRL — while both
metadata files said revoked and both calls returned success. Relying parties
then accept the still-listed leaf until next_update.

PrivateCAGenerator now exposes crl_lock(), and every caller that rebuilds the
CRL (revoke_certificate, CRLManager.update_crl) holds it around the whole
list-revoked -> generate_crl unit.
"""
import threading

import pytest
from cryptography import x509

from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def ca(tmp_path_factory):
    """Module-scoped: generating a 4096-bit CA is expensive and these tests
    only need one. Each test fully rewrites crl.pem and reads it back, so they
    do not depend on each other's CRL state (Copilot)."""
    d = tmp_path_factory.mktemp('ca')
    g = PrivateCAGenerator(d)
    assert g.initialize()
    return g


def _serials(ca):
    crl = x509.load_pem_x509_crl(ca.crl_path.read_bytes())
    return sorted(r.serial_number for r in crl)


def test_the_crl_lock_serialises_the_rebuild(ca):
    """A reads a partial set and writes last; B writes first with the full set.
    Under the lock A cannot interleave, so both serials survive."""
    shared = {'revoked': []}
    recA = {'serial_number': 1001, 'revoked_at': None, 'reason_revoked': 'x'}
    recB = {'serial_number': 2002, 'revoked_at': None, 'reason_revoked': 'y'}
    a_read = threading.Event()

    def revoke_a():
        with ca.crl_lock():
            shared['revoked'].append(recA)
            a_read.set()
            ca.generate_crl(list(shared['revoked']))

    def revoke_b():
        a_read.wait(3)
        with ca.crl_lock():
            shared['revoked'].append(recB)
            ca.generate_crl(list(shared['revoked']))

    tA = threading.Thread(target=revoke_a)
    tB = threading.Thread(target=revoke_b)
    tA.start(); tB.start(); tA.join(5); tB.join(5)
    assert not tA.is_alive() and not tB.is_alive(), "threads did not finish"

    assert _serials(ca) == [1001, 2002]


def test_crl_lock_is_reentrant_safe_across_calls(ca):
    """Sequential rebuilds still work — the lock is released each time."""
    with ca.crl_lock():
        ca.generate_crl([{'serial_number': 1, 'revoked_at': None,
                          'reason_revoked': 'a'}])
    with ca.crl_lock():
        ca.generate_crl([{'serial_number': 1, 'revoked_at': None,
                          'reason_revoked': 'a'},
                         {'serial_number': 2, 'revoked_at': None,
                          'reason_revoked': 'b'}])
    assert _serials(ca) == [1, 2]


def test_revoke_certificate_holds_the_crl_lock():
    import inspect
    from modules.core.client_certificates import ClientCertificateManager
    src = inspect.getsource(ClientCertificateManager.revoke_certificate)
    assert 'self.private_ca.crl_lock()' in src


def test_update_crl_holds_the_crl_lock():
    import inspect
    from modules.core.ocsp_crl import CRLManager
    src = inspect.getsource(CRLManager.update_crl)
    assert 'self.private_ca.crl_lock()' in src


def test_two_instances_for_the_same_ca_dir_share_the_lock(tmp_path):
    """The lock must be process-wide for a CA, not per instance: a second
    PrivateCAGenerator for the same ca_dir must serialise against the first,
    or two of them could race the same crl.pem."""
    d = tmp_path / 'ca'
    d.mkdir()
    a = PrivateCAGenerator(d)
    b = PrivateCAGenerator(d)
    assert a._crl_lock is b._crl_lock

    other = tmp_path / 'ca2'
    other.mkdir()
    c = PrivateCAGenerator(other)
    assert a._crl_lock is not c._crl_lock
