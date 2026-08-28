"""A revocation must survive a renewal that was already in flight.

`renew_certificate` read the certificate's metadata at the top, spent the
length of a key generation and a signature inside `create_client_certificate`,
and then wrote that snapshot back wholesale to mark the old certificate
superseded. A revocation landing in between was inside the window, and writing
the pre-renewal dict erased `revoked`, `revoked_at` and `reason_revoked`.

That field is what the OCSP responder answers from (`ocsp_crl.py:49`), so the
responder went back to saying **good** for a certificate the operator had just
revoked — the one answer a client trusts to decide whether to accept it. The
CRL is ordering-dependent and diverges too: `revoke_certificate` rebuilds it
from metadata at revoke time, so the serial is in that generation and gone from
the next one.

The credible trigger is not an operator clicking Renew and then Revoke — the UI
puts a confirmation in front of the revoke, which is seconds against a window of
milliseconds. It is the 03:00 `_client_certificate_renewal_job` sweep crossing a
revocation done by hand.

The fix writes back only the three fields the renewal owns, onto the metadata as
it is at that moment, instead of the snapshot from before the signing. Same
shape as the settings lost-update closed in v2.26.0: the read of a
read-modify-write must not predate a slow operation.
"""
from __future__ import annotations

import json
import threading
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

from modules.core.client_certificates import ClientCertificateManager
from modules.core.ocsp_crl import OCSPResponder
from modules.core.utils import utc_now

pytestmark = [pytest.mark.unit]

TIMEOUT = 10
SERIAL = 4242


@pytest.fixture
def mgr(tmp_path):
    return ClientCertificateManager(
        client_certs_dir=tmp_path / "client", private_ca=MagicMock()
    )


def _seed(mgr, identifier="alice-1"):
    """A live, unrevoked client certificate on disk."""
    created = utc_now()
    # The usage maps to a directory (_get_cert_subdir): "api-mtls" lands in
    # api_certs_dir. Seeding anywhere else is findable by identifier — that
    # glob is `*/<id>/metadata.json` — but invisible to list_client_certificates,
    # which only walks the three known usage directories, and therefore
    # invisible to OCSP.
    subdir = mgr.api_certs_dir / identifier
    subdir.mkdir(parents=True)
    metadata = {
        "identifier": identifier,
        "common_name": "alice",
        "email": "alice@example.com",
        "organization": "CertMate",
        "organizational_unit": "Users",
        "cert_usage": "api-mtls",
        "serial_number": SERIAL,
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(days=365)).isoformat(),
        "days_valid": 365,
        "renewal_enabled": True,
    }
    (subdir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    return subdir / "metadata.json"


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_a_revocation_during_renewal_is_not_erased(mgr):
    """The race, run for real: two threads, the file on disk as the judge."""
    metadata_file = _seed(mgr)
    signing = threading.Event()
    revoked = threading.Event()
    errors = []

    def slow_signing(**kwargs):
        # Stands in for key generation + signing: long enough for a human,
        # or the 03:00 sweep, to revoke in the middle.
        signing.set()
        assert revoked.wait(timeout=TIMEOUT), "the revoke thread never finished"
        return True, None, {"identifier": "alice-2", "serial_number": 9999}

    mgr.create_client_certificate = slow_signing        # type: ignore[assignment]

    def renew():
        try:
            mgr.renew_certificate("alice-1")
        except BaseException as error:                   # noqa: BLE001
            errors.append(error)

    def revoke():
        try:
            assert signing.wait(timeout=TIMEOUT)
            mgr.revoke_certificate("alice-1", reason="key_compromise")
        except BaseException as error:                   # noqa: BLE001
            errors.append(error)
        finally:
            revoked.set()

    threads = [threading.Thread(target=renew, daemon=True),
               threading.Thread(target=revoke, daemon=True)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=TIMEOUT)
    assert not [t for t in threads if t.is_alive()], "a thread did not finish"
    if errors:
        raise errors[0]

    final = _read(metadata_file)
    assert final.get("revoked") is True, (
        "the renewal wrote back the metadata it read before signing and erased "
        "the revocation; OCSP decides on this field and would answer 'good' "
        "for a certificate the operator revoked"
    )
    assert final.get("reason_revoked") == "key_compromise"
    assert final.get("revoked_at"), "revoked_at was lost with the revocation"
    # The renewal's own write must still land: the fix merges, it does not
    # abandon the supersede marker.
    assert final.get("superseded_by") == "alice-2"
    assert final.get("renewal_enabled") is False


def test_ocsp_still_answers_revoked_after_the_race(mgr):
    """The consequence an operator actually experiences."""
    _seed(mgr)
    signing = threading.Event()
    revoked = threading.Event()

    def slow_signing(**kwargs):
        signing.set()
        revoked.wait(timeout=TIMEOUT)
        return True, None, {"identifier": "alice-2", "serial_number": 9999}

    mgr.create_client_certificate = slow_signing        # type: ignore[assignment]

    def revoke():
        signing.wait(timeout=TIMEOUT)
        mgr.revoke_certificate("alice-1", reason="key_compromise")
        revoked.set()

    worker = threading.Thread(target=revoke, daemon=True)
    worker.start()
    mgr.renew_certificate("alice-1")
    worker.join(timeout=TIMEOUT)

    status = OCSPResponder(MagicMock(), mgr).get_cert_status(SERIAL)
    assert status["status"] == "revoked", (
        f"OCSP answered {status['status']!r} for a revoked certificate. This "
        f"is the answer a client trusts to decide whether to accept it."
    )
    assert status["reason"] == "key_compromise"


def test_the_supersede_write_still_works_without_a_race(mgr):
    """Guard the guard: the ordinary path must be unchanged."""
    metadata_file = _seed(mgr)
    mgr.create_client_certificate = (                    # type: ignore[assignment]
        lambda **kwargs: (True, None, {"identifier": "alice-2", "serial_number": 9999}))

    ok, error, data = mgr.renew_certificate("alice-1")

    assert ok and error is None and data["identifier"] == "alice-2"
    final = _read(metadata_file)
    assert final["superseded_by"] == "alice-2"
    assert final["renewal_enabled"] is False
    assert final.get("superseded_at")
    assert "revoked" not in final, "nothing revoked it; the field must not appear"


def test_both_paths_take_the_same_metadata_lock(mgr):
    """Narrow is not closed.

    Re-reading immediately before the write shrank the window from the length
    of a signature to a few microseconds, but two unlocked read-modify-writes
    can still interleave, and then either the revocation or the supersede
    marker is the one that disappears (Copilot, #603). Both paths now take the
    per-identifier lock — the SAME lock object, or it protects nothing.

    Asserted by watching who acquires it rather than by hammering threads: a
    stress test that passes 999 times out of 1000 is not evidence, and this
    is the property the correctness actually rests on.
    """
    _seed(mgr)
    taken = []
    real = mgr._metadata_lock

    def watch(identifier):
        lock = real(identifier)
        taken.append((identifier, id(lock)))
        return lock

    mgr._metadata_lock = watch                       # type: ignore[assignment]
    mgr.create_client_certificate = (                # type: ignore[assignment]
        lambda **kwargs: (True, None, {"identifier": "alice-2", "serial_number": 9999}))

    mgr.renew_certificate("alice-1")
    mgr.revoke_certificate("alice-1", reason="superseded")

    assert [i for i, _ in taken] == ["alice-1", "alice-1"], (
        f"both paths must lock on the identifier; saw {taken}"
    )
    assert len({lock_id for _, lock_id in taken}) == 1, (
        "renew and revoke took DIFFERENT lock objects, which serialises "
        "nothing — the whole point is that they contend on the same one"
    )


def test_a_lock_is_per_identifier_not_global(mgr):
    """Two different certificates must not serialise on each other."""
    assert mgr._metadata_lock("alice-1") is mgr._metadata_lock("alice-1")
    assert mgr._metadata_lock("alice-1") is not mgr._metadata_lock("bob-1")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
