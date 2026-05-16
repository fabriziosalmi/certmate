"""
Targeted coverage for two specific gaps in modules/core/certificates.py:

1. Concurrent issuance locking (line 561): create_certificate guards against
   two simultaneous create/renew calls for the same domain by acquiring a
   per-domain threading.Lock in non-blocking mode and raising RuntimeError
   if it's already held. Without this guard, two concurrent issuances would
   race over the same data/certs/<domain>/ directory and trigger Let's
   Encrypt rate-limit denials.

2. check_dns_alias_records DNS failure paths: when the upstream DoH
   resolver (Cloudflare) is unreachable, returns a 5xx, or returns the
   wrong CNAME target, the function must surface a structured status
   ('error'/'missing'/'mismatch') rather than raising or silently
   reporting 'ok'.

The renewal-job N+1 gap (third bullet from the audit) is already addressed
by commit 7f7b41f's `tests/test_renewal_job_settings_reuse.py`.
"""
from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager


pytestmark = [pytest.mark.unit]


def _make_manager(tmp_path):
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
    )


# ---------------------------------------------------------------------------
# Per-domain non-blocking lock — concurrent issuance guard
# ---------------------------------------------------------------------------


class TestConcurrentIssuanceLock:
    def test_first_acquire_succeeds(self, tmp_path):
        """The lock starts free — the first caller of _get_domain_lock can
        always acquire it. Sanity check for the fixture."""
        mgr = _make_manager(tmp_path)
        lock = mgr._get_domain_lock("example.com")
        assert lock.acquire(blocking=False) is True
        lock.release()

    def test_lock_is_per_domain_not_global(self, tmp_path):
        """A lock held on example.com must NOT block acquisition of the
        lock for other.example.com. A global lock would serialise all
        cert operations, even unrelated ones — that would make multi-
        cert renewal sessions painfully slow."""
        mgr = _make_manager(tmp_path)
        lock_a = mgr._get_domain_lock("a.example.com")
        lock_b = mgr._get_domain_lock("b.example.com")

        assert lock_a.acquire(blocking=False) is True
        try:
            # b's lock must still be free
            assert lock_b.acquire(blocking=False) is True
            lock_b.release()
        finally:
            lock_a.release()

    def test_same_domain_lock_is_reused(self, tmp_path):
        """Calling _get_domain_lock twice for the same domain returns the
        same Lock instance. Without this, the second caller would get a
        fresh lock and the non-blocking guard would always succeed
        (defeating the whole point)."""
        mgr = _make_manager(tmp_path)
        first = mgr._get_domain_lock("example.com")
        second = mgr._get_domain_lock("example.com")
        assert first is second

    def test_second_create_attempt_raises_runtime_error(self, tmp_path):
        """The contract create_certificate enforces: if another thread is
        already issuing for this domain, raise RuntimeError immediately
        instead of queueing (which could pile up requests during a slow
        ACME exchange and trigger LE rate limits)."""
        mgr = _make_manager(tmp_path)

        # Pre-hold the lock from the test thread to simulate an in-flight
        # issuance.
        held = mgr._get_domain_lock("example.com")
        assert held.acquire(blocking=False) is True

        try:
            with pytest.raises(RuntimeError, match="already in progress"):
                mgr.create_certificate(
                    domain="example.com",
                    email="t@example.com",
                )
        finally:
            held.release()

    def test_concurrent_create_attempts_only_one_proceeds(self, tmp_path):
        """End-to-end multi-thread check: spawn two threads both trying to
        issue for the same domain. Exactly ONE must get past the lock
        guard; the other must raise RuntimeError. The 'lucky' thread can
        fail later for any reason (DNS provider not configured, etc.) —
        we only assert the lock barrier behaviour."""
        mgr = _make_manager(tmp_path)

        outcomes: list[str] = []
        outcomes_lock = threading.Lock()
        gate = threading.Barrier(2)

        def attempt():
            gate.wait()  # release both threads simultaneously
            try:
                mgr.create_certificate(domain="example.com",
                                        email="t@example.com")
                with outcomes_lock:
                    outcomes.append("proceeded")
            except RuntimeError as e:
                if "already in progress" in str(e):
                    with outcomes_lock:
                        outcomes.append("locked_out")
                else:
                    with outcomes_lock:
                        outcomes.append(f"other-runtime:{e}")
            except Exception as e:
                with outcomes_lock:
                    outcomes.append(f"proceeded-but-failed-downstream:{type(e).__name__}")

        t1 = threading.Thread(target=attempt)
        t2 = threading.Thread(target=attempt)
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)

        # Exactly one thread saw the lock barrier. The other made it past
        # and tripped on something downstream (missing CA manager, DNS
        # provider config, etc.) — but it MUST NOT be a "locked_out".
        locked = outcomes.count("locked_out")
        passed_lock = len(outcomes) - locked
        assert locked == 1, (
            f"exactly one thread should hit the lock barrier; outcomes={outcomes}"
        )
        assert passed_lock == 1, (
            f"exactly one thread should proceed past the lock; outcomes={outcomes}"
        )


# ---------------------------------------------------------------------------
# check_dns_alias_records — error / missing / mismatch surfacing
# ---------------------------------------------------------------------------


class TestCheckDnsAliasRecords:
    def test_ok_when_cname_target_matches(self, tmp_path):
        """The happy path: _resolve_cname returns the expected target, the
        result's `ok` is True and each check has status 'ok'."""
        mgr = _make_manager(tmp_path)
        with patch.object(CertificateManager, '_resolve_cname',
                          return_value=['_acme-challenge.lab.io.']):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',
            )
        assert result['ok'] is True
        assert len(result['checks']) == 1
        assert result['checks'][0]['status'] == 'ok'
        assert result['checks'][0]['error'] is None

    def test_mismatch_when_cname_points_elsewhere(self, tmp_path):
        """The CNAME exists but points at the WRONG delegation target —
        renewals would all silently fail. Surface 'mismatch' so the
        operator can see it."""
        mgr = _make_manager(tmp_path)
        with patch.object(CertificateManager, '_resolve_cname',
                          return_value=['_acme-challenge.other-zone.com.']):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',
            )
        assert result['ok'] is False
        assert result['checks'][0]['status'] == 'mismatch'

    def test_missing_when_cname_unset(self, tmp_path):
        """No CNAME at the source — the most common misconfiguration. Must
        report 'missing' (not 'error', which would suggest a transient
        DNS failure)."""
        mgr = _make_manager(tmp_path)
        with patch.object(CertificateManager, '_resolve_cname',
                          return_value=[]):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',
            )
        assert result['ok'] is False
        assert result['checks'][0]['status'] == 'missing'

    def test_error_when_doh_resolver_raises(self, tmp_path):
        """Cloudflare DoH down / network firewall blocks egress / DNS
        timeout. _resolve_cname raises; check_dns_alias_records must NOT
        crash. It surfaces 'error' with the exception message in the
        error field so the operator can diagnose."""
        mgr = _make_manager(tmp_path)
        with patch.object(CertificateManager, '_resolve_cname',
                          side_effect=RuntimeError("DNS query failed: timed out")):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',
            )
        assert result['ok'] is False
        assert result['checks'][0]['status'] == 'error'
        assert 'timed out' in result['checks'][0]['error']

    def test_san_domains_each_get_their_own_check(self, tmp_path):
        """A multi-SAN cert with alias mode needs every SAN's CNAME
        verified individually. The result['checks'] list must have one
        entry per source domain (deduplicated)."""
        mgr = _make_manager(tmp_path)
        with patch.object(CertificateManager, '_resolve_cname',
                          return_value=['_acme-challenge.lab.io.']):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',
                san_domains=['alt.example.com', 'extra.example.com'],
            )
        # primary + 2 SANs = 3 source domains
        assert len(result['checks']) == 3
        sources = [c['source'] for c in result['checks']]
        assert '_acme-challenge.example.com' in sources
        assert '_acme-challenge.alt.example.com' in sources
        assert '_acme-challenge.extra.example.com' in sources

    def test_overall_ok_only_if_every_check_ok(self, tmp_path):
        """If even ONE SAN's CNAME is missing, the overall result must be
        not-ok. A single missing CNAME means the cert renewal will fail."""
        mgr = _make_manager(tmp_path)

        # First call returns ok; second returns empty (missing CNAME).
        responses = iter([
            ['_acme-challenge.lab.io.'],
            [],
        ])
        with patch.object(CertificateManager, '_resolve_cname',
                          side_effect=lambda src: next(responses)):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',
                san_domains=['alt.example.com'],
            )
        assert result['ok'] is False

    def test_normalises_trailing_dot_in_cname_compare(self, tmp_path):
        """DNS CNAME records traditionally end with a trailing dot
        ('.example.com.') while the configured alias usually does not.
        The comparison must normalise both sides — otherwise every check
        falsely reports mismatch."""
        mgr = _make_manager(tmp_path)
        # Resolver returns trailing-dot form; alias config has no dot.
        with patch.object(CertificateManager, '_resolve_cname',
                          return_value=['_acme-challenge.lab.io.']):
            result = mgr.check_dns_alias_records(
                domain='example.com',
                domain_alias='_acme-challenge.lab.io',  # no trailing dot
            )
        assert result['ok'] is True


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
