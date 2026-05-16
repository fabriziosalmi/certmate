"""
Regression test for the metadata read-modify-write race in
CertificateManager.record_backend_deployment_status /
record_browser_deployment_status.

Both methods previously did `_load_metadata` -> mutate -> `_save_metadata`
without holding the per-domain lock that already existed in the class.
Two concurrent HTTP requests (one writing the `backend` block, one writing
the `browser` block) could each load `{}`, set their key, and save —
losing whichever update was persisted second.

The fix wraps the RMW in `with self._get_domain_lock(domain):`. This test
pins that contract: after many concurrent updates, both `backend` and
`browser` keys must be present in the persisted metadata.json.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager


def _make_manager(tmp_path: Path) -> CertificateManager:
    settings_mgr = MagicMock()
    dns_mgr = MagicMock()
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
    )


def _prepare_domain(cert_dir: Path, domain: str) -> None:
    (cert_dir / domain).mkdir(parents=True, exist_ok=True)


def test_concurrent_backend_and_browser_updates_both_persisted(tmp_path):
    """Both writers must end up in metadata.json — neither can lose its key."""
    mgr = _make_manager(tmp_path)
    domain = "example.com"
    _prepare_domain(tmp_path, domain)

    # A barrier maximises the contention window: both threads block until
    # both have entered, then they race into the RMW at the same moment.
    barrier = threading.Barrier(2)

    def write_backend():
        barrier.wait()
        mgr.record_backend_deployment_status(domain, {
            "deployed": True, "reachable": True,
            "method": "https", "timestamp": "2026-05-16T12:00:00Z",
        })

    def write_browser():
        barrier.wait()
        mgr.record_browser_deployment_status(domain, {
            "reachable": True,
            "checked_at": "2026-05-16T12:00:00Z",
            "method": "browser-fallback",
        })

    # Run many iterations to make a lost-write reliably surface without
    # the lock. With the lock the test is deterministic.
    for i in range(50):
        # Clear metadata between iterations so each starts from {}.
        meta_path = tmp_path / domain / "metadata.json"
        meta_path.write_text("{}")

        t1 = threading.Thread(target=write_backend, name=f"backend-{i}")
        t2 = threading.Thread(target=write_browser, name=f"browser-{i}")
        t1.start(); t2.start()
        t1.join(); t2.join()

        on_disk = json.loads(meta_path.read_text())
        deployment_status = on_disk.get("deployment_status", {})
        assert "backend" in deployment_status, (
            f"iteration {i}: backend key missing — lost write detected. "
            f"on disk: {on_disk}"
        )
        assert "browser" in deployment_status, (
            f"iteration {i}: browser key missing — lost write detected. "
            f"on disk: {on_disk}"
        )


def test_record_backend_returns_full_deployment_status_after_concurrent_browser_write(tmp_path):
    """The return value of record_backend_deployment_status must include any
    `browser` block that a concurrent writer already persisted. Holding the
    lock guarantees the read-modify-write sees a consistent snapshot."""
    mgr = _make_manager(tmp_path)
    domain = "example.com"
    _prepare_domain(tmp_path, domain)

    # Seed a browser block first (single-threaded — no race here).
    mgr.record_browser_deployment_status(domain, {
        "reachable": True, "checked_at": "2026-05-16T12:00:00Z",
        "method": "browser-fallback",
    })

    result = mgr.record_backend_deployment_status(domain, {
        "deployed": True, "reachable": True, "method": "https",
    })

    assert "backend" in result
    assert "browser" in result, (
        "record_backend_deployment_status must return the merged "
        "deployment_status including the pre-existing browser block"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
