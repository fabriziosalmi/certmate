"""A new certificate must never end up beside the previous private key.

The renewal path copied certbot's four files from `live/<domain>/` to the flat
directory one at a time. `_atomic_binary_copy` is atomic per file; there was no
atomicity across the four, the exception handlers unlink credential files and
release the domain lock but roll nothing back, and `privkey.pem` is LAST in
CERTIFICATE_FILES.

So a failure on the fourth file left a new cert.pem, chain.pem and
fullchain.pem beside the OLD privkey.pem. Those flat files are what
`/api/certificates/<domain>/download` serves off local disk, what deploy hooks
ship, and what the storage backends push. The pair cannot complete a handshake.

The permanence is the part that made it dangerous rather than merely unlucky.
The next scheduled renewal fingerprints `live/`, finds it already fresh,
concludes `renewed=False` and returns BEFORE the copy loop — so nothing ever
retried it, and `check_renewals` booked the domain as `skipped_not_due`: no
failure, no `certificate_failed` event, no email. Only `force=true` broke out,
and an operator has no reason to force a certificate the dashboard says is
fine.

Two changes, tested here. The publish stages all four files and only then
promotes them, so a failure leaves the previous generation intact and
internally consistent. And the no-op branch reconciles instead of returning
blind, which is what repairs an instance that is already wedged.
"""
from __future__ import annotations

import pathlib
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'wedged.example.com'
OLD = {name: f"OLD {name} generation-1\n".encode() for name in CERTIFICATE_FILES}
NEW = {name: f"NEW {name} generation-2\n".encode() for name in CERTIFICATE_FILES}


@pytest.fixture
def manager(tmp_path):
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'cloudflare': 1},
    }
    settings_manager.get_domain_dns_provider.return_value = 'cloudflare'
    dns_manager = MagicMock()
    dns_manager.get_dns_provider_account_config.return_value = (
        {'api_token': 'token'}, 'production')
    shell = MockShellExecutor()
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()
    manager = CertificateManager(
        cert_dir=cert_dir, settings_manager=settings_manager,
        dns_manager=dns_manager, shell_executor=shell)
    return manager, shell, cert_dir


def _seed(cert_dir, *, flat, live):
    """A domain directory with a flat copy and certbot's live copy."""
    domain_dir = cert_dir / DOMAIN
    live_dir = domain_dir / 'live' / DOMAIN
    live_dir.mkdir(parents=True)
    for name, content in flat.items():
        (domain_dir / name).write_bytes(content)
    for name, content in live.items():
        (live_dir / name).write_bytes(content)
    (domain_dir / 'metadata.json').write_text(
        '{"domain": "%s", "dns_provider": "cloudflare", '
        '"account_id": "production"}' % DOMAIN)
    return domain_dir, live_dir


def _flat(domain_dir):
    return {name: (domain_dir / name).read_bytes()
            for name in CERTIFICATE_FILES if (domain_dir / name).exists()}


# --------------------------------------------------------------------------
# The publish is one unit
# --------------------------------------------------------------------------

def test_a_publish_that_fails_partway_leaves_the_previous_pair_intact(manager, monkeypatch):
    """The exact shape: privkey.pem is last, and writing it fails."""
    cert_manager, _shell, cert_dir = manager
    domain_dir, live_dir = _seed(cert_dir, flat=OLD, live=NEW)

    real_read_bytes = pathlib.Path.read_bytes

    def fail_on_the_private_key(self):
        if self.name == 'privkey.pem' and 'live' in self.parts:
            raise OSError("simulated I/O failure on the fourth file")
        return real_read_bytes(self)

    monkeypatch.setattr(pathlib.Path, 'read_bytes', fail_on_the_private_key)

    with pytest.raises(OSError):
        cert_manager._publish_flat_files(live_dir, domain_dir)

    monkeypatch.undo()
    served = _flat(domain_dir)
    assert served == OLD, (
        "the served copy is a mixture of generations. Whatever is in cert.pem "
        "no longer matches privkey.pem, and /download hands that pair to "
        "whoever asks for it"
    )
    assert not list(domain_dir.glob('*.staging')), (
        "staging files were left behind for the storage backends and the "
        "next listing to trip over"
    )


def test_a_publish_that_succeeds_replaces_every_file(manager):
    cert_manager, _shell, cert_dir = manager
    domain_dir, live_dir = _seed(cert_dir, flat=OLD, live=NEW)

    published = cert_manager._publish_flat_files(live_dir, domain_dir)

    assert _flat(domain_dir) == NEW
    assert published == NEW, "the returned bytes must be what was published"
    assert not list(domain_dir.glob('*.staging'))


def test_the_private_key_keeps_its_permissions(manager):
    """certbot writes privkey.pem 0600; a world-readable copy is a leak."""
    cert_manager, _shell, cert_dir = manager
    domain_dir, live_dir = _seed(cert_dir, flat=OLD, live=NEW)
    (live_dir / 'privkey.pem').chmod(0o600)
    (domain_dir / 'privkey.pem').chmod(0o644)

    cert_manager._publish_flat_files(live_dir, domain_dir)

    mode = (domain_dir / 'privkey.pem').stat().st_mode & 0o777
    assert mode == 0o600, f"privkey.pem landed {oct(mode)}"


# --------------------------------------------------------------------------
# A no-op renewal repairs instead of returning blind
# --------------------------------------------------------------------------

def test_a_no_op_renewal_republishes_a_served_copy_that_disagrees(manager):
    """The wedged instance heals itself on the next nightly run."""
    cert_manager, shell, cert_dir = manager
    # The state a half-finished publish leaves: three new files, old key.
    wedged = dict(NEW)
    wedged['privkey.pem'] = OLD['privkey.pem']
    domain_dir, _live_dir = _seed(cert_dir, flat=wedged, live=NEW)
    shell.set_next_result(returncode=0, stdout="Cert not yet due for renewal")

    result = cert_manager.renew_certificate(DOMAIN)

    assert result['success'] is True
    assert result['renewed'] is False
    assert _flat(domain_dir) == NEW, (
        "the renewal ran, saw nothing was due, and left the mismatched pair "
        "on disk exactly as it found it — which is how this state became "
        "permanent in the first place"
    )
    assert result.get('repaired') == ['privkey.pem'], (
        f"the repair must be reported, not silent: got {result.get('repaired')}"
    )


def test_a_no_op_renewal_touches_nothing_when_the_copy_agrees(manager):
    """No spurious writes on the ordinary daily path."""
    cert_manager, shell, cert_dir = manager
    domain_dir, _live_dir = _seed(cert_dir, flat=NEW, live=NEW)
    before = {name: (domain_dir / name).stat().st_mtime_ns
              for name in CERTIFICATE_FILES}
    shell.set_next_result(returncode=0, stdout="Cert not yet due for renewal")

    result = cert_manager.renew_certificate(DOMAIN)

    assert result['renewed'] is False
    assert result.get('repaired') is None
    after = {name: (domain_dir / name).stat().st_mtime_ns
             for name in CERTIFICATE_FILES}
    assert after == before, "files were rewritten although nothing had changed"


def test_a_certificate_with_no_live_directory_is_not_called_stale(manager):
    """Imported or externally-managed certs have nothing to reconcile."""
    cert_manager, _shell, cert_dir = manager
    domain_dir = cert_dir / DOMAIN
    domain_dir.mkdir()
    for name, content in OLD.items():
        (domain_dir / name).write_bytes(content)

    assert cert_manager._stale_flat_files(
        domain_dir / 'live' / DOMAIN, domain_dir) == []


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])


def test_leftovers_from_a_killed_attempt_are_removed_before_publishing(tmp_path):
    """A process killed between staging and promote (SIGKILL, OOM) leaves
    *.staging files that no exception handler can clean. The next publish
    removes them first; the domain lock guarantees they are not in flight."""
    from modules.core.certificates import CertificateManager
    from unittest.mock import MagicMock
    src = tmp_path / 'live'
    dest = tmp_path / 'flat'
    src.mkdir()
    dest.mkdir()
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        (src / name).write_text(f'new-{name}')
        (dest / name).write_text(f'old-{name}')
    (dest / 'privkey.pem.staging').write_text('from-a-dead-attempt')
    (dest / 'cert.pem.staging').write_text('from-a-dead-attempt')
    cm = CertificateManager.__new__(CertificateManager)
    cm.shell_executor = MagicMock()
    published = cm._publish_flat_files(src, dest)
    assert set(published) == {'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'}
    assert not list(dest.glob('*.staging'))
    assert (dest / 'privkey.pem').read_text() == 'new-privkey.pem'
