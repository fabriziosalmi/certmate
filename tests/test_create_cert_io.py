"""
Regression tests for the create_certificate() I/O quick wins:

1. Settings are loaded at most once. Several branches of create_certificate
   need the settings dict (default CA, challenge type, DNS provider, key
   shape, propagation time). They used to each call load_settings()
   independently, re-reading settings (a flask.g deepcopy in-request, or a
   real disk read for background/script callers). The lazy-once pattern
   loads at most once and reuses the result across branches.

2. The cert copy block reads each live/ file once (instead of copying then
   re-opening the destination) AND preserves the source file's permission
   bits. shutil.copy used to carry the mode across implicitly; the rewrite
   uses write_bytes (which respects the umask) so it MUST call
   shutil.copymode explicitly — otherwise privkey.pem (mode 0600) would be
   written world-readable (0644), a security regression. Test 2 is the
   guard: it fails if anyone reverts to a naive write_bytes.

NOTE: the permission assertions are Linux semantics (the Docker test
harness); native Windows ignores POSIX mode bits, which is why this suite
runs in the container.
"""
import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.shell import MockShellExecutor


pytestmark = [pytest.mark.unit]


# Distinct, recognisable contents per file so a byte-for-byte comparison is
# meaningful (and so a mix-up between files would be caught).
_LIVE_CONTENTS = {
    'cert.pem': b'-----BEGIN CERT-----\ncert-bytes\n-----END CERT-----\n',
    'chain.pem': b'-----BEGIN CERT-----\nchain-bytes\n-----END CERT-----\n',
    'fullchain.pem': b'-----BEGIN CERT-----\nfullchain-bytes\n-----END CERT-----\n',
    'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nkey-bytes\n-----END PRIVATE KEY-----\n',
}


class _StagingShellExecutor(MockShellExecutor):
    """A MockShellExecutor that, on a successful certbot run, stages the
    live/<domain>/ files certbot would have produced so create_certificate's
    copy block actually runs. Files are written with the restrictive modes a
    real certbot install uses (private key 0600)."""

    def __init__(self, cert_dir: Path, domain: str, modes: dict | None = None):
        super().__init__()
        self._cert_dir = Path(cert_dir)
        self._domain = domain
        # privkey is the security-sensitive one; default to 0600 like certbot.
        self._modes = modes or {f: 0o600 if f == 'privkey.pem' else 0o644
                                for f in CERTIFICATE_FILES}
        self.set_next_result(returncode=0)

    def run(self, cmd, **kwargs):
        result = super().run(cmd, **kwargs)
        if result.returncode == 0:
            live_dir = self._cert_dir / self._domain / 'live' / self._domain
            live_dir.mkdir(parents=True, exist_ok=True)
            for cert_file in CERTIFICATE_FILES:
                p = live_dir / cert_file
                p.write_bytes(_LIVE_CONTENTS[cert_file])
                os.chmod(p, self._modes[cert_file])
        return result


def _make_manager(tmp_path, domain, shell):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
        'default_key_type': 'ecdsa',
        'default_elliptic_curve': 'secp384r1',
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'

    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'api_token': 'duck-token'}, 'default'
    )

    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
        shell_executor=shell,
    )


def test_settings_loaded_at_most_once(tmp_path):
    """A create that leaves CA provider, challenge type and key shape
    unspecified exercises several settings-dependent branches. With the
    lazy-once pattern the settings dict is loaded exactly once and reused.

    _write_pfx (best-effort, post-issuance) is patched out so the only
    load_settings calls counted come from the create flow itself.
    """
    domain = 'app.example.duckdns.org'
    shell = _StagingShellExecutor(tmp_path, domain)
    mgr = _make_manager(tmp_path, domain, shell)

    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.create_certificate(
            domain=domain,
            email='test@example.com',
            dns_provider='duckdns',
            staging=True,
            # ca_provider, challenge_type and key shape intentionally omitted
            # so multiple settings-dependent branches run.
        )

    assert result['success'] is True
    # The branches each consult settings; the lazy-once pattern must collapse
    # those into a single load. (At least one load must have happened, proving
    # the branches ran and we're actually testing the dedup.)
    call_count = mgr.settings_manager.load_settings.call_count
    assert call_count == 1, (
        f"expected settings loaded exactly once, got {call_count}"
    )


def test_copy_preserves_bytes_and_mode(tmp_path):
    """The copy block must reproduce the source bytes exactly AND preserve
    the source permission bits. This is the regression guard for the
    security concern: privkey.pem staged at 0600 must land at 0600, not the
    umask default. Fails if copymode is dropped in favour of a naive
    write_bytes.
    """
    domain = 'secure.example.duckdns.org'
    shell = _StagingShellExecutor(tmp_path, domain)
    mgr = _make_manager(tmp_path, domain, shell)

    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.create_certificate(
            domain=domain,
            email='test@example.com',
            dns_provider='duckdns',
            staging=True,
        )

    assert result['success'] is True

    cert_output_dir = tmp_path / domain
    live_dir = cert_output_dir / 'live' / domain

    for cert_file in CERTIFICATE_FILES:
        src = live_dir / cert_file
        dst = cert_output_dir / cert_file
        assert dst.exists(), f"{cert_file} was not copied to the cert dir"
        # Bytes identical to source (and to what we staged).
        assert dst.read_bytes() == _LIVE_CONTENTS[cert_file]
        assert dst.read_bytes() == src.read_bytes()
        # Mode preserved from source.
        src_mode = stat.S_IMODE(os.stat(src).st_mode)
        dst_mode = stat.S_IMODE(os.stat(dst).st_mode)
        assert dst_mode == src_mode, (
            f"{cert_file}: dst mode {oct(dst_mode)} != src mode {oct(src_mode)}"
        )

    # Explicit, hard-coded check on the security-sensitive private key: it
    # MUST be 0600 regardless of the process umask.
    privkey_dst = cert_output_dir / 'privkey.pem'
    assert stat.S_IMODE(os.stat(privkey_dst).st_mode) == 0o600, (
        "privkey.pem must remain mode 0600 — a naive write_bytes without "
        "copymode would leave it world-readable under the default umask"
    )


def test_settings_not_loaded_for_fully_specified_http01(tmp_path):
    """Laziness is preserved: an HTTP-01 caller that supplies CA provider,
    challenge type and key shape needs nothing from settings, so
    load_settings must never be called. This pins that the lazy-once
    initializer didn't turn into an unconditional load at the top.
    """
    domain = 'http.example.com'
    shell = _StagingShellExecutor(tmp_path, domain)
    mgr = _make_manager(tmp_path, domain, shell)

    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.create_certificate(
            domain=domain,
            email='test@example.com',
            ca_provider='letsencrypt',
            challenge_type='http-01',
            key_type='ecdsa',
            elliptic_curve='secp384r1',
            staging=True,
        )

    assert result['success'] is True
    assert mgr.settings_manager.load_settings.call_count == 0, (
        "a fully-specified HTTP-01 create must not load settings at all"
    )
