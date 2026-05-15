"""
Regression test for issue #171: NETWORK_ERROR on POST /api/certificates/<name>/renew.

Root cause was that `certbot renew` injects a random sleep of up to ~8
minutes before contacting the ACME server (a default designed to avoid
stampeding Let's Encrypt when run from a flock of crontabs). Since
CertMate's renewal endpoint is always invoked interactively from the
UI / API, the sleep just made the POST time out in the browser even
though certbot eventually completed the renewal in the background.

The fix is to always pass `--no-random-sleep-on-renew` to the certbot
invocation. This test pins the flag's presence so a future refactor
that touches the cmd list cannot quietly drop it again.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


def _build_cm(tmp_path: Path, shell_executor) -> CertificateManager:
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    settings_manager = SettingsManager(
        file_ops=file_ops, settings_file=data_dir / "settings.json"
    )
    return CertificateManager(
        cert_dir=cert_dir,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
        shell_executor=shell_executor,
    )


def _seed_existing_cert(cm: CertificateManager, domain: str) -> None:
    """Plant the on-disk shape renew_certificate() probes before invoking certbot."""
    domain_dir = cm.cert_dir / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "cert.pem").write_text("placeholder")


def test_renew_cmd_includes_no_random_sleep_on_renew(tmp_path):
    shell = MagicMock()
    # The post-run codepath copies live/<domain>/* files; we short-circuit
    # by returning a non-zero exit so the function bails before reaching
    # that branch. The assertion targets the cmd that was *attempted*,
    # which is exactly what we want to pin.
    shell.run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="bail")

    cm = _build_cm(tmp_path, shell_executor=shell)
    _seed_existing_cert(cm, "example.com")

    # The post-success codepath copies live/<domain>/* files; we bail
    # out with returncode=1 so renew_certificate raises before reaching
    # that branch. The assertion targets the cmd that was *attempted*,
    # which is exactly what we want to pin — the flag must be there
    # regardless of certbot's eventual exit code.
    with pytest.raises(RuntimeError):
        cm.renew_certificate("example.com", force=True)

    assert shell.run.call_count >= 1, "shell_executor.run should have been invoked"
    cmd = shell.run.call_args.args[0]
    assert "certbot" in cmd and "renew" in cmd, f"expected certbot renew, got: {cmd!r}"
    assert "--no-random-sleep-on-renew" in cmd, (
        "--no-random-sleep-on-renew flag is missing from the certbot renew "
        "invocation; without it, certbot injects a random delay (up to ~8 "
        "min) that makes the UI POST time out as NETWORK_ERROR. See #171."
    )
    # --force-renewal goes through unchanged when force=True is passed.
    assert "--force-renewal" in cmd
