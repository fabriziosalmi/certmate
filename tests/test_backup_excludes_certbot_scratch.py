"""The unified backup must not archive certbot's ephemeral scratch/log dirs.

certbot is invoked with ``--config-dir``/``--work-dir``/``--logs-dir`` all
pointing at ``certificates/<domain>/`` (see CertificateManager.create_certificate),
so each domain directory accumulates ``logs/`` (verbose certbot logs) and
``work/`` (scratch). ``create_unified_backup`` used to ``rglob("*")`` the whole
tree into the ZIP on every settings save — including those bloat dirs — which,
right after a certbot run, piled IO/CPU/disk onto an already memory-tight
container. ``accounts/`` and ``archive/`` are intentionally retained because
certbot needs that lineage/account state to renew a restored certificate.
"""

import zipfile

import pytest

from modules.core.file_operations import FileOperations


pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    return FileOperations(cert_dir, data_dir, backup_dir, logs_dir)


def _seed_domain_tree(cert_dir, domain):
    """Lay out a realistic certbot config-dir for one domain."""
    dom = cert_dir / domain
    (dom).mkdir()
    # Canonical served files + CertMate metadata — MUST be backed up.
    (dom / "cert.pem").write_text("CERT")
    (dom / "chain.pem").write_text("CHAIN")
    (dom / "fullchain.pem").write_text("FULLCHAIN")
    (dom / "privkey.pem").write_text("KEY")
    (dom / "metadata.json").write_text('{"dns_provider": "cloudflare"}')
    # certbot scratch/log dirs — MUST be excluded.
    (dom / "logs").mkdir()
    (dom / "logs" / "letsencrypt.log").write_text("x" * 5000)
    (dom / "work").mkdir()
    (dom / "work" / "scratch.tmp").write_text("y" * 5000)
    # certbot lineage/account state — MUST be retained for restored renewal.
    (dom / "archive").mkdir()
    (dom / "archive" / "cert1.pem").write_text("z" * 5000)
    (dom / "accounts").mkdir()
    (dom / "accounts" / "regr.json").write_text("a" * 5000)


def test_backup_keeps_cert_files_excludes_logs_and_work(file_ops):
    _seed_domain_tree(file_ops.cert_dir, "example.com")

    filename = file_ops.create_unified_backup({"domains": []}, "test")
    assert filename, "create_unified_backup returned None"

    with zipfile.ZipFile(file_ops.backup_dir / "unified" / filename) as zf:
        names = zf.namelist()

    assert "certificates/example.com/cert.pem" in names
    assert "certificates/example.com/privkey.pem" in names
    assert "certificates/example.com/metadata.json" in names
    assert "certificates/example.com/archive/cert1.pem" in names
    assert "certificates/example.com/accounts/regr.json" in names

    leaked = [
        n for n in names
        if any(part in n for part in ("/logs/", "/work/"))
    ]
    assert not leaked, f"certbot scratch/log dirs leaked into backup: {leaked}"
