"""A restored backup must come back with a renewable certbot lineage.

Regression test for #410. A ZIP cannot carry symlinks — ``zipfile.write()``
dereferences them — so certbot's ``live/<domain>/*.pem`` came back from a
backup as plain files. certbot reports a parsefail on such a lineage and
*skips* it, so after a DR restore every scheduled renewal failed, or exited 0
reporting ``renewed: False``, forever: silently, until the certificate
expired. ``_quarantine_broken_lineage`` existed for exactly this case but was
only ever called from the create/reissue path.

The repair rebuilds the links from the ``archive/`` generation that the backup
did preserve, and runs both at restore time and at the top of
``renew_certificate`` (so instances restored by an older version heal
themselves on the next renewal attempt).
"""

import os
import zipfile

import pytest

from modules.core.file_operations import FileOperations
from modules.core.utils import repair_certbot_lineage_symlinks


pytestmark = [pytest.mark.unit]

DOMAIN = "example.com"


def _seed_certbot_lineage(cert_dir, domain=DOMAIN, generation=3):
    """Lay out a healthy certbot lineage the way certbot itself does."""
    dom = cert_dir / domain
    live = dom / "live" / domain
    archive = dom / "archive" / domain
    renewal = dom / "renewal"
    for d in (live, archive, renewal):
        d.mkdir(parents=True)

    renewal.joinpath(f"{domain}.conf").write_text("# certbot renewal config\n")
    for stem in ("cert", "chain", "fullchain", "privkey"):
        # Older generations exist too — the repair must pick the newest.
        for n in range(1, generation + 1):
            archive.joinpath(f"{stem}{n}.pem").write_text(f"{stem} gen {n}")
        link = live / f"{stem}.pem"
        link.symlink_to(os.path.relpath(archive / f"{stem}{generation}.pem", live))
        # What CertMate actually serves from: flat copies at the domain root.
        dom.joinpath(f"{stem}.pem").write_text(f"{stem} gen {generation}")
    return dom


@pytest.fixture
def file_ops(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    return FileOperations(cert_dir, data_dir, backup_dir, logs_dir)


def test_zip_flattens_symlinks_then_restore_repairs_them(file_ops, tmp_path):
    _seed_certbot_lineage(file_ops.cert_dir)

    filename = file_ops.create_unified_backup({"domains": [DOMAIN]}, "test")
    backup_path = file_ops.backup_dir / "unified" / filename

    dest = tmp_path / "restored"
    dirs = [dest / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir(parents=True)
    restored = FileOperations(*dirs)

    assert restored.restore_unified_backup(str(backup_path)) is True

    live_cert = dirs[0] / DOMAIN / "live" / DOMAIN / "cert.pem"
    assert live_cert.exists(), "the lineage did not come back at all"
    # The whole point: certbot only accepts a lineage whose live/ members are
    # symlinks into archive/.
    assert live_cert.is_symlink(), "live/cert.pem came back as a flat file"
    assert live_cert.resolve().name == "cert3.pem", "must link the newest generation"
    assert live_cert.read_text() == "cert gen 3"
    # Relative, like certbot's own, so the data dir stays movable.
    assert not os.path.isabs(os.readlink(live_cert))

    for stem in ("chain", "fullchain", "privkey"):
        link = dirs[0] / DOMAIN / "live" / DOMAIN / f"{stem}.pem"
        assert link.is_symlink(), f"{stem}.pem not relinked"


def test_repair_is_a_noop_on_a_healthy_lineage(file_ops):
    dom = _seed_certbot_lineage(file_ops.cert_dir)
    assert repair_certbot_lineage_symlinks(dom, DOMAIN) is False


def test_repair_is_a_noop_without_a_renewal_conf(file_ops):
    dom = _seed_certbot_lineage(file_ops.cert_dir)
    (dom / "renewal" / f"{DOMAIN}.conf").unlink()
    # Flatten live/ the way a restore would.
    for stem in ("cert", "chain", "fullchain", "privkey"):
        link = dom / "live" / DOMAIN / f"{stem}.pem"
        data = link.read_text()
        link.unlink()
        link.write_text(data)
    assert repair_certbot_lineage_symlinks(dom, DOMAIN) is False


def test_repair_leaves_flat_files_intact_when_archive_is_incomplete(file_ops):
    dom = _seed_certbot_lineage(file_ops.cert_dir)
    for stem in ("cert", "chain", "fullchain", "privkey"):
        link = dom / "live" / DOMAIN / f"{stem}.pem"
        data = link.read_text()
        link.unlink()
        link.write_text(data)
    # An archive missing one member (a partial restore) must not be "repaired"
    # into a half-linked lineage.
    for n in (1, 2, 3):
        (dom / "archive" / DOMAIN / f"privkey{n}.pem").unlink()

    assert repair_certbot_lineage_symlinks(dom, DOMAIN) is False
    live_cert = dom / "live" / DOMAIN / "cert.pem"
    assert live_cert.exists() and not live_cert.is_symlink()
    assert live_cert.read_text() == "cert gen 3"


def test_repair_is_all_or_nothing_when_generations_do_not_overlap(file_ops):
    """privkey exists only as gen 4 while cert runs 1..3: no common generation.

    Relinking per-member here would leave live/ half symlink, half flat file
    — a state certbot handles no better than the one we started in.
    """
    dom = _seed_certbot_lineage(file_ops.cert_dir)
    for stem in ("cert", "chain", "fullchain", "privkey"):
        link = dom / "live" / DOMAIN / f"{stem}.pem"
        data = link.read_text()
        link.unlink()
        link.write_text(data)

    archive = dom / "archive" / DOMAIN
    for n in (1, 2, 3):
        (archive / f"privkey{n}.pem").unlink()
    (archive / "privkey4.pem").write_text("privkey gen 4")

    assert repair_certbot_lineage_symlinks(dom, DOMAIN) is False
    for stem in ("cert", "chain", "fullchain", "privkey"):
        link = dom / "live" / DOMAIN / f"{stem}.pem"
        assert not link.is_symlink(), f"{stem}.pem was relinked in a partial repair"


def test_repair_picks_the_generation_present_for_every_member(file_ops):
    """privkey lags a generation (mid-renewal snapshot) -> link the common one."""
    dom = _seed_certbot_lineage(file_ops.cert_dir)
    for stem in ("cert", "chain", "fullchain", "privkey"):
        link = dom / "live" / DOMAIN / f"{stem}.pem"
        data = link.read_text()
        link.unlink()
        link.write_text(data)
    (dom / "archive" / DOMAIN / "privkey3.pem").unlink()

    assert repair_certbot_lineage_symlinks(dom, DOMAIN) is True
    live_cert = dom / "live" / DOMAIN / "cert.pem"
    assert live_cert.is_symlink()
    assert live_cert.resolve().name == "cert2.pem"
