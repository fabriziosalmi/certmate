"""The unified backup must carry the PKI and audit state that lives in data_dir.

Regression test for #409. ``create_unified_backup`` archived only
``certificates/`` + ``settings.json``, so the private CA signing key, every
client certificate it signed, the CRL and the audit chain were silently
absent from every backup. An operator who followed the documented DR
procedure came back unable to issue, renew or revoke a single client
certificate — with no error at backup time, because ``total_domains`` still
looked right.

The restore side is allowlisted to the same subtrees on purpose: honouring an
arbitrary ``data/...`` member would let a tampered archive drop a
``settings.json`` into data_dir behind the deploy-hook revalidation gate that
guards the real settings entry.
"""

import stat
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


def _seed_pki_and_audit(data_dir):
    """Lay out the data_dir state a private-CA deployment actually holds."""
    ca = data_dir / "certs" / "ca"
    ca.mkdir(parents=True)
    (ca / "ca.crt").write_text("CA CERT")
    (ca / "ca.key").write_text("CA PRIVATE KEY")

    client = data_dir / "certs" / "client" / "alice"
    client.mkdir(parents=True)
    (client / "cert.pem").write_text("CLIENT CERT")
    (client / "privkey.pem").write_text("CLIENT KEY")

    crl = data_dir / "certs" / "crl"
    crl.mkdir(parents=True)
    (crl / "ca.crl").write_text("CRL")

    audit = data_dir / "audit"
    audit.mkdir(parents=True)
    (audit / "certificate_audit.log").write_text("chain entry\n")
    (audit / "audit_signing.key").write_text("AUDIT SIGNING KEY")

    # Must NOT be archived under data/: settings travel in their own entry,
    # which is the one the deploy-hook validation gate inspects.
    (data_dir / "settings.json").write_text('{"domains": []}')


def _archive_names(file_ops, filename):
    path = file_ops.backup_dir / "unified" / filename
    with zipfile.ZipFile(path) as zf:
        return set(zf.namelist())


def test_backup_archives_ca_key_client_certs_crl_and_audit(file_ops):
    _seed_pki_and_audit(file_ops.data_dir)

    filename = file_ops.create_unified_backup({"domains": []}, "test")
    assert filename, "create_unified_backup returned None"
    names = _archive_names(file_ops, filename)

    assert "data/certs/ca/ca.key" in names, "the CA signing key is the whole point"
    assert "data/certs/ca/ca.crt" in names
    assert "data/certs/client/alice/privkey.pem" in names
    assert "data/certs/crl/ca.crl" in names
    assert "data/audit/certificate_audit.log" in names
    assert "data/audit/audit_signing.key" in names

    # settings.json rides in its own entry, never under data/.
    assert "settings.json" in names
    assert "data/settings.json" not in names


def test_backup_metadata_counts_the_data_files(file_ops):
    _seed_pki_and_audit(file_ops.data_dir)

    filename = file_ops.create_unified_backup({"domains": []}, "test")
    path = file_ops.backup_dir / "unified" / filename
    with zipfile.ZipFile(path) as zf:
        import json

        meta = json.loads(zf.read("backup_metadata.json"))
        settings_meta = json.loads(zf.read("settings.json"))["metadata"]

    assert meta["data_files"] == 7
    # The count must agree in both copies of the metadata.
    assert settings_meta["data_files"] == meta["data_files"]


def test_backup_without_a_private_ca_still_works(file_ops):
    """No data/certs or data/audit on disk is the common case, not an error."""
    filename = file_ops.create_unified_backup({"domains": []}, "test")
    assert filename
    names = _archive_names(file_ops, filename)
    assert not any(n.startswith("data/") for n in names)


def test_restore_round_trips_the_ca_key_with_locked_down_permissions(file_ops, tmp_path):
    _seed_pki_and_audit(file_ops.data_dir)
    filename = file_ops.create_unified_backup({"domains": []}, "test")
    backup_path = file_ops.backup_dir / "unified" / filename

    # Restore into a pristine instance.
    dest = tmp_path / "restored"
    cert_dir = dest / "certificates"
    data_dir = dest / "data"
    backup_dir = dest / "backups"
    logs_dir = dest / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir(parents=True)
    restored = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)

    assert restored.restore_unified_backup(str(backup_path)) is True

    ca_key = data_dir / "certs" / "ca" / "ca.key"
    assert ca_key.read_text() == "CA PRIVATE KEY"
    assert (data_dir / "certs" / "client" / "alice" / "privkey.pem").exists()
    assert (data_dir / "certs" / "crl" / "ca.crl").exists()
    assert (data_dir / "audit" / "certificate_audit.log").exists()

    # Private key material must not come back group/world readable.
    assert stat.S_IMODE(ca_key.stat().st_mode) == 0o600
    assert stat.S_IMODE((data_dir / "certs" / "ca" / "ca.crt").stat().st_mode) == 0o640


def test_restore_refuses_non_allowlisted_data_entries(file_ops, tmp_path):
    """A tampered archive must not write settings.json through the data/ branch."""
    _seed_pki_and_audit(file_ops.data_dir)
    filename = file_ops.create_unified_backup({"domains": []}, "test")
    backup_path = file_ops.backup_dir / "unified" / filename

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(backup_path) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            dst.writestr(item, src.read(item.filename))
        dst.writestr("data/settings.json", '{"deploy_hooks": {"global_hooks": ["rm -rf /"]}}')
        dst.writestr("data/../escaped.txt", "nope")

    dest = tmp_path / "restored2"
    cert_dir = dest / "certificates"
    data_dir = dest / "data"
    backup_dir = dest / "backups"
    logs_dir = dest / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir(parents=True)
    restored = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)

    assert restored.restore_unified_backup(str(tampered)) is True

    # The allowlisted PKI state came back...
    assert (data_dir / "certs" / "ca" / "ca.key").exists()
    # ...while the smuggled entries did not overwrite settings or escape data_dir.
    assert '"rm -rf /"' not in (data_dir / "settings.json").read_text()
    assert not (dest / "escaped.txt").exists()
