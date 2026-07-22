"""Pruning the audit chain is explicit, refuses what it cannot verify, and
records itself.

Tests for #445, the last half of #437. Retention on a tamper-evident record is a
policy question, not a disk question: you cannot make deletion impossible on a
file the operator owns, so the goal is to make it non-deniable. Concretely that
means three properties, and each section below pins one of them:

1. It refuses. Every path that would delete entries whose archive does not
   verify, does not belong to this chain, or does not cover exactly the prefix,
   ends in a refusal with nothing removed.
2. It records itself. The prune appears as an `archive` entry inside the chain
   that continues, naming the range, the head hash and the archive's digest.
3. It does not overclaim, and it does not cry wolf. The pruned chain verifies
   from a signed anchor and says so; a forged anchor fails; and — the failure
   mode this whole design exists to avoid — the checkpoints that attest the
   archived entries do not make routine maintenance look like tampering.
"""

import json

import pytest

from modules.core import audit_chain, audit_verify
from modules.core.audit import AuditLogger
from modules.core.audit_prune import (
    PruneError, main, plan_prune, sha256_file,
)
from modules.core.audit_signing import AuditSigner


pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance(tmp_path):
    """A CertMate audit trail with 12 entries and checkpoints every 5."""
    signer = AuditSigner(tmp_path)
    audit = AuditLogger(tmp_path / "logs", chain_dir=tmp_path / "chain",
                        signer=signer, checkpoint_interval=5)
    for i in range(12):
        audit.log_operation("renew", "certificate", f"d{i}.example.com", "success")
    yield audit
    if audit.file_handler is not None:
        audit.audit_logger.removeHandler(audit.file_handler)
        audit.file_handler.close()


def _archive(instance, tmp_path, to_seq=5, name="prefix.json"):
    path = tmp_path / name
    path.write_text(json.dumps(instance.export_bundle(to_seq=to_seq)), encoding="utf-8")
    return path


def _reopen(instance, tmp_path, signer=None):
    """A fresh AuditLogger over the same chain — what the next boot sees."""
    audit = AuditLogger(tmp_path / "logs-reopened", chain_dir=tmp_path / "chain",
                        signer=signer or instance._signer)
    if audit.file_handler is not None:
        audit.audit_logger.removeHandler(audit.file_handler)
        audit.file_handler.close()
    return audit


def _prune(instance, tmp_path, bundle_path):
    return main(["--bundle", str(bundle_path), "--data-dir", str(tmp_path / "chain"),
                 "--key-dir", str(tmp_path), "--yes"])


# --------------------------------------------------------------------------
# 1. It refuses
# --------------------------------------------------------------------------

def test_it_refuses_an_unverifiable_archive(instance, tmp_path):
    path = _archive(instance, tmp_path)
    bundle = json.loads(path.read_text())
    bundle["entries"][2]["entry"]["status"] = "forged"

    with pytest.raises(PruneError, match="does not verify"):
        plan_prune(instance.audit_chain_file, bundle, "sha")


def test_it_refuses_an_unsigned_archive(tmp_path):
    """Unsigned entries are still chain-verifiable, but nothing ties them to
    this instance — and the archive is about to become the only copy."""
    audit = AuditLogger(tmp_path / "logs", chain_dir=tmp_path / "chain")
    for i in range(6):
        audit.log_operation("renew", "certificate", f"d{i}.example.com", "success")
    bundle = audit.export_bundle(to_seq=2)
    try:
        with pytest.raises(PruneError, match="unsigned"):
            plan_prune(audit.audit_chain_file, bundle, "sha")
    finally:
        audit.audit_logger.removeHandler(audit.file_handler)
        audit.file_handler.close()


def test_it_refuses_an_archive_from_another_instance(instance, tmp_path):
    """Same shape, different history: the hashes will not match."""
    other_signer = AuditSigner(tmp_path / "other")
    other = AuditLogger(tmp_path / "other-logs", chain_dir=tmp_path / "other-chain",
                        signer=other_signer)
    for i in range(8):
        other.log_operation("renew", "certificate", f"x{i}.example.com", "success")
    bundle = other.export_bundle(to_seq=5)
    try:
        with pytest.raises(PruneError, match="disagree at seq"):
            plan_prune(instance.audit_chain_file, bundle, "sha")
    finally:
        other.audit_logger.removeHandler(other.file_handler)
        other.file_handler.close()


def test_it_refuses_an_archive_that_is_not_a_prefix(instance, tmp_path):
    """A slice from the middle would leave a hole, not a shorter chain."""
    bundle = instance.export_bundle(from_seq=4, to_seq=8)

    with pytest.raises(PruneError, match="not a prefix of this chain"):
        plan_prune(instance.audit_chain_file, bundle, "sha")


def test_it_refuses_to_empty_the_chain(instance, tmp_path):
    """A chain with no live records cannot be verified at all, only asserted."""
    bundle = instance.export_bundle()

    with pytest.raises(PruneError, match="would empty the chain"):
        plan_prune(instance.audit_chain_file, bundle, "sha")


def test_it_refuses_when_the_chain_is_missing(instance, tmp_path):
    bundle = json.loads(_archive(instance, tmp_path).read_text())

    with pytest.raises(PruneError, match="no audit chain"):
        plan_prune(tmp_path / "nowhere" / "chain.jsonl", bundle, "sha")


def test_a_dry_run_changes_nothing(instance, tmp_path, capsys):
    path = _archive(instance, tmp_path)
    before = instance.audit_chain_file.read_text()

    rc = main(["--bundle", str(path), "--data-dir", str(tmp_path / "chain"),
               "--key-dir", str(tmp_path)])

    assert rc == 0
    assert "Dry run" in capsys.readouterr().out
    assert instance.audit_chain_file.read_text() == before
    assert not (tmp_path / "chain" / audit_chain.ANCHOR_FILENAME).exists()


def test_a_refusal_removes_nothing(instance, tmp_path, capsys):
    bundle_path = tmp_path / "middle.json"
    bundle_path.write_text(json.dumps(instance.export_bundle(from_seq=4, to_seq=8)))
    before = instance.audit_chain_file.read_text()

    rc = main(["--bundle", str(bundle_path), "--data-dir", str(tmp_path / "chain"),
               "--key-dir", str(tmp_path), "--yes"])

    assert rc == 1
    assert "REFUSED" in capsys.readouterr().err
    assert instance.audit_chain_file.read_text() == before


# --------------------------------------------------------------------------
# 2. It records itself
# --------------------------------------------------------------------------

def test_the_prune_is_an_entry_in_the_chain_that_continues(instance, tmp_path):
    path = _archive(instance, tmp_path)
    digest = sha256_file(path)

    assert _prune(instance, tmp_path, path) == 0

    records = audit_chain.load_records(instance.audit_chain_file)
    assert [r["seq"] for r in records] == [6, 7, 8, 9, 10, 11, 12]
    archive = records[-1]["entry"]
    assert archive["operation"] == "archive"
    assert archive["resource_type"] == "audit_chain"
    assert archive["details"]["archived_first_seq"] == 0
    assert archive["details"]["archived_last_seq"] == 5
    assert archive["details"]["archived_count"] == 6
    assert archive["details"]["bundle_sha256"] == digest


def test_the_archived_head_hash_is_recorded(instance, tmp_path):
    """What the deleted entries hashed to, kept where the deletion is visible."""
    head_before = audit_chain.load_records(instance.audit_chain_file)[5]["hash"]
    path = _archive(instance, tmp_path)

    _prune(instance, tmp_path, path)

    archive = audit_chain.load_records(instance.audit_chain_file)[-1]["entry"]
    assert archive["details"]["archived_head_hash"] == head_before


def test_the_anchor_records_what_was_archived(instance, tmp_path):
    path = _archive(instance, tmp_path)

    _prune(instance, tmp_path, path)

    anchor = audit_chain.read_anchor(
        audit_chain.anchor_path_for(instance.audit_chain_file))
    assert anchor["anchor_seq"] == 6
    assert anchor["archived_count"] == 6
    assert anchor["bundle_sha256"] == sha256_file(path)
    assert anchor["signature"]


# --------------------------------------------------------------------------
# 3. It does not overclaim, and it does not cry wolf
# --------------------------------------------------------------------------

def test_the_pruned_chain_verifies_from_the_anchor(instance, tmp_path):
    _prune(instance, tmp_path, _archive(instance, tmp_path))

    result = _reopen(instance, tmp_path).verify_chain()

    assert result["ok"]
    assert result["anchored"] is True
    assert result["anchor_seq"] == 6
    assert result["anchor_signature_ok"] is True
    assert "from the anchor at seq 6" in result["reason"]
    assert result["reason"] != "intact"


def test_the_stdlib_verifier_never_says_bare_intact(instance, tmp_path, capsys):
    """An auditor running the standalone verifier must not read a pruned chain
    as a complete one."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))

    rc = audit_verify.main([str(instance.audit_chain_file)])

    out = capsys.readouterr()
    assert rc == 0
    assert "intact from the anchor at seq 6" in out.out
    assert "PRUNED" in out.err
    assert "NOT verified" in out.err, "an unpinned anchor must not read as verified"


def test_the_stdlib_verifier_verifies_a_pinned_anchor(instance, tmp_path, capsys):
    _prune(instance, tmp_path, _archive(instance, tmp_path))
    pem = tmp_path / "pub.pem"
    pem.write_text(instance._signer.public_key_pem(), encoding="utf-8")

    rc = audit_verify.main([str(instance.audit_chain_file), "--pubkey", str(pem)])

    assert rc == 0
    assert "Anchor signature: verified" in capsys.readouterr().err


def test_a_forged_anchor_is_rejected(instance, tmp_path):
    """Deleting history and writing a matching anchor must not verify: the
    anchor is signed precisely so that it cannot be fabricated."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))
    anchor_path = audit_chain.anchor_path_for(instance.audit_chain_file)
    anchor = json.loads(open(anchor_path).read())
    anchor["archived_count"] = 999
    open(anchor_path, "w").write(json.dumps(anchor))

    result = _reopen(instance, tmp_path).verify_chain()

    assert not result["ok"]
    assert "not signed by this instance" in result["reason"]


def test_an_anchor_pinned_to_a_different_key_is_rejected(instance, tmp_path, capsys):
    _prune(instance, tmp_path, _archive(instance, tmp_path))
    stranger = tmp_path / "stranger.pem"
    stranger.write_text(AuditSigner(tmp_path / "stranger").public_key_pem())

    rc = audit_verify.main([str(instance.audit_chain_file), "--pubkey", str(stranger)])

    assert rc == 1
    assert "not signed by the pinned key" in capsys.readouterr().err


def test_an_unreadable_anchor_fails_closed(instance, tmp_path):
    """"No anchor" means "this chain starts at the genesis". Concluding that
    about a chain whose anchor is corrupt would hide a prune."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))
    open(audit_chain.anchor_path_for(instance.audit_chain_file), "w").write("{oops")

    result = audit_chain.verify_chain(instance.audit_chain_file)

    assert not result["ok"]
    assert result["anchor_unreadable"] is True


def test_old_checkpoints_do_not_report_the_prune_as_tampering(instance, tmp_path):
    """The failure this design exists to avoid. Checkpoints at seq 4 and 9
    attest entries that were archived; cross-checking against the older one
    would call routine maintenance a truncation, and an operator who sees a
    tamper alert from maintenance learns to ignore tamper alerts."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))

    result = _reopen(instance, tmp_path).verify_chain()

    assert result["ok"], result["reason"]
    assert result["checkpoint_verified"] is True
    assert result["checkpoint_seq"] >= result["anchor_seq"]


def test_a_prune_past_every_checkpoint_says_so_rather_than_failing(instance, tmp_path):
    _prune(instance, tmp_path, _archive(instance, tmp_path, to_seq=9))

    result = _reopen(instance, tmp_path).verify_chain()

    assert result["ok"], result["reason"]
    assert "predates the archived prefix" in result["checkpoint_reason"]


def test_an_anchored_chain_without_a_signing_key_does_not_verify(instance, tmp_path):
    """An anchor nobody can check is an assertion, not evidence."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))
    unsigned = AuditLogger(tmp_path / "logs-nokey", chain_dir=tmp_path / "chain")
    try:
        result = unsigned.verify_chain()
    finally:
        unsigned.audit_logger.removeHandler(unsigned.file_handler)
        unsigned.file_handler.close()

    assert not result["ok"]
    assert "no signing key" in result["reason"]


# --------------------------------------------------------------------------
# Interrupted and resumed
# --------------------------------------------------------------------------

def test_an_interrupted_prune_leaves_a_chain_that_still_verifies(instance, tmp_path):
    """The anchor is written before the chain is replaced, so a crash between
    the two loses nothing — and must not read as tampering."""
    path = _archive(instance, tmp_path)
    plan = plan_prune(instance.audit_chain_file, json.loads(path.read_text()),
                      sha256_file(path))
    anchor = dict(plan)
    anchor["pruned_at"] = "2026-07-22T00:00:00"
    anchor["signature"] = instance._signer.sign(
        audit_chain.anchor_signing_bytes(anchor))
    open(audit_chain.anchor_path_for(instance.audit_chain_file), "w").write(
        json.dumps(anchor))

    result = audit_chain.verify_chain(instance.audit_chain_file)

    assert result["ok"], result["reason"]
    assert result["anchor_pending"] is True
    assert "interrupted prune" in result["reason"]
    assert result["count"] == 12, "nothing was removed"


def test_an_anchor_that_does_not_describe_this_chain_fails(instance, tmp_path):
    """A planted anchor claiming a prefix that never hashed that way."""
    anchor = {
        "anchor_seq": 6, "prev_hash": "0" * 64, "archived_first_seq": 0,
        "archived_last_seq": 5, "archived_count": 6, "bundle_sha256": "x",
        "pruned_at": "2026-07-22T00:00:00",
    }
    anchor["signature"] = instance._signer.sign(
        audit_chain.anchor_signing_bytes(anchor))
    open(audit_chain.anchor_path_for(instance.audit_chain_file), "w").write(
        json.dumps(anchor))

    result = audit_chain.verify_chain(instance.audit_chain_file)

    assert not result["ok"]
    assert "does not describe this chain" in result["reason"]


def test_the_chain_keeps_growing_after_a_prune(instance, tmp_path):
    """The next boot must continue the chain from the pruned head, not restart."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))

    resumed = _reopen(instance, tmp_path)
    resumed.log_operation("renew", "certificate", "after.example.com", "success")

    result = resumed.verify_chain()
    assert result["ok"], result["reason"]
    assert result["last_seq"] == 13
    assert result["anchored"] is True


def test_a_second_prune_moves_the_anchor(instance, tmp_path):
    """Pruning twice works: the second archive starts at the first anchor, not
    at the genesis, so its bundle is an anchored slice and verifies as one."""
    _prune(instance, tmp_path, _archive(instance, tmp_path, to_seq=5))
    resumed = _reopen(instance, tmp_path)

    second = tmp_path / "second.json"
    second.write_text(json.dumps(resumed.export_bundle(to_seq=9)))
    rc = main(["--bundle", str(second), "--data-dir", str(tmp_path / "chain"),
               "--key-dir", str(tmp_path), "--yes"])

    assert rc == 0
    result = _reopen(instance, tmp_path).verify_chain()
    assert result["ok"], result["reason"]
    assert result["anchor_seq"] == 10
    assert [r["seq"] for r in audit_chain.load_records(instance.audit_chain_file)] \
        == [10, 11, 12, 13]


def test_an_exported_bundle_from_a_pruned_chain_is_anchored(instance, tmp_path):
    """It no longer starts at the genesis, so it must declare its anchor —
    which is exactly the #441 primitive doing its job here."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))

    bundle = _reopen(instance, tmp_path).export_bundle()

    assert bundle["manifest"]["format_version"] == \
        audit_chain.ANCHORED_BUNDLE_FORMAT_VERSION
    verdict = audit_verify.verify_bundle(bundle)
    assert verdict["ok"] and verdict["anchored"]


def test_an_interrupted_second_prune_still_verifies(instance, tmp_path):
    """The case that made the anchor record what it supersedes. After a first
    prune the chain starts at seq 6, not at the genesis; a second prune that
    dies before replacing the chain would otherwise leave a file whose only
    description — the old anchor — has just been overwritten, and it would read
    as tampered."""
    _prune(instance, tmp_path, _archive(instance, tmp_path, to_seq=5))
    resumed = _reopen(instance, tmp_path)
    second = tmp_path / "second.json"
    second.write_text(json.dumps(resumed.export_bundle(to_seq=9)))
    plan = plan_prune(instance.audit_chain_file, json.loads(second.read_text()),
                      sha256_file(second))
    assert plan["supersedes"] == {"anchor_seq": 6, "prev_hash": plan["supersedes"]["prev_hash"]}
    anchor = dict(plan)
    anchor["pruned_at"] = "2026-07-22T00:00:00"
    anchor["signature"] = instance._signer.sign(
        audit_chain.anchor_signing_bytes(anchor))
    open(audit_chain.anchor_path_for(instance.audit_chain_file), "w").write(
        json.dumps(anchor))

    result = _reopen(instance, tmp_path).verify_chain()

    assert result["ok"], result["reason"]
    assert result["anchor_pending"] is True
    assert "intact from seq 6" in result["reason"]
    assert result["first_seq"] == 6, "nothing was removed"


def test_a_chain_starting_at_neither_the_anchor_nor_its_predecessor_fails(
        instance, tmp_path):
    _prune(instance, tmp_path, _archive(instance, tmp_path, to_seq=5))
    anchor_path = audit_chain.anchor_path_for(instance.audit_chain_file)
    anchor = json.loads(open(anchor_path).read())
    anchor["anchor_seq"] = 9  # claims a prune the chain does not reflect
    open(anchor_path, "w").write(json.dumps(anchor))

    result = audit_chain.verify_chain(instance.audit_chain_file)

    assert not result["ok"]
    assert "neither the genesis nor the anchor" in result["reason"]


def test_an_anchor_that_vanishes_mid_verification_fails_closed(instance, tmp_path,
                                                               monkeypatch):
    """verify_chain reads the anchor, then the signature check reads it again.
    A file that disappears in between must not raise — nor pass."""
    _prune(instance, tmp_path, _archive(instance, tmp_path))
    audit = _reopen(instance, tmp_path)
    real = audit_chain.read_anchor
    calls = {"n": 0}

    def vanishing(path):
        calls["n"] += 1
        return real(path) if calls["n"] == 1 else None

    monkeypatch.setattr(audit_chain, "read_anchor", vanishing)
    result = audit.verify_chain()

    assert not result["ok"]
    assert "disappeared" in result["reason"]
