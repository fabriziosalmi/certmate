"""An incremental export slice must verify — and must not overclaim.

Regression tests for #441. `GET /api/audit/export?from_seq=N` was documented as
producing a "self-verifying" slice and produced a bundle the shipped verifier
rejected: `verify_records` seeds `prev_hash` with the genesis and requires the
first record's `prev_hash` to be `""`, so any fragment failed on its very first
link. Every documented incremental-export workflow was broken, and the failure
mode was the worst wording available — "broken link ... a deletion or reorder"
on a perfectly intact record.

The fix is not to relax the genesis requirement: that requirement is why head
truncation of a *full* chain is detected. It is to let a fragment declare, inside
the signed manifest, the predecessor hash it continues from.

The second half of these tests is about not overclaiming. A verified fragment
says nothing about the entries before its anchor, and neither the result dict nor
the CLI is allowed to imply otherwise.
"""

import json

import pytest

from modules.core import audit_chain, audit_verify
from modules.core.audit import AuditLogger
from modules.core.audit_signing import AuditSigner


pytestmark = [pytest.mark.unit]


@pytest.fixture
def audit(tmp_path):
    a = AuditLogger(tmp_path / "logs", chain_dir=tmp_path / "chain",
                    signer=AuditSigner(tmp_path))
    for i in range(6):
        a.log_operation("renew", "certificate", f"d{i}.example.com", "success")
    yield a
    a.audit_logger.removeHandler(a.file_handler)
    a.file_handler.close()


# --------------------------------------------------------------------------
# The bug itself
# --------------------------------------------------------------------------

def test_a_slice_from_the_middle_verifies(audit):
    bundle = audit.export_bundle(from_seq=3)

    result = audit_verify.verify_bundle(bundle)

    assert result["ok"], result["reason"]
    assert result["signed"] and result["signature_ok"]
    assert result["count"] == 3
    assert result["first_seq"] == 3 and result["last_seq"] == 5


def test_a_bounded_slice_verifies(audit):
    bundle = audit.export_bundle(from_seq=2, to_seq=4)

    result = audit_verify.verify_bundle(bundle)

    assert result["ok"], result["reason"]
    assert result["first_seq"] == 2 and result["last_seq"] == 4


def test_a_full_export_is_unchanged_and_unanchored(audit):
    """v1 stays byte-compatible: no new manifest keys, so a verifier shipped
    before this change still accepts every full export."""
    manifest = audit.export_bundle()["manifest"]

    assert manifest["format_version"] == audit_chain.BUNDLE_FORMAT_VERSION
    assert "anchor_prev_hash" not in manifest
    assert "anchor_seq" not in manifest


def test_a_slice_starting_at_the_genesis_is_not_anchored(audit):
    """?from_seq=0 is a full export by another name."""
    manifest = audit.export_bundle(from_seq=0)["manifest"]

    assert manifest["format_version"] == audit_chain.BUNDLE_FORMAT_VERSION


def test_an_empty_slice_still_verifies(audit):
    """Nothing at or after the requested seq: no entries, no anchor to declare."""
    bundle = audit.export_bundle(from_seq=99)

    assert bundle["entries"] == []
    assert bundle["manifest"]["format_version"] == audit_chain.BUNDLE_FORMAT_VERSION
    assert audit_verify.verify_bundle(bundle)["ok"]


# --------------------------------------------------------------------------
# Anchoring must not become a hole
# --------------------------------------------------------------------------

def test_tampering_inside_a_slice_is_still_caught(audit):
    bundle = audit.export_bundle(from_seq=3)
    bundle["entries"][1]["entry"]["status"] = "forged"

    result = audit_verify.verify_bundle(bundle)

    assert not result["ok"]
    assert "hash mismatch" in result["reason"]


def test_a_forged_anchor_does_not_validate_foreign_entries(audit):
    """The anchor is checked against the entries, not merely recorded."""
    bundle = audit.export_bundle(from_seq=3)
    bundle["manifest"]["anchor_prev_hash"] = "0" * 64

    result = audit_verify.verify_bundle(bundle)

    assert not result["ok"]
    assert "broken link" in result["reason"]


def test_a_wrong_anchor_seq_is_caught(audit):
    bundle = audit.export_bundle(from_seq=3)
    bundle["manifest"]["anchor_seq"] = 99

    result = audit_verify.verify_bundle(bundle)

    assert not result["ok"]
    assert "sequence break" in result["reason"]


@pytest.mark.parametrize("dropped", [None, "anchor_prev_hash", "anchor_seq"])
def test_a_slice_cannot_be_downgraded_to_look_complete(audit, dropped):
    """Stripping the version off a fragment must not turn it into a full chain
    — nor produce a misleading 'broken chain' verdict. Dropping either anchor
    field on the way down does not help: every anchor field is rejected on a v1
    bundle, so the verdict names the real problem instead of blaming the
    entries."""
    bundle = audit.export_bundle(from_seq=3)
    bundle["manifest"]["format_version"] = audit_chain.BUNDLE_FORMAT_VERSION
    if dropped:
        del bundle["manifest"][dropped]

    result = audit_verify.verify_bundle(bundle)

    assert not result["ok"]
    assert "declares anchor fields" in result["reason"]


def test_an_anchored_bundle_without_an_anchor_is_rejected(audit):
    bundle = audit.export_bundle(from_seq=3)
    del bundle["manifest"]["anchor_prev_hash"]

    result = audit_verify.verify_bundle(bundle)

    assert not result["ok"]
    assert "without a usable anchor" in result["reason"]


def test_the_signature_covers_the_anchor(audit):
    """An attacker who rewrites the anchor cannot re-sign it."""
    bundle = audit.export_bundle(from_seq=3)
    genuine = bundle["entries"][0]["prev_hash"]
    bundle["manifest"]["anchor_prev_hash"] = genuine  # unchanged value...
    assert audit_verify.verify_bundle(bundle)["ok"]

    # ...but any real change breaks the manifest signature as well as the link.
    bundle["manifest"]["anchor_seq"] = 4
    assert not audit_verify.verify_bundle(bundle)["ok"]


def test_an_unknown_format_version_is_still_rejected(audit):
    bundle = audit.export_bundle()
    bundle["manifest"]["format_version"] = 99

    result = audit_verify.verify_bundle(bundle)

    assert not result["ok"]
    assert "format_version" in result["reason"]


# --------------------------------------------------------------------------
# Not overclaiming
# --------------------------------------------------------------------------

def test_a_slice_is_reported_as_partial_not_intact(audit):
    result = audit_verify.verify_bundle(audit.export_bundle(from_seq=3))

    assert result["anchored"] is True
    assert result["anchor_seq"] == 3
    assert "partial slice" in result["reason"]


def test_a_full_export_is_not_flagged_as_partial(audit):
    result = audit_verify.verify_bundle(audit.export_bundle())

    assert result["anchored"] is False
    assert "partial" not in result["reason"]


def test_the_cli_says_a_slice_is_partial(audit, tmp_path, capsys):
    path = tmp_path / "slice.json"
    path.write_text(json.dumps(audit.export_bundle(from_seq=3)))

    assert audit_verify.main(["--bundle", str(path)]) == 0

    err = capsys.readouterr().err
    assert "PARTIAL slice" in err
    assert "seq 3" in err


def test_the_cli_does_not_cry_partial_on_a_full_export(audit, tmp_path, capsys):
    path = tmp_path / "full.json"
    path.write_text(json.dumps(audit.export_bundle()))

    assert audit_verify.main(["--bundle", str(path)]) == 0
    assert "PARTIAL" not in capsys.readouterr().err


# --------------------------------------------------------------------------
# verify_records: the primitive, directly
# --------------------------------------------------------------------------

def test_verify_records_still_requires_the_genesis_by_default(audit):
    """The default is load-bearing: it is what makes head truncation of a full
    chain detectable. Anchoring is opt-in, never inferred from the records."""
    records = audit_chain.load_records(audit.audit_chain_file)

    beheaded = audit_chain.verify_records(records[2:])

    assert not beheaded["ok"]
    assert "broken link" in beheaded["reason"]


def test_verify_records_accepts_an_explicit_anchor(audit):
    records = audit_chain.load_records(audit.audit_chain_file)
    tail = records[2:]

    result = audit_chain.verify_records(
        tail, anchor_prev_hash=tail[0]["prev_hash"], anchor_seq=tail[0]["seq"])

    assert result["ok"]
    assert result["first_seq"] == 2
    assert result["head_hash"] == records[-1]["hash"]


def test_an_empty_anchored_slice_reports_the_anchor_as_its_head(audit):
    result = audit_chain.verify_records([], anchor_prev_hash="abc", anchor_seq=7)

    assert result["ok"] and result["head_hash"] == "abc"


def test_export_endpoint_slice_verifies(audit, tmp_path):
    """End to end through the HTTP route, since that is where the broken
    workflow was documented."""
    from types import SimpleNamespace
    from flask import Flask
    from modules.web.misc_routes import register_misc_routes

    def _passthrough(*_a, **_k):
        return lambda fn: fn

    app = Flask(__name__)
    register_misc_routes(app, {"audit": audit}, _passthrough,
                         SimpleNamespace(require_role=_passthrough))

    response = app.test_client().get("/api/audit/export?from_seq=4")

    assert response.status_code == 200
    body = json.loads(response.data)
    assert body["manifest"]["format_version"] == audit_chain.ANCHORED_BUNDLE_FORMAT_VERSION
    assert audit_verify.verify_bundle(body)["ok"]
