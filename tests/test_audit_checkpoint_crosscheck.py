"""P1-7 (2026-07-02 audit): the signed checkpoints were WRITTEN but never READ,
so a tail truncation / rewind / rewrite of the hash chain went undetected by
the verifier. AuditLogger.verify_chain now cross-checks the chain against the
newest signed checkpoint that verifies under the current key — fail-closed.

This does NOT bind an operator who holds the signing key (that needs off-box
anchoring); it closes the gap for anyone WITHOUT the key, and turns the
previously-dead checkpoint file into a real anchor."""
import os
from types import SimpleNamespace

import pytest
from flask import Flask

from modules.core.audit import AuditLogger
from modules.core.audit_signing import AuditSigner
from modules.core import audit_chain
from modules.web.misc_routes import register_misc_routes


@pytest.fixture
def make_audit():
    created = []

    def _make(dir_path, **kw):
        a = AuditLogger(dir_path, **kw)
        created.append(a)
        return a

    yield _make
    for a in created:
        a.audit_logger.removeHandler(a.file_handler)
        a.file_handler.close()


def _emit(audit, n):
    for i in range(n):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success',
                             actor={'kind': 'agent', 'id': 'k1'}, trigger={'cause': 'agent'})


def _chain_lines(tmp_path):
    p = tmp_path / audit_chain.CHAIN_FILENAME
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def _rewrite_chain(tmp_path, lines):
    (tmp_path / audit_chain.CHAIN_FILENAME).write_text(
        ''.join(ln + '\n' for ln in lines))


# --- unit: cross_check_checkpoint ------------------------------------------

def _records():
    r0 = audit_chain.make_line(0, {'op': 'a'}, audit_chain.GENESIS_PREV)
    r1 = audit_chain.make_line(1, {'op': 'b'}, r0['hash'])
    r2 = audit_chain.make_line(2, {'op': 'c'}, r1['hash'])
    return [r0, r1, r2]


def test_cross_check_ok_when_hash_matches():
    recs = _records()
    cp = {'seq': 2, 'hash': recs[2]['hash'], 'count': 3}
    assert audit_chain.cross_check_checkpoint(recs, cp)['ok'] is True


def test_cross_check_fails_when_checkpointed_seq_missing():
    recs = _records()
    cp = {'seq': 2, 'hash': recs[2]['hash'], 'count': 3}
    out = audit_chain.cross_check_checkpoint(recs[:2], cp)  # seq 2 truncated
    assert out['ok'] is False
    assert 'truncated' in out['reason'] or 'rewound' in out['reason']


def test_cross_check_fails_when_hash_diverges():
    recs = _records()
    cp = {'seq': 2, 'hash': 'deadbeef' * 8, 'count': 3}  # different head hash
    out = audit_chain.cross_check_checkpoint(recs, cp)
    assert out['ok'] is False
    assert 'rewritten' in out['reason']


def test_cross_check_ignores_malformed_checkpoint():
    assert audit_chain.cross_check_checkpoint(_records(), {'seq': None})['ok'] is True


# --- integration: AuditLogger.verify_chain ---------------------------------

def test_verify_ok_and_checkpoint_verified_when_intact(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 6)  # checkpoints at seq 2 and 5
    r = audit.verify_chain()
    assert r['ok'] is True
    assert r['checkpoint_verified'] is True
    assert r['checkpoint_seq'] == 5


def test_verify_detects_truncation_below_signed_checkpoint(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 6)  # latest signed checkpoint at seq 5
    # Drop the last entry (seq 5) — internally still a valid, shorter chain,
    # but it no longer contains the checkpointed head.
    _rewrite_chain(tmp_path, _chain_lines(tmp_path)[:-1])
    r = audit.verify_chain()
    assert r['ok'] is False
    assert r['checkpoint_verified'] is False
    assert r['error_seq'] == 5


def test_verify_detects_wiped_chain_after_checkpoint(make_audit, tmp_path):
    """A wiped/empty chain used to verify as ok='empty chain'. With a prior
    signed checkpoint, that erasure is now caught."""
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 3)  # checkpoint at seq 2
    _rewrite_chain(tmp_path, [])  # wipe the chain
    r = audit.verify_chain()
    assert r['ok'] is False
    assert r['checkpoint_verified'] is False


def test_verify_unaffected_without_signer(make_audit, tmp_path):
    """No signer → behavior unchanged (checkpoints not cross-checked). The bare
    hash chain's known tail-truncation limitation stays documented elsewhere."""
    audit = make_audit(tmp_path, checkpoint_interval=3)  # no signer
    _emit(audit, 4)
    r = audit.verify_chain()
    assert r['ok'] is True
    assert r['checkpoint_verified'] is False
    assert 'no signer' in r['checkpoint_reason']


def test_verify_intact_reports_no_checkpoint_yet(make_audit, tmp_path):
    """Signer wired but too few entries to trigger a checkpoint → ok, and the
    reason explains no anchor exists yet (not a false tamper signal)."""
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=100)
    _emit(audit, 2)
    r = audit.verify_chain()
    assert r['ok'] is True
    assert r['checkpoint_verified'] is False
    assert 'no checkpoints' in r['checkpoint_reason']


# --------------------------------------------------------------------------
# /api/audit/verify HTTP semantics: "no chain yet" (benign) vs broken (tamper)
# --------------------------------------------------------------------------

def _passthrough(*_a, **_k):
    def deco(fn):
        return fn
    return deco


def _verify_route(audit):
    app = Flask(__name__)
    register_misc_routes(app, {'audit': audit}, _passthrough,
                         SimpleNamespace(require_role=_passthrough))
    return app.test_client().get('/api/audit/verify')


def test_verify_endpoint_fresh_instance_is_200_absent(make_audit, tmp_path):
    """A brand-new instance (nothing audited, no chain file, no checkpoints)
    must NOT look like a tamper: 200 with state='absent', so a monitoring probe
    does not false-alarm on a fresh deploy."""
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path))
    r = _verify_route(audit)
    assert r.status_code == 200
    body = r.get_json()
    assert body['ok'] is False and body.get('state') == 'absent'


def test_verify_endpoint_intact_is_200(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path))
    _emit(audit, 3)
    r = _verify_route(audit)
    assert r.status_code == 200 and r.get_json()['ok'] is True


def test_verify_endpoint_tampered_is_409(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path))
    _emit(audit, 3)
    # Corrupt an interior entry's hash → internal verify fails.
    lines = _chain_lines(tmp_path)
    lines[1] = lines[1].replace('"hash":', '"hash":"deadbeef","_x":')
    _rewrite_chain(tmp_path, lines)
    r = _verify_route(audit)
    assert r.status_code == 409 and r.get_json()['ok'] is False


def test_verify_endpoint_deleted_chain_with_checkpoints_is_409(make_audit, tmp_path):
    """A missing chain file is benign ONLY when nothing attested it. If a signed
    checkpoint exists, a missing chain is a DELETION → 409, not 200 absent."""
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 3)  # writes a checkpoint at seq 2
    (tmp_path / audit_chain.CHAIN_FILENAME).unlink()  # delete the chain file
    r = _verify_route(audit)
    assert r.status_code == 409
    assert r.get_json().get('state') != 'absent'


# --------------------------------------------------------------------------
# Fail-closed on an UNREADABLE checkpoint file: it must never read as "no
# checkpoints ever existed" (which, with a deleted chain, produced a clean
# 200 state='absent' verdict on a tampered box).
# --------------------------------------------------------------------------

def _make_unreadable(path):
    """chmod 000 and verify it took effect; as root (some CI) the file stays
    readable and the scenario cannot be reproduced — skip, don't false-pass."""
    os.chmod(path, 0)
    if os.access(path, os.R_OK):
        pytest.skip("cannot make the file unreadable (running as root?)")


def test_read_checkpoints_missing_file_is_empty(tmp_path):
    assert audit_chain.read_checkpoints(tmp_path / 'nope.jsonl') == []


def test_read_checkpoints_raises_on_unreadable_file(tmp_path):
    cp_file = tmp_path / audit_chain.CHECKPOINT_FILENAME
    cp_file.write_text('{"seq": 2, "hash": "abc"}\n')
    _make_unreadable(cp_file)
    try:
        with pytest.raises(audit_chain.CheckpointReadError):
            audit_chain.read_checkpoints(cp_file)
    finally:
        os.chmod(cp_file, 0o600)


def test_verify_chain_missing_file_sets_structured_flag(tmp_path):
    """The absent-vs-tampered decision keys on 'chain_file_missing', not on
    substring-matching the human-readable reason."""
    result = audit_chain.verify_chain(tmp_path / 'no-such-chain.jsonl')
    assert result['ok'] is False
    assert result['chain_file_missing'] is True
    assert result['reason'] == 'chain file does not exist'  # wording unchanged


def test_verify_endpoint_unreadable_checkpoints_and_deleted_chain_is_409(make_audit, tmp_path):
    """chmod-000 checkpoint file + deleted chain used to return 200 'absent'
    (fail-open): the OSError was swallowed as 'no checkpoints'. It must be a
    409 — integrity cannot be verified — and not a 500 traceback either."""
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 3)  # writes a checkpoint at seq 2
    (tmp_path / audit_chain.CHAIN_FILENAME).unlink()
    cp_file = tmp_path / audit_chain.CHECKPOINT_FILENAME
    _make_unreadable(cp_file)
    try:
        r = _verify_route(audit)
    finally:
        os.chmod(cp_file, 0o600)
    assert r.status_code == 409
    body = r.get_json()
    assert body.get('state') != 'absent'
    assert body.get('checkpoint_unreadable') is True
    assert 'unreadable' in (body.get('reason') or '')


def test_verify_intact_chain_with_unreadable_checkpoints_fails_closed(make_audit, tmp_path):
    """Even with an intact chain, an unreadable anchor means the cross-check
    cannot run — report NOT verified (409), never a silent pass."""
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 3)
    cp_file = tmp_path / audit_chain.CHECKPOINT_FILENAME
    _make_unreadable(cp_file)
    try:
        r = _verify_route(audit)
    finally:
        os.chmod(cp_file, 0o600)
    assert r.status_code == 409
    body = r.get_json()
    assert body['ok'] is False
    assert body.get('checkpoint_unreadable') is True
