"""P1-7 (2026-07-02 audit): the signed checkpoints were WRITTEN but never READ,
so a tail truncation / rewind / rewrite of the hash chain went undetected by
the verifier. AuditLogger.verify_chain now cross-checks the chain against the
newest signed checkpoint that verifies under the current key — fail-closed.

This does NOT bind an operator who holds the signing key (that needs off-box
anchoring); it closes the gap for anyone WITHOUT the key, and turns the
previously-dead checkpoint file into a real anchor."""
import pytest

from modules.core.audit import AuditLogger
from modules.core.audit_signing import AuditSigner
from modules.core import audit_chain


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
