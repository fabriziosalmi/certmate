"""
Phase 2 of the agentic audit trail (l0 #408): the tamper-evident SHA-256 hash
chain and its standalone verifier.
"""

import json

import pytest

from modules.core.audit import AuditLogger
from modules.core import audit_chain
from modules.core import audit_verify


@pytest.fixture
def make_audit():
    """Factory that builds AuditLoggers and detaches their shared-logger
    handler afterwards (so handlers do not leak across tests)."""
    created = []

    def _make(dir_path, **kw):
        a = AuditLogger(dir_path, **kw)
        created.append(a)
        return a

    yield _make
    for a in created:
        a.audit_logger.removeHandler(a.file_handler)
        a.file_handler.close()


def _emit(audit, n, op='create'):
    for i in range(n):
        audit.log_operation(op, 'certificate', f'd{i}.example.com', 'success',
                            actor={'kind': 'agent', 'id': 'k1'}, trigger={'cause': 'agent'})


# --------------------------------------------------------------------------
# canon + hash primitives
# --------------------------------------------------------------------------

def test_canon_is_key_order_independent():
    a = audit_chain.canon_bytes({'b': 1, 'a': 2})
    b = audit_chain.canon_bytes({'a': 2, 'b': 1})
    assert a == b


def test_canon_preserves_non_ascii_stably():
    # An internationalised domain must hash identically everywhere.
    entry = {'resource_id': 'exämple.com', 'details': {'note': 'café'}}
    h1 = audit_chain.entry_hash(0, entry, '')
    h2 = audit_chain.entry_hash(0, dict(entry), '')
    assert h1 == h2
    assert audit_chain.canon_bytes(entry).decode('utf-8')  # round-trips


def test_make_line_links_prev_hash():
    l0 = audit_chain.make_line(0, {'x': 1}, audit_chain.GENESIS_PREV)
    l1 = audit_chain.make_line(1, {'x': 2}, l0['hash'])
    assert l1['prev_hash'] == l0['hash']
    assert l0['hash'] != l1['hash']


# --------------------------------------------------------------------------
# Writer + verifier happy path
# --------------------------------------------------------------------------

def test_chain_written_and_verifies(make_audit, tmp_path):
    audit = make_audit(tmp_path)
    _emit(audit, 5)
    assert audit.audit_chain_file.exists()
    result = audit.verify_chain()
    assert result['ok'] is True
    assert result['count'] == 5
    assert result['first_seq'] == 0
    assert result['last_seq'] == 4
    assert result['head_hash']


def test_chain_disabled_writes_nothing(make_audit, tmp_path):
    audit = make_audit(tmp_path, enable_chain=False)
    _emit(audit, 3)
    assert not audit.audit_chain_file.exists()


def test_chain_env_killswitch(make_audit, tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_AUDIT_CHAIN', '0')
    audit = make_audit(tmp_path)
    _emit(audit, 2)
    assert not audit.audit_chain_file.exists()


def test_chain_dir_separate_from_log(make_audit, tmp_path):
    log_dir = tmp_path / 'logs'
    chain_dir = tmp_path / 'data'
    audit = make_audit(log_dir, chain_dir=chain_dir)
    _emit(audit, 1)
    assert (chain_dir / audit_chain.CHAIN_FILENAME).exists()
    assert not (log_dir / audit_chain.CHAIN_FILENAME).exists()


# --------------------------------------------------------------------------
# Tamper detection
# --------------------------------------------------------------------------

def _rewrite_lines(path, lines):
    path.write_text(''.join(l if l.endswith('\n') else l + '\n' for l in lines),
                    encoding='utf-8')


def test_detects_modified_entry(make_audit, tmp_path):
    audit = make_audit(tmp_path)
    _emit(audit, 4)
    lines = audit.audit_chain_file.read_text(encoding='utf-8').splitlines()
    rec = json.loads(lines[2])
    rec['entry']['resource_id'] = 'attacker.example.com'  # edit content, keep hash
    lines[2] = json.dumps(rec)
    _rewrite_lines(audit.audit_chain_file, lines)

    result = audit.verify_chain()
    assert result['ok'] is False
    assert result['error_seq'] == 2
    assert 'hash mismatch' in result['reason']


def test_detects_deleted_entry(make_audit, tmp_path):
    audit = make_audit(tmp_path)
    _emit(audit, 5)
    lines = audit.audit_chain_file.read_text(encoding='utf-8').splitlines()
    del lines[2]  # remove a middle entry
    _rewrite_lines(audit.audit_chain_file, lines)

    result = audit.verify_chain()
    assert result['ok'] is False
    # Either the seq gap or the broken prev_hash link localizes the deletion.
    assert result['error_seq'] == 2
    assert ('sequence break' in result['reason']) or ('broken link' in result['reason'])


def test_detects_reordered_entries(make_audit, tmp_path):
    audit = make_audit(tmp_path)
    _emit(audit, 4)
    lines = audit.audit_chain_file.read_text(encoding='utf-8').splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # swap
    _rewrite_lines(audit.audit_chain_file, lines)

    result = audit.verify_chain()
    assert result['ok'] is False


def test_empty_chain_is_ok(tmp_path):
    (tmp_path / audit_chain.CHAIN_FILENAME).write_text('', encoding='utf-8')
    result = audit_chain.verify_chain(tmp_path / audit_chain.CHAIN_FILENAME)
    assert result['ok'] is True


def test_missing_chain_reports_not_exist(tmp_path):
    result = audit_chain.verify_chain(tmp_path / 'nope.jsonl')
    assert result['ok'] is False
    assert 'does not exist' in result['reason']


# --------------------------------------------------------------------------
# Recovery across restarts (single-writer continuation)
# --------------------------------------------------------------------------

def test_chain_continues_across_instances(make_audit, tmp_path):
    a1 = make_audit(tmp_path)
    _emit(a1, 2)
    # Simulate restart: detach the first instance, build a fresh one on the
    # same directory; it must recover seq/last_hash and continue the chain.
    a1.audit_logger.removeHandler(a1.file_handler)
    a1.file_handler.close()

    a2 = make_audit(tmp_path)
    assert a2._next_seq == 2
    _emit(a2, 1)
    result = a2.verify_chain()
    assert result['ok'] is True
    assert result['count'] == 3
    assert result['last_seq'] == 2


def test_truncated_trailing_line_tolerated_on_recovery(make_audit, tmp_path):
    a1 = make_audit(tmp_path)
    _emit(a1, 2)
    a1.audit_logger.removeHandler(a1.file_handler)
    a1.file_handler.close()
    # Append a partial (interrupted) write.
    with open(tmp_path / audit_chain.CHAIN_FILENAME, 'a', encoding='utf-8') as f:
        f.write('{"seq": 2, "entry": {"opera')

    a2 = make_audit(tmp_path)
    # Recovery resumes from the last COMPLETE record (seq 1 -> next 2).
    assert a2._next_seq == 2


# --------------------------------------------------------------------------
# CLI verifier exit codes
# --------------------------------------------------------------------------

def test_cli_ok_returns_zero(make_audit, tmp_path, capsys):
    audit = make_audit(tmp_path)
    _emit(audit, 3)
    rc = audit_verify.main([str(audit.audit_chain_file)])
    assert rc == 0
    assert 'intact' in capsys.readouterr().out


def test_cli_broken_returns_one(make_audit, tmp_path):
    audit = make_audit(tmp_path)
    _emit(audit, 3)
    lines = audit.audit_chain_file.read_text(encoding='utf-8').splitlines()
    rec = json.loads(lines[1]); rec['entry']['status'] = 'tampered'
    lines[1] = json.dumps(rec)
    _rewrite_lines(audit.audit_chain_file, lines)
    rc = audit_verify.main([str(audit.audit_chain_file)])
    assert rc == 1


def test_cli_missing_returns_two(tmp_path):
    rc = audit_verify.main([str(tmp_path / 'nope.jsonl')])
    assert rc == 2


def test_cli_json_mode(make_audit, tmp_path, capsys):
    audit = make_audit(tmp_path)
    _emit(audit, 2)
    audit_verify.main(['--json', str(audit.audit_chain_file)])
    out = json.loads(capsys.readouterr().out)
    assert out['ok'] is True and out['count'] == 2
