"""A record cut short by a crash does not swallow the next one or break the chain.

The audit chain is append-only, one JSON record per line. A process killed in
the middle of an append leaves the start of a record with no newline. Recovery
resumed from the last record that parsed, which is right, and then the next
append wrote its line straight after the stray bytes: the fragment and the new
record became one unparseable line. That audit event was lost, and the verifier,
which reads a bad line in the middle of the file as tampering, reported the
chain broken from then on, for a crash nobody caused on purpose.
"""
import json

import pytest

from modules.core import audit_chain
from modules.core.audit import AuditLogger

pytestmark = [pytest.mark.unit]


@pytest.fixture
def make_audit():
    created = []

    def _make(dir_path, **kw):
        logger = AuditLogger(dir_path, **kw)
        created.append(logger)
        return logger

    yield _make
    for logger in created:
        logger.audit_logger.removeHandler(logger.file_handler)
        logger.file_handler.close()


def _emit(audit, start, n):
    for i in range(start, start + n):
        audit.log_operation('create', 'certificate', f'd{i}.example.com', 'success',
                            actor={'kind': 'agent', 'id': 'k1'}, trigger={'cause': 'agent'})


def _tear_the_tail(chain_file, keep=60):
    """What a kill in the middle of an append leaves: the start of a record, no newline."""
    head = json.dumps(audit_chain.make_line(99, {'operation': 'create', 'resource_id': 'torn'}, 'x'))
    with open(chain_file, 'ab') as handle:
        handle.write(head[:keep].encode())


def test_the_chain_is_intact_after_a_torn_tail_and_later_events(make_audit, tmp_path):
    first = make_audit(tmp_path)
    _emit(first, 0, 3)
    _tear_the_tail(first.audit_chain_file)

    restarted = make_audit(tmp_path)
    _emit(restarted, 10, 2)

    verdict = audit_chain.verify_chain(first.audit_chain_file)
    assert verdict['ok'] is True, verdict
    assert verdict['count'] == 5            # the three before, the two after; none swallowed


def test_the_stray_bytes_are_kept_beside_the_chain_not_thrown_away(make_audit, tmp_path):
    first = make_audit(tmp_path)
    _emit(first, 0, 1)
    _tear_the_tail(first.audit_chain_file, keep=40)

    _emit(make_audit(tmp_path), 5, 1)

    kept = list(tmp_path.rglob('*.torn'))
    assert kept, 'the cut-short record should be set aside, not deleted'
    assert b'"seq"' in kept[0].read_bytes()


def test_a_chain_that_ends_properly_is_left_alone(make_audit, tmp_path):
    audit = make_audit(tmp_path)
    _emit(audit, 0, 3)
    before = audit.audit_chain_file.read_bytes()

    _emit(make_audit(tmp_path), 3, 1)

    after = audit.audit_chain_file.read_bytes()
    assert after.startswith(before)
    assert not list(tmp_path.rglob('*.torn'))
    assert audit_chain.verify_chain(audit.audit_chain_file)['count'] == 4


def test_a_whole_record_that_only_lacks_its_newline_is_kept_and_chained_on(make_audit, tmp_path):
    first = make_audit(tmp_path)
    _emit(first, 0, 2)
    whole = audit_chain.make_line(first._next_seq, {'operation': 'create', 'resource_id': 'whole'},
                                  first._last_hash)
    with open(first.audit_chain_file, 'ab') as handle:     # the write stopped before the "\n"
        handle.write(json.dumps(whole, ensure_ascii=False).encode())

    _emit(make_audit(tmp_path), 7, 1)

    verdict = audit_chain.verify_chain(first.audit_chain_file)
    assert verdict['ok'] is True, verdict
    assert verdict['count'] == 4            # two, the whole one, and the new one
    assert not list(tmp_path.rglob('*.torn'))
