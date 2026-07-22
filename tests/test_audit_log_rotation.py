"""The human-readable audit log is rotated by construction.

Regression tests for #443. `AuditLogger.__init__` built a plain
`logging.FileHandler` for `logs/audit/certificate_audit.log`, which grew without
bound. #431 bounded the *application* log through
`configure_structured_logging`; this handler is constructed independently and
was never reached by that fix, so the file was still unbounded in production
after the fix shipped.

Rotating it is safe precisely because it carries no integrity property: it is
human-readable text, not hashed, not chained, and the `logs/` tree is excluded
from backups. The verifiable artifact is the hash chain under `data/audit/`,
and these tests pin that the chain is left alone — rotating it naively would
break the property it exists for (#437).
"""

import json
import logging
import os

import pytest

from modules.core import audit_chain
from modules.core.audit import (
    DEFAULT_AUDIT_LOG_BACKUP_COUNT,
    DEFAULT_AUDIT_LOG_MAX_BYTES,
    AuditLogger,
)


pytestmark = [pytest.mark.unit]


@pytest.fixture
def make_audit():
    """Each AuditLogger adds a handler to the shared 'certmate.audit' logger;
    detach them so one test cannot write into another's file."""
    created = []

    def _make(log_dir, **kw):
        a = AuditLogger(log_dir, **kw)
        created.append(a)
        return a

    yield _make
    for a in created:
        if a.file_handler is not None:
            a.audit_logger.removeHandler(a.file_handler)
            a.file_handler.close()


def _emit(audit, n, size=0):
    for i in range(n):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success',
                            details={'pad': 'x' * size} if size else None)


def test_the_handler_rotates(make_audit, tmp_path):
    audit = make_audit(tmp_path / 'logs')

    assert isinstance(audit.file_handler, logging.handlers.RotatingFileHandler)
    assert audit.file_handler.maxBytes == DEFAULT_AUDIT_LOG_MAX_BYTES
    assert audit.file_handler.backupCount == DEFAULT_AUDIT_LOG_BACKUP_COUNT


def test_it_actually_rolls_and_the_tail_is_capped(make_audit, tmp_path):
    log_dir = tmp_path / 'logs'
    audit = make_audit(log_dir, max_bytes=4096, backup_count=2)

    _emit(audit, 200, size=200)

    names = sorted(p.name for p in log_dir.glob('certificate_audit.log*'))
    assert 'certificate_audit.log' in names
    assert 'certificate_audit.log.1' in names, "the audit log never rotated"
    assert 'certificate_audit.log.3' not in names, "backupCount did not cap the tail"
    for name in names:
        assert (log_dir / name).stat().st_size < 40_000


def test_the_line_format_is_unchanged(make_audit, tmp_path):
    """get_recent_entries splits on ' - INFO - ' and parses the rest as JSON.
    Rotation must not disturb that."""
    audit = make_audit(tmp_path / 'logs')

    audit.log_operation('create', 'certificate', 'example.com', 'success')

    line = audit.audit_log_file.read_text(encoding='utf-8').strip()
    assert ' - INFO - ' in line
    entry = json.loads(line.split(' - INFO - ', 1)[1])
    assert entry['resource_id'] == 'example.com'
    assert audit.get_recent_entries(limit=10)[0]['resource_id'] == 'example.com'


def test_env_overrides_are_honoured(make_audit, tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_AUDIT_LOG_MAX_BYTES', '2048')
    monkeypatch.setenv('CERTMATE_AUDIT_LOG_BACKUP_COUNT', '1')

    audit = make_audit(tmp_path / 'logs')

    assert audit.file_handler.maxBytes == 2048
    assert audit.file_handler.backupCount == 1


@pytest.mark.parametrize('bad', ['', 'lots', '-1', '10MB'])
def test_an_unusable_env_value_falls_back_instead_of_crashing(
        make_audit, tmp_path, monkeypatch, bad):
    """A typo in a log-rotation setting must not take a certificate manager
    down at startup."""
    monkeypatch.setenv('CERTMATE_AUDIT_LOG_MAX_BYTES', bad)

    audit = make_audit(tmp_path / 'logs')

    assert audit.file_handler.maxBytes == DEFAULT_AUDIT_LOG_MAX_BYTES


def test_rotation_can_be_turned_off_explicitly(make_audit, tmp_path):
    """0 is how `logging` spells 'never roll'; it stays available for an
    operator who ships the file elsewhere."""
    audit = make_audit(tmp_path / 'logs', max_bytes=0)

    assert audit.file_handler.maxBytes == 0


# --------------------------------------------------------------------------
# The chain is a different file with different rules
# --------------------------------------------------------------------------

def test_the_hash_chain_is_not_rotated(make_audit, tmp_path):
    """The chain must stay a single append-only file: rotating it naively
    breaks the tamper-evidence it exists for (#437)."""
    audit = make_audit(tmp_path / 'logs', chain_dir=tmp_path / 'data',
                       max_bytes=2048, backup_count=2)

    _emit(audit, 200, size=200)

    chain_files = sorted(p.name for p in (tmp_path / 'data').iterdir())
    assert chain_files == [audit_chain.CHAIN_FILENAME]
    assert audit.verify_chain()['ok'], "rotating the .log disturbed the chain"
    assert audit.verify_chain()['count'] == 200


# --------------------------------------------------------------------------
# Failure posture
# --------------------------------------------------------------------------

@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_an_unwritable_log_dir_does_not_stop_the_application(make_audit, tmp_path, caplog):
    """This previously raised out of __init__, which the factory calls
    unguarded: an unwritable logs directory took the whole application down
    over a *log file*."""
    blocked = tmp_path / 'blocked'
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        with caplog.at_level(logging.ERROR):
            audit = make_audit(blocked / 'logs', chain_dir=tmp_path / 'data')

        assert audit.file_handler is None
        assert 'Could not open audit log file' in caplog.text

        # And the record that matters is still written and verifiable.
        _emit(audit, 3)
        assert audit.verify_chain()['ok']
        assert audit.verify_chain()['count'] == 3
        assert audit.get_recent_entries(limit=10) == []
    finally:
        blocked.chmod(0o700)


def test_the_dead_whole_file_reader_is_gone(make_audit, tmp_path):
    """get_entries_by_resource read the entire log, had no callers, and behind
    a rotating handler would have silently returned only what survived in the
    active file."""
    audit = make_audit(tmp_path / 'logs')

    assert not hasattr(audit, 'get_entries_by_resource')
