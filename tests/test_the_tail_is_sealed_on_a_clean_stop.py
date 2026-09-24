"""A clean shutdown seals the audit entries written since the last checkpoint.

Item 10 of #876. A signed checkpoint is written every `checkpoint_interval`
entries — 100 by default — and `write_checkpoint`'s own docstring said what was
missing:

    The only caller today is the every-`checkpoint_interval`-entries path in
    the append; nothing calls it on shutdown, so entries after the last
    checkpoint stay unsealed.

`docs/compliance.md` lists the consequence as a known limit: entries written
after the last checkpoint can be dropped undetected until the next one seals
them. On an instance that stops after 99 entries, that is 99 entries anyone who
can write the file can remove without the verification noticing.

`stop_background_work` now seals, and **last of all**. Draining the event bus
dispatches handlers, and some of them append audit entries; sealing before that
would sign a head that is about to move and leave the newest entries — the ones
written while shutting down — outside the very checkpoint this exists to
create. That ordering is the part worth testing, because a checkpoint written
at the wrong moment looks exactly like one written at the right one.

**It narrows the window; it does not close it.** A crash or a SIGKILL still
leaves a tail — correctly, because work that must never delay a kill must not
run on one — and an operator holding the signing key can still re-sign over a
rewritten chain. The documentation says both, and a test keeps it saying so.
"""
import pathlib

import pytest

from modules.core.audit import AuditLogger
from modules.core.audit_signing import AuditSigner

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


class _Bus:
    """An event bus whose `stop()` writes an audit entry, the way a real drain
    does when a queued handler logs one."""

    def __init__(self, audit, entries=1):
        self._audit = audit
        self._entries = entries
        self.stopped = False

    def stop(self):
        self.stopped = True
        for i in range(self._entries):
            self._audit.log_operation(
                'renew', 'certificate', f'drained{i}.example.com', 'success')
        return 0


@pytest.fixture
def audit(tmp_path):
    instance = AuditLogger(tmp_path / 'logs', chain_dir=tmp_path / 'chain',
                           signer=AuditSigner(tmp_path), checkpoint_interval=100)
    yield instance
    if instance.file_handler is not None:
        instance.audit_logger.removeHandler(instance.file_handler)
        instance.file_handler.close()


def _container(audit, bus=None):
    from modules.core.factory import AppContainer

    container = AppContainer.__new__(AppContainer)
    container.shutdown_complete = False
    container.scheduler = None
    container.request_watchdog = None
    container.managers = {'audit': audit}
    if bus is not None:
        container.managers['events'] = bus
    return container


def _checkpoints(tmp_path):
    path = tmp_path / 'chain' / 'certificate_audit.checkpoints.jsonl'
    if not path.exists():
        return []
    import json
    return [json.loads(line) for line in
            path.read_text(encoding='utf-8').splitlines() if line.strip()]


def test_nothing_is_sealed_before_the_interval(audit, tmp_path):
    """Guard the guard: if a checkpoint were written on every entry, every
    assertion below would pass without the shutdown doing anything."""
    for i in range(5):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success')
    assert _checkpoints(tmp_path) == []


def test_a_clean_stop_seals_what_is_there(audit, tmp_path):
    from modules.core.factory import stop_background_work

    for i in range(5):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success')

    summary = stop_background_work(_container(audit))

    written = _checkpoints(tmp_path)
    assert len(written) == 1, 'the tail was not sealed'
    assert written[0]['seq'] == 4
    assert written[0]['signature']
    assert summary['checkpoint'] == 4


def test_the_seal_covers_entries_written_while_stopping(audit, tmp_path):
    """The ordering. Sealing before the bus drains would sign seq 4 and leave
    the entry the drain produced outside it — a checkpoint that looks right
    and attests one entry less than the chain holds."""
    from modules.core.factory import stop_background_work

    for i in range(5):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success')
    bus = _Bus(audit, entries=1)

    stop_background_work(_container(audit, bus=bus))

    assert bus.stopped
    written = _checkpoints(tmp_path)
    assert len(written) == 1
    assert written[0]['seq'] == 5, (
        'the checkpoint was written before the bus drained, so the entry that '
        'drain produced is outside it'
    )


def test_an_empty_chain_seals_nothing(audit, tmp_path):
    """`write_checkpoint` returns None for an empty chain, and an instance
    that started and stopped without auditing anything must not leave a
    checkpoint attesting nothing."""
    from modules.core.factory import stop_background_work

    summary = stop_background_work(_container(audit))

    assert _checkpoints(tmp_path) == []
    assert summary['checkpoint'] is None


def test_a_second_stop_changes_nothing(audit, tmp_path):
    """`stop_background_work` is idempotent — app.py calls it on Ctrl-C and
    atexit calls it again. A second checkpoint for the same head would be
    noise in a file auditors read."""
    from modules.core.factory import stop_background_work

    audit.log_operation('renew', 'certificate', 'a.example.com', 'success')
    container = _container(audit)

    stop_background_work(container)
    stop_background_work(container)

    assert len(_checkpoints(tmp_path)) == 1


def test_a_failure_to_seal_does_not_break_the_shutdown(audit, tmp_path):
    """Sealing is best-effort by design: the process is going away, and an
    audit checkpoint must never be the reason a container fails to stop."""
    from modules.core.factory import stop_background_work

    audit.log_operation('renew', 'certificate', 'a.example.com', 'success')

    class _Exploding:
        def write_checkpoint(self):
            raise OSError('disk gone')

    summary = stop_background_work(_container(_Exploding()))
    assert summary['checkpoint'] is None


def test_the_chain_still_verifies_after_the_seal(audit, tmp_path):
    from modules.core import audit_chain
    from modules.core.factory import stop_background_work

    for i in range(4):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success')
    stop_background_work(_container(audit))

    assert audit_chain.verify_chain(audit.audit_chain_file)['ok']


def test_the_docs_still_say_what_this_does_not_close():
    """The limit is narrowed, not removed. A page that stopped saying so
    would be claiming more than the code does — and a crash still leaves a
    tail, deliberately."""
    page = (REPO / 'docs' / 'compliance.md').read_text(encoding='utf-8')
    assert 'sealed on a clean shutdown' in page
    assert 'crash' in page.lower()
