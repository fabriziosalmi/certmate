"""
Regression test for issue #165: deploy history "stays empty even after a
manual trigger" with status 200 and a clear Kubernetes log.

The reporter's situation matches a PersistentVolume mounted with an
owner uid that doesn't match the certmate user (uid 1000) in the
container. `_log_history` then raises `PermissionError` on every write
and the old `logger.debug(...)` call swallowed it at production log
level (INFO/WARNING). The endpoint kept returning 200 with an empty
list, leaving the operator without a single diagnostic breadcrumb.

This test pins the write-failure path to WARNING-level so a future
maintainer can't quietly demote it again, and locks in the path in
the log message — the path is the actionable bit for the operator
("oh, the volume must be writable by uid 1000").

A second test guards the read-side: a corrupted line in the JSONL
file must skip the line, not blank the whole pane.
"""
import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from modules.core.deployer import DeployManager
from modules.core.shell import MockShellExecutor


pytestmark = [pytest.mark.unit]


@pytest.fixture
def deploy_manager(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {'deploy_hooks': {'enabled': True}}
    return DeployManager(
        settings_manager=settings,
        shell_executor=MockShellExecutor(),
        audit_logger=MagicMock(),
        event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs',
        data_dir=str(tmp_path / 'data'),
    )


def test_log_history_permission_error_logs_at_warning(deploy_manager, caplog):
    """A write failure caused by a PermissionError on the data volume
    must surface as a WARNING with the path, not a debug whisper."""
    result = {
        'hook_id': 'h1', 'hook_name': 'Test', 'domain': 'example.com',
        'event': 'manual', 'success': True, 'duration_ms': 0,
    }

    with patch('builtins.open', side_effect=PermissionError(13, "Permission denied")):
        with caplog.at_level(logging.WARNING, logger='modules.core.deployer'):
            deploy_manager._log_history(result)

    records = [r for r in caplog.records if r.name == 'modules.core.deployer']
    assert records, "expected a WARNING from the deployer logger"
    assert any(r.levelno == logging.WARNING for r in records), (
        "write failure must be WARNING, not debug — that's the whole point of #165"
    )
    assert any('deploy_history.jsonl' in r.getMessage() for r in records), (
        "log message must cite the path so the operator knows where to look"
    )
    assert any('uid 1000' in r.getMessage() for r in records), (
        "log message must hint at the typical Kubernetes root cause"
    )


def test_get_history_skips_corrupted_line_instead_of_blanking_whole_pane(
    deploy_manager, tmp_path
):
    """A single corrupted JSONL line must not return [] for the whole
    history. The healthy lines around it must still come through."""
    history_path = deploy_manager._history_path
    history_path.parent.mkdir(parents=True, exist_ok=True)
    good = json.dumps({
        'hook_id': 'h1', 'hook_name': 'Good', 'domain': 'a.com',
        'event': 'manual', 'success': True, 'duration_ms': 5,
    })
    good2 = json.dumps({
        'hook_id': 'h2', 'hook_name': 'Good2', 'domain': 'b.com',
        'event': 'manual', 'success': True, 'duration_ms': 5,
    })
    history_path.write_text(good + '\n' + 'this-is-not-json\n' + good2 + '\n')

    entries = deploy_manager.get_history()

    assert len(entries) == 2, (
        f"expected the 2 healthy entries to survive a corrupted middle line, "
        f"got {len(entries)}"
    )
    names = {e['hook_name'] for e in entries}
    assert names == {'Good', 'Good2'}
