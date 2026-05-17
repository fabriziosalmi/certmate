"""
Defensive coverage for the timeout-coercion path in DeployManager._run_hook.

save_config (the write path) calls `int(hook.get('timeout', DEFAULT_TIMEOUT))`
on every hook before persisting it, so under normal flow `timeout` arrives at
_run_hook as an int. But a hand-edited settings.json, an older config schema
migrated forward, or a hook constructed directly in code could carry a string
or even a None. Before the fix, `max(str, 1)` raised TypeError in Python 3
and crashed the renewal worker silently.

This test exercises _run_hook with four malformed timeout shapes and asserts
the runner does NOT raise; it falls back to DEFAULT_TIMEOUT (or a coerced int
when coercion succeeds).
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager, DEFAULT_TIMEOUT


class _CapturedShell:
    """Stand-in for ShellExecutor that records the timeout it was called with."""

    def __init__(self):
        self.last_timeout = None

    def run(self, *args, **kwargs):
        self.last_timeout = kwargs.get('timeout')
        result = MagicMock()
        result.returncode = 0
        result.stdout = ''
        result.stderr = ''
        return result


@pytest.fixture
def deploy_manager(tmp_path):
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {'deploy_hooks': {'enabled': True}}
    shell = _CapturedShell()
    mgr = DeployManager(
        settings_manager=settings_manager,
        shell_executor=shell,
        audit_logger=MagicMock(),
        event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs',
        data_dir=str(tmp_path / 'data'),
    )
    mgr._shell_for_test = shell
    return mgr


@pytest.mark.parametrize("bad_timeout,expected", [
    ("30", 30),                  # coercible string -> int
    (None, DEFAULT_TIMEOUT),     # missing -> default
    ("abc", DEFAULT_TIMEOUT),    # non-numeric string -> default
    (3.14, 3),                   # float -> int() truncates
])
def test_run_hook_coerces_malformed_timeout_without_typeerror(
    deploy_manager, bad_timeout, expected
):
    hook = {
        'id': 'h1', 'name': 'test', 'command': '/bin/true',
        'enabled': True, 'timeout': bad_timeout, 'on_events': ['renewed'],
    }
    # Must not raise.
    result = deploy_manager._run_hook(hook, 'example.com', 'renewed')

    passed = deploy_manager._shell_for_test.last_timeout
    assert isinstance(passed, int), (
        f"timeout passed to shell_executor.run must be int, got "
        f"{type(passed).__name__}={passed!r}"
    )
    assert passed == expected, (
        f"For input timeout={bad_timeout!r} expected {expected}, got {passed}"
    )
    # And the hook itself reported success (no exception path taken).
    assert result['error'] is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
