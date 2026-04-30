"""
Regression test for issue #101.

When `test_hook(hook_id)` is called with a hook ID not in settings, the
returned error message must point at the two real-world causes (stale UI
state vs save-time validator rejection) rather than the bare and
unactionable string "Hook not found".
"""

from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager


pytestmark = [pytest.mark.unit]


def test_test_hook_returns_actionable_message_for_missing_hook(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'deploy_hooks': {
            'enabled': True,
            'global_hooks': [],
            'domain_hooks': {},
        },
    }
    dm = DeployManager(
        settings_manager=settings,
        shell_executor=MagicMock(),
        audit_logger=MagicMock(),
        event_bus=MagicMock(),
        cert_dir=tmp_path / "certs",
        data_dir=str(tmp_path),
    )

    result = dm.test_hook('does-not-exist')

    # Old behavior: {'error': 'Hook not found', 'hook_id': ...}
    # New behavior: actionable error that names the two real causes.
    assert result.get('hook_id') == 'does-not-exist'
    assert 'reason' in result, "Should include a structured reason field for log triage"
    assert result['reason'] == 'hook_missing_from_config'

    msg = result.get('error', '')
    assert 'does-not-exist' in msg, "error message must echo the hook id"
    # Both real causes named in the message:
    assert 'out of sync' in msg.lower() or 'page' in msg.lower(), (
        "must mention stale UI as a likely cause"
    )
    assert 'safety validator' in msg.lower() or 'rejected' in msg.lower(), (
        "must mention save-time validator rejection as a likely cause"
    )
