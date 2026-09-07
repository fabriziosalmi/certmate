"""Saving deploy hooks must not delete the deploy targets.

Found while adding maintenance windows (#632), which apply to typed deploy
targets as much as to shell hooks — and a window on a target is worth nothing
if pressing Save removes the target.

`deploy_hooks` in settings holds four keys: `enabled`, `global_hooks`,
`domain_hooks`, and `targets` — the typed deploy targets from #475. The
Settings -> Deploy screen manages the first three and has no editor for the
fourth: `loadConfig` never reads `targets`, so `saveConfig` posts a body
without them. `save_config` then assigned the whole block:

    settings['deploy_hooks'] = config

So opening Settings -> Deploy and pressing Save — without touching anything —
silently deleted every configured Kubernetes secret target. No error, no audit
entry naming the loss, and the next renewal simply stopped publishing to the
cluster.

The rule is the same one `CertificateService.update_config` already applies to
certificate metadata: **absent leaves alone, an explicit value replaces** —
including an explicit empty list, so a caller that means to clear the targets
still can.
"""
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager

pytestmark = [pytest.mark.unit]

TARGET = {'name': 'k8s-prod', 'type': 'kubernetes-secret',
          'config': {'secret_name': 'tls', 'in_cluster': True}}
HOOK = {'id': 'h1', 'name': 'reload', 'command': 'echo hi',
        'enabled': True, 'on_events': ['renewed']}


@pytest.fixture
def stored():
    return {'deploy_hooks': {
        'enabled': True, 'global_hooks': [HOOK], 'domain_hooks': {},
        'targets': [TARGET],
    }}


@pytest.fixture
def manager(stored):
    settings = MagicMock()
    settings.update.side_effect = lambda mutate, reason: mutate(stored)
    return DeployManager(settings, MagicMock(), MagicMock(), MagicMock(),
                         cert_dir=Path(tempfile.mkdtemp()),
                         data_dir=tempfile.mkdtemp())


def _ui_payload():
    """Exactly what the Settings -> Deploy screen posts: no `targets` key,
    because `loadConfig` never put one in the component's state."""
    return {'enabled': True, 'global_hooks': [dict(HOOK)], 'domain_hooks': {}}


def test_a_save_from_the_hooks_screen_keeps_the_targets(manager, stored):
    ok, error = manager.save_config(_ui_payload())

    assert ok, error
    assert stored['deploy_hooks'].get('targets') == [TARGET], (
        'saving deploy hooks deleted the typed deploy targets, which that '
        'screen has no editor for and the operator never touched'
    )


def test_the_hooks_themselves_are_still_replaced(manager, stored):
    """CONTROL: preserving absent keys must not turn the whole save into a
    merge that can never remove a hook."""
    ok, error = manager.save_config(
        {'enabled': True, 'global_hooks': [], 'domain_hooks': {}})

    assert ok, error
    assert stored['deploy_hooks']['global_hooks'] == [], (
        'removing every hook no longer removes them'
    )


def test_an_explicit_empty_list_still_clears_the_targets(manager, stored):
    """Absent and empty are different answers. A caller that means to clear
    the targets says so, and is obeyed."""
    ok, error = manager.save_config(dict(_ui_payload(), targets=[]))

    assert ok, error
    assert stored['deploy_hooks']['targets'] == []


def test_the_master_switch_still_moves(manager, stored):
    assert manager.save_config(dict(_ui_payload(), enabled=False))[0]
    assert stored['deploy_hooks']['enabled'] is False


def test_a_first_save_on_an_instance_with_no_deploy_block_works(manager):
    """CONTROL: the merge must not assume something is already there."""
    empty = {}
    manager.settings_manager.update.side_effect = (
        lambda mutate, reason: mutate(empty))

    assert manager.save_config(_ui_payload())[0]
    assert empty['deploy_hooks']['global_hooks'][0]['id'] == 'h1'


def test_a_corrupt_existing_block_is_replaced_not_merged_into(manager):
    """A hand-edited `deploy_hooks: "yes"` must not make the save crash or
    quietly produce something that is neither."""
    broken = {'deploy_hooks': 'yes'}
    manager.settings_manager.update.side_effect = (
        lambda mutate, reason: mutate(broken))

    assert manager.save_config(_ui_payload())[0]
    assert broken['deploy_hooks']['global_hooks'][0]['id'] == 'h1'
    assert 'targets' not in broken['deploy_hooks']


def test_a_window_on_a_target_survives_a_hooks_save(manager, stored):
    """Why this was found. Maintenance windows (#632) apply to targets too,
    and a window is worth nothing if saving hooks removes the target under it.
    """
    stored['deploy_hooks']['targets'] = [
        dict(TARGET, window={'start': '02:00', 'end': '04:00',
                             'days': ['sun'], 'timezone': 'UTC'})]

    assert manager.save_config(_ui_payload())[0]
    assert stored['deploy_hooks']['targets'][0]['window']['days'] == ['sun']


def test_the_save_stays_atomic(manager):
    """It goes through settings_manager.update, so a concurrent DNS-provider
    save cannot lose it. A read-modify-write here would reintroduce exactly
    the race that call exists to prevent."""
    seen = []
    manager.settings_manager.update.side_effect = (
        lambda mutate, reason: seen.append(reason) or mutate({}))

    manager.save_config(_ui_payload())
    assert seen == ['deploy_hooks_save']
    assert not manager.settings_manager.save_settings.called, (
        'the save bypassed the atomic update path'
    )


def test_concurrent_saves_do_not_lose_the_targets(manager, stored):
    """The merge reads and writes inside the mutate callback, which
    settings_manager.update serialises. Doing it outside would restore the
    lost-update this fix is about, only harder to see."""
    lock = threading.Lock()

    def _serialised(mutate, reason):
        with lock:
            mutate(stored)
    manager.settings_manager.update.side_effect = _serialised

    threads = [threading.Thread(target=manager.save_config,
                                args=(_ui_payload(),)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert stored['deploy_hooks']['targets'] == [TARGET]
