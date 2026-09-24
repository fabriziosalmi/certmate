"""`save_config` promised that an absent key is left alone. `enabled` was not.

The docstring says, in as many words: "A key the payload does not mention is
left as it was … Absent leaves alone; an explicit value, including an empty
list, replaces." It was written for `targets`, which have no UI editor and
were being deleted by a Save from the Deploy screen.

Two lines below it:

    if not isinstance(config.get('enabled'), bool):
        config['enabled'] = False

`config.get('enabled')` is None for an absent key, None is not a bool, so a
missing key was rewritten to False *before* the merge — and the merge then
applied it over the stored True. `POST /api/deploy/config {"targets": [...]}`,
which is exactly the call `docs/deploy-hooks.md` tells an API client to make,
turned off every hook and every target, left them all listed in the config,
and answered "Deploy configuration saved".

The built-in UI always sends `enabled`, so this only ever bit API clients —
the ones the missing UI forces to exist.
"""
import tempfile
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
    """Built the way tests/test_saving_deploy_hooks_keeps_the_targets.py
    builds it — the same defect class, one key over."""
    settings = MagicMock()
    settings.update.side_effect = lambda mutate, reason: mutate(stored)
    deployer = DeployManager(settings, MagicMock(), MagicMock(), MagicMock(),
                             cert_dir=Path(tempfile.mkdtemp()),
                             data_dir=tempfile.mkdtemp())
    return deployer, stored


def _stored(stored):
    return stored['deploy_hooks']


def test_a_payload_without_enabled_leaves_it_alone(manager):
    """THE regression, in the shape the docs hand to an API client."""
    deployer, stored = manager

    ok, err = deployer.save_config({'targets': [TARGET]})

    assert (ok, err) == (True, None)
    assert _stored(stored)['enabled'] is True, (
        'a save that never mentioned `enabled` switched deployment off'
    )


def test_the_key_it_did_mention_is_still_replaced(manager):
    """CONTROL. The rule is "absent leaves alone", not "enabled is
    immutable" — a fix that ignored the key entirely would pass the test
    above and make the switch unusable."""
    deployer, stored = manager

    assert deployer.save_config({'enabled': False})[0] is True
    assert _stored(stored)['enabled'] is False

    assert deployer.save_config({'enabled': True})[0] is True
    assert _stored(stored)['enabled'] is True


@pytest.mark.parametrize('value', ['true', 1, 0, None, [], 'yes'])
def test_a_value_that_is_not_a_decision_is_refused(manager, value):
    """It used to be read as False, silently. Whatever the sender meant by
    `"enabled": "true"`, it was not "turn everything off and report
    success"."""
    deployer, stored = manager

    ok, err = deployer.save_config({'enabled': value})

    assert ok is False
    assert 'true or false' in err
    assert _stored(stored)['enabled'] is True, 'a refused save still wrote'


def test_the_other_keys_still_survive_a_partial_save(manager):
    """The defect this docstring was written for, still fixed: `targets` has
    no UI editor, so a Save from the Deploy screen must not delete it."""
    deployer, stored = manager

    deployer.save_config({'enabled': True, 'global_hooks': [], 'domain_hooks': {}})

    assert [t['name'] for t in _stored(stored)['targets']] == ['k8s-prod']


def test_the_docstring_and_the_code_still_agree():
    """The promise is load-bearing here — it is why the merge exists at all.
    If it is ever narrowed, this file's premise goes with it."""
    import inspect

    from modules.core.deployer import DeployManager

    doc = inspect.getdoc(DeployManager.save_config) or ''

    assert 'does not mention is left as it was' in doc
