"""`on_events: ["revoked"]` was documented, accepted, and never fired.

`docs/deploy-hooks.md` says deploy hooks run "after a certificate is issued,
renewed, or revoked", offers `"revoked"` in the `on_events` array, and
documents `CERTMATE_EVENT=revoked` for the hook to read. The configuration
accepts it without complaint.

Nothing ever ran it. `DeployManager.on_certificate_event` mapped
`certificate_created` and `certificate_renewed` and returned early on anything
else, so a hook written to react to a revocation sat there looking configured.

That is the worse kind of gap: not a missing feature an operator can see is
missing, but one the product offers, stores, and displays back to them. The
only way to find out was to revoke something and watch nothing happen.

Reported by the certmate-website session while writing the deploy-hooks page
against the code.

## What is still not true after this

Only **client** certificates can be revoked through CertMate — there is one
revoke route, `/api/client-certs/<id>/revoke`, and no equivalent for a server
certificate. So a `revoked` hook fires for client certificates and for nothing
else, which the documentation now says.
"""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager():
    settings = MagicMock()
    return DeployManager(settings, MagicMock(), MagicMock(), MagicMock(),
                         cert_dir=Path(tempfile.mkdtemp()),
                         data_dir=tempfile.mkdtemp())


def _ran(manager):
    """The (domain, event_type) pairs the hook runner was asked for."""
    return [call.args for call in manager._execute_hooks.call_args_list]


# --------------------------------------------------------------------------- #
# The event reaches the hooks
# --------------------------------------------------------------------------- #

def test_a_revocation_runs_the_hooks_written_for_it(manager):
    manager._execute_hooks = MagicMock(return_value=[{'success': True}])
    manager.on_certificate_event('certificate_revoked',
                                 {'domain': 'client-42',
                                  'resource_type': 'client_certificate'})
    assert _ran(manager) == [('client-42', 'revoked')]


def test_the_event_type_handed_to_the_hook_is_the_documented_word(manager):
    """`CERTMATE_EVENT` is documented as created / renewed / revoked /
    manual, and the hook reads it to decide what to do."""
    manager._execute_hooks = MagicMock(return_value=[])
    manager.on_certificate_event('certificate_revoked', {'domain': 'client-42'})
    assert _ran(manager)[0][1] == 'revoked'


def test_the_three_documented_events_all_arrive(manager):
    manager._execute_hooks = MagicMock(return_value=[])
    for event, expected in (('certificate_created', 'created'),
                            ('certificate_renewed', 'renewed'),
                            ('certificate_revoked', 'revoked')):
        manager.on_certificate_event(event, {'domain': 'example.com'})
    assert [args[1] for args in _ran(manager)] == ['created', 'renewed', 'revoked']


def test_an_event_nobody_documented_is_still_ignored(manager):
    """The early return is right for everything else; only the mapping was
    short. A deployed or expiring event must not run deploy hooks."""
    manager._execute_hooks = MagicMock(return_value=[])
    for event in ('certificate_deployed', 'certificate_expiring',
                  'certificate_deploy_incomplete', ''):
        manager.on_certificate_event(event, {'domain': 'example.com'})
    assert _ran(manager) == []


def test_a_revocation_without_a_subject_runs_nothing(manager):
    manager._execute_hooks = MagicMock(return_value=[])
    manager.on_certificate_event('certificate_revoked', {})
    assert _ran(manager) == []


# --------------------------------------------------------------------------- #
# ...and behaves like the other two once it gets there
# --------------------------------------------------------------------------- #

def _published(manager, event):
    return [call.args for call in manager.event_bus.publish.call_args_list
            if call.args and call.args[0] == event]


def test_a_successful_revoke_hook_is_reported_like_any_other(manager):
    manager._execute_hooks = MagicMock(return_value=[{'success': True}])
    manager.on_certificate_event('certificate_revoked', {'domain': 'client-42'})
    published = _published(manager, 'certificate_deployed')
    assert published and published[0][1]['event'] == 'revoked'


def test_a_revoke_hook_that_failed_says_so_like_any_other(manager):
    """The event that exists so an operator can tell "it ran" from "it was
    supposed to run" covers this path too, rather than being wired for the
    two events it was written for."""
    manager._execute_hooks = MagicMock(return_value=[{'success': False}])
    manager.on_certificate_event('certificate_revoked', {'domain': 'client-42'})
    assert _published(manager, 'certificate_deploy_incomplete')


def test_a_revoke_hook_that_raises_does_not_escape_the_listener(manager):
    """It runs on the event bus: an exception here would be swallowed by the
    dispatcher and the revocation would report success with nothing said."""
    manager._execute_hooks = MagicMock(side_effect=RuntimeError('hook on fire'))
    manager.on_certificate_event('certificate_revoked', {'domain': 'client-42'})
    incomplete = _published(manager, 'certificate_deploy_incomplete')
    assert incomplete and 'hook on fire' in str(incomplete[0][1])


# --------------------------------------------------------------------------- #
# What a hook that says nothing about events gets
# --------------------------------------------------------------------------- #

def test_a_hook_that_names_no_events_does_not_silently_gain_revocations():
    """The documentation said an absent `on_events` means all three. It has
    always meant two, and leaving it at two is the conservative reading:
    nobody's hook has ever run on a revocation, because nothing fired one, so
    adding it to the default would start running commands on an upgrade that
    the operator never asked to run there. `revoked` is opted into.
    """
    from modules.core.deployer import DEFAULT_ON_EVENTS

    assert DEFAULT_ON_EVENTS == ['created', 'renewed']
    assert 'revoked' not in DEFAULT_ON_EVENTS
