"""A certificate obtained but not published is not a completed renewal.

The listener that runs deploy hooks caught everything and logged it. So a
renewal that succeeded at the CA and then failed to reach the systems that
serve it was reported, to every other subscriber, as a completed renewal — and
the machines in front were still presenting the previous certificate.

`deploy_hook_failed` already fires *per hook*. That is the right grain for
"which target broke" and the wrong grain for the question an operator actually
asks after a renewal: **is this certificate live?** Answering it meant counting
per-hook failures across a stream, and a notifier had no single event meaning
"renewed, not deployed".

## What this deliberately does not do

The finding asked for `deployed: true/false` alongside `renewed` in the renewal
result. That is not reachable: hooks run on the event bus, so the renewal has
already returned by the time any of it is known. Carrying the outcome back into
that result would mean making issuance wait for a deploy hook — with a 300
second timeout — which is precisely what the bounded dispatch exists to
prevent. An event is where a fact that arrives later belongs.
"""
import logging
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


def _published(manager, event):
    return [call.args for call in manager.event_bus.publish.call_args_list
            if call.args and call.args[0] == event]


def _hooks_return(manager, results):
    manager._execute_hooks = MagicMock(return_value=results)


# --- when a deploy did not fully succeed --------------------------------

def test_a_failed_hook_produces_one_event_for_the_certificate(manager):
    _hooks_return(manager, [{'success': True}, {'success': False},
                            {'success': False}])

    manager.on_certificate_event('certificate_renewed',
                                 {'domain': 'example.com'})

    incomplete = _published(manager, 'certificate_deploy_incomplete')
    assert len(incomplete) == 1, (
        'a renewal that did not reach production produced no single event '
        'saying so'
    )
    payload = incomplete[0][1]
    assert payload['domain'] == 'example.com'
    assert payload['event'] == 'renewed'
    assert payload['failed'] == 2
    assert payload['total'] == 3


def test_the_partial_success_is_still_announced(manager):
    """CONTROL: one target failing must not suppress the news that the others
    worked — a subscriber watching for 'the cert is live somewhere' still
    needs it."""
    _hooks_return(manager, [{'success': True}, {'success': False}])
    manager.on_certificate_event('certificate_renewed',
                                 {'domain': 'example.com'})

    assert _published(manager, 'certificate_deployed')
    assert _published(manager, 'certificate_deploy_incomplete')


def test_the_failure_is_logged_with_the_consequence(manager, caplog):
    _hooks_return(manager, [{'success': False}])
    with caplog.at_level(logging.ERROR):
        manager.on_certificate_event('certificate_renewed',
                                     {'domain': 'example.com'})

    errors = [r.getMessage() for r in caplog.records
              if r.levelno >= logging.ERROR]
    assert errors, 'nothing was logged at ERROR'
    assert 'previous certificate' in errors[0], (
        f'the log says what happened but not what it means: {errors[0]}'
    )


def test_a_crash_in_the_listener_also_says_so(manager):
    """The path that motivated the finding. `except Exception: log` meant a
    deploy that blew up was indistinguishable from one that never ran."""
    manager._execute_hooks = MagicMock(side_effect=RuntimeError('boom'))

    manager.on_certificate_event('certificate_renewed',
                                 {'domain': 'example.com'})

    incomplete = _published(manager, 'certificate_deploy_incomplete')
    assert len(incomplete) == 1
    assert 'boom' in incomplete[0][1]['error']


# --- when it did, or when there was nothing to do -----------------------

def test_a_fully_successful_deploy_says_nothing_extra(manager):
    """CONTROL: an event on every renewal is an event nobody reads."""
    _hooks_return(manager, [{'success': True}, {'success': True}])
    manager.on_certificate_event('certificate_renewed',
                                 {'domain': 'example.com'})

    assert _published(manager, 'certificate_deployed')
    assert not _published(manager, 'certificate_deploy_incomplete')


def test_no_hooks_at_all_is_not_an_incomplete_deploy(manager):
    """CONTROL, and the case that would fire on most instances: a certificate
    on an instance with no hooks configured is not 'incompletely deployed',
    it is a certificate nobody asked to publish."""
    _hooks_return(manager, [])
    manager.on_certificate_event('certificate_renewed',
                                 {'domain': 'example.com'})

    assert not _published(manager, 'certificate_deploy_incomplete')
    assert not _published(manager, 'certificate_deployed')


def test_an_unrelated_event_is_ignored(manager):
    manager._execute_hooks = MagicMock()
    manager.on_certificate_event('certificate_expiring',
                                 {'domain': 'example.com'})
    assert not manager._execute_hooks.called


def test_a_creation_reports_its_own_event_type(manager):
    _hooks_return(manager, [{'success': False}])
    manager.on_certificate_event('certificate_created',
                                 {'domain': 'example.com'})
    assert _published(manager, 'certificate_deploy_incomplete')[0][1]['event'] \
        == 'created'


# --- the operator cannot silence it by accident -------------------------

def test_the_event_is_delivered_whatever_the_filter_says():
    """It reports a failure an operator must not be able to silence by
    accident — the same reason deploy_hook_failed is on this list. Neither is
    among the five certificate_* events the UI offers, so ANY filter drops
    them unless they are here."""
    from modules.core.notifier import _ALWAYS_NOTIFY_EVENTS
    assert 'certificate_deploy_incomplete' in _ALWAYS_NOTIFY_EVENTS
    assert 'deploy_hook_failed' in _ALWAYS_NOTIFY_EVENTS
