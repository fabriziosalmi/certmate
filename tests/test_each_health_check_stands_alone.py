"""Each health check is a function now, so each one can be called.

`create_health_resources` was the most complex unit in the repository —
cyclomatic complexity 64, higher than the certificate renewal path it reports
on. The complexity was not one hard decision: it was twelve independent
try/except sections inlined into two request handlers, none of which could be
entered except through Flask.

The practical cost was that a branch was only reachable by building an app.
Exercising "the configured storage backend failed to initialise and CertMate
silently fell back to local disk" — which is the check that exists precisely
because it used to be invisible — meant standing up a whole application to get
at four lines.

Every check and every collector is now a module-level function taking a
context and returning data, and this file calls them directly. The severity
ordering, which used to live implicitly in four `if overall == 'healthy'`
guards, is now one `max` with a test on it.

The behaviour is unchanged. That was checked by running the old and the new
module against identical inputs and diffing the JSON — once with every
subsystem working and once with every optional subsystem raising — and the
payloads were identical in both.
"""
from unittest.mock import MagicMock

import pytest

from modules.api.resources_health import (
    DEGRADED, HEALTHY, UNHEALTHY, build_diagnostics_snapshot, check_scheduler,
    check_settings, check_storage, collect_recent_audit, collect_scheduler,
    run_health_checks,
)

pytestmark = [pytest.mark.unit]


def _ctx(**managers):
    """A context with nothing wired but what a test asks for. This is the
    thing the old shape made impossible."""
    context = MagicMock()
    context.managers = managers
    return context


# --- one check at a time -------------------------------------------------

def test_unreadable_settings_are_unhealthy():
    context = _ctx()
    context.settings.load_settings.side_effect = OSError('disk gone')

    assert check_settings(context) == ('settings', 'error', UNHEALTHY)


def test_readable_settings_are_healthy():
    assert check_settings(_ctx()) == ('settings', 'ok', HEALTHY)


def test_a_stopped_scheduler_is_degraded_not_unhealthy():
    """Renewals stop firing, which monitoring must see — but the instance
    still serves, and failing liveness on it would take a working install out
    of rotation."""
    assert check_scheduler(_ctx(scheduler=MagicMock(running=False))) == (
        'scheduler', 'not_running', DEGRADED)


def test_a_missing_scheduler_reads_the_same_as_a_stopped_one():
    assert check_scheduler(_ctx()).severity == DEGRADED


def test_a_running_scheduler_is_healthy():
    assert check_scheduler(_ctx(scheduler=MagicMock(running=True))) == (
        'scheduler', 'running', HEALTHY)


def test_a_storage_backend_that_fell_back_to_local_is_degraded():
    """The check that motivated all of this. The operator believes
    certificates are in Azure/Vault/S3; they are on local disk. Before it was
    reported, only a log line said so."""
    storage = MagicMock()
    storage.get_fallback_backend.return_value = 'azure_keyvault'

    name, state, severity = check_storage(_ctx(storage=storage))

    assert name == 'storage'
    assert severity == DEGRADED
    assert 'azure_keyvault' in state, (
        'the state does not name the backend that was supposed to be in use, '
        'so it says something is wrong without saying what')


def test_a_storage_backend_that_did_not_fall_back_is_healthy():
    storage = MagicMock()
    storage.get_fallback_backend.return_value = None

    assert check_storage(_ctx(storage=storage)) == ('storage', 'ok', HEALTHY)


def test_a_backend_that_raises_when_asked_is_not_read_as_a_fallback():
    """CONTROL: an exception here must not be reported as "fell back to
    local". It means the question could not be answered, and inventing a
    degraded status from it would page someone for nothing."""
    storage = MagicMock()
    storage.get_fallback_backend.side_effect = RuntimeError('backend confused')

    assert check_storage(_ctx(storage=storage)) == ('storage', 'ok', HEALTHY)


@pytest.mark.parametrize('storage', [None, object()])
def test_an_instance_with_no_remote_backend_reports_no_storage_check(storage):
    """Absent, not 'ok'. Most installs have no remote backend at all, and a
    green tick for a subsystem they do not have means nothing."""
    result = check_storage(_ctx(storage=storage))
    assert result.name is None


# --- the aggregate -------------------------------------------------------

def test_the_worst_severity_wins():
    """Unhealthy beats degraded. This used to be four separate
    `if overall == 'healthy'` guards — correct, and one edit from not being."""
    context = _ctx(scheduler=MagicMock(running=False))
    context.settings.load_settings.side_effect = OSError('disk gone')

    checks, overall = run_health_checks(context)

    assert overall == 'unhealthy'
    assert checks == {'settings': 'error', 'scheduler': 'not_running'}


def test_one_degraded_check_degrades_the_whole():
    context = _ctx(scheduler=MagicMock(running=False))

    checks, overall = run_health_checks(context)

    assert overall == 'degraded'
    assert checks['settings'] == 'ok'


def test_everything_working_is_healthy():
    storage = MagicMock()
    storage.get_fallback_backend.return_value = None
    context = _ctx(scheduler=MagicMock(running=True), storage=storage)

    checks, overall = run_health_checks(context)

    assert overall == 'healthy'
    assert checks == {'settings': 'ok', 'scheduler': 'running',
                      'storage': 'ok'}


def test_a_check_reporting_nothing_leaves_no_key_behind():
    context = _ctx(scheduler=MagicMock(running=True))

    checks, _ = run_health_checks(context)

    assert 'storage' not in checks


# --- the diagnostics loop ------------------------------------------------

def test_a_collector_that_raises_does_not_take_the_snapshot_down():
    """The property the twelve hand-written try/except blocks each
    implemented separately, now implemented once. This is what somebody
    attaches to a bug report: losing all of it because one subsystem is
    broken is exactly the case it is most needed in."""
    import modules.api.resources_health as health

    def _explodes(ctx):
        raise RuntimeError('this collector was written on a Friday')

    _explodes.__name__ = 'collect_something_new'
    original = health.DIAGNOSTIC_COLLECTORS
    health.DIAGNOSTIC_COLLECTORS = (collect_scheduler, _explodes)
    try:
        payload = build_diagnostics_snapshot(
            _ctx(scheduler=MagicMock(running=True)))
    finally:
        health.DIAGNOSTIC_COLLECTORS = original

    assert payload['scheduler_running'] is True, (
        'the collector that worked was lost along with the one that failed')
    assert payload['errors'] == {'collect_something_new': 'collector_failed'}


def test_a_snapshot_with_nothing_wrong_carries_no_errors_key():
    """CONTROL: an always-present empty `errors` would train whoever reads the
    snapshot to ignore it."""
    import modules.api.resources_health as health

    original = health.DIAGNOSTIC_COLLECTORS
    health.DIAGNOSTIC_COLLECTORS = (collect_scheduler,)
    try:
        payload = build_diagnostics_snapshot(
            _ctx(scheduler=MagicMock(running=True)))
    finally:
        health.DIAGNOSTIC_COLLECTORS = original

    assert 'errors' not in payload


def test_the_audit_collector_drops_every_identifier():
    """Unchanged behaviour, asserted here because it is now assertable without
    an app: what survives is operational tempo, not who did what to which
    domain from which IP."""
    context = _ctx()
    context.audit.get_recent_entries.return_value = [{
        'timestamp': '2026-09-08T10:00:00Z', 'operation': 'create',
        'resource_type': 'certificate', 'status': 'success',
        'resource_id': 'secret.example.com', 'user': 'admin@example.com',
        'ip_address': '198.51.100.42',
        'details': {'private_key_pem': 'should-never-leak'},
    }]

    fields, errors = collect_recent_audit(context)

    assert errors == {}
    assert fields['recent_audit'] == [{
        'timestamp': '2026-09-08T10:00:00Z', 'operation': 'create',
        'resource_type': 'certificate', 'status': 'success'}]


def test_the_audit_collector_caps_at_five_entries():
    context = _ctx()
    context.audit.get_recent_entries.return_value = [
        {'operation': f'op-{index}'} for index in range(20)]

    fields, _ = collect_recent_audit(context)

    assert len(fields['recent_audit']) == 5


def test_no_unit_in_the_module_is_complex_any_more():
    """The finding this closes measured the whole closure at 64. Splitting it
    is only worth anything if it stays split, so the number is checked rather
    than remembered."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, '-m', 'flake8', 'modules/api/resources_health.py',
         '--select=C901', '--max-complexity=12'],
        capture_output=True, text=True)

    assert result.stdout == '', (
        'a unit in the health module is complex again:\n' + result.stdout)
