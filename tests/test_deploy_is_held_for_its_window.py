"""A deploy with a maintenance window waits for it (#632).

`modules/core/deploy_window` decides *when* a window is open; this decides what
the deploy manager does about it. The two halves are separated because the
calendar questions are pure and the queue questions are not: this file is about
a deploy surviving a restart, two renewals collapsing into one deploy, and a
hook that was deleted while its deploy waited.

The property that matters more than any of them: a hook with no window runs
immediately, exactly as it always has. Every existing installation is in that
case, and a release that quietly started deferring their deploys would be an
outage of a different shape.
"""
import datetime
import json
import threading
from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager

pytestmark = [pytest.mark.unit]

UTC = datetime.timezone.utc
NIGHT = {'start': '02:00', 'end': '04:00'}


def _at(day, hour, minute=0):
    return datetime.datetime(2026, 9, day, hour, minute, tzinfo=UTC)


@pytest.fixture
def manager(tmp_path):
    settings = MagicMock()
    manager = DeployManager(
        settings_manager=settings, shell_executor=MagicMock(),
        audit_logger=MagicMock(), event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs', data_dir=str(tmp_path / 'data'))
    manager.ran = []
    manager._run_hook = lambda hook, domain, event, dry_run=False: (
        manager.ran.append((hook['id'], domain, event))
        or {'success': True, 'hook': hook['id'], 'domain': domain})
    return manager


def _configure(manager, hooks, enabled=True, targets=None):
    config = {'enabled': enabled, 'global_hooks': hooks, 'domain_hooks': {},
              'targets': targets or []}
    manager.get_config = lambda: config
    return config


def _hook(hook_id='h1', window=None, **extra):
    hook = {'id': hook_id, 'name': hook_id, 'command': 'echo hi',
            'enabled': True, 'on_events': ['created', 'renewed'], **extra}
    if window is not None:
        hook['window'] = window
    return hook


# ---------------------------------------------------------------------------
# The default is unchanged
# ---------------------------------------------------------------------------

def test_a_hook_without_a_window_runs_immediately(manager):
    _configure(manager, [_hook()])
    manager._execute_hooks('example.com', 'renewed')
    assert manager.ran == [('h1', 'example.com', 'renewed')]
    assert not manager._pending_path.exists(), (
        'an un-windowed hook wrote to the queue'
    )


def test_a_hook_whose_window_is_open_runs_immediately(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 3))
    manager._execute_hooks('example.com', 'renewed')
    assert manager.ran == [('h1', 'example.com', 'renewed')]


# ---------------------------------------------------------------------------
# Held, then run
# ---------------------------------------------------------------------------

def test_a_closed_window_queues_instead_of_running(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))

    manager._execute_hooks('example.com', 'renewed')

    assert manager.ran == [], 'the deploy ran outside its window'
    queued = json.loads(manager._pending_path.read_text())
    assert list(queued) == ['hook:h1:example.com']
    assert queued['hook:h1:example.com']['event'] == 'renewed'


def test_the_drain_runs_it_once_the_window_opens(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    assert manager.drain_pending(now=_at(8, 23))['ran'] == 0, 'still shut'
    assert manager.ran == []

    summary = manager.drain_pending(now=_at(9, 2, 30))
    assert summary['ran'] == 1
    assert manager.ran == [('h1', 'example.com', 'renewed')]
    assert not manager._pending_path.exists(), 'the entry was not cleared'


def test_the_queue_survives_a_restart(manager, monkeypatch, tmp_path):
    """The whole reason it is on disk. The window is hours away, and a
    container restart in between is ordinary."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    reborn = DeployManager(
        settings_manager=MagicMock(), shell_executor=MagicMock(),
        audit_logger=MagicMock(), event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs', data_dir=str(tmp_path / 'data'))
    reborn.ran = []
    reborn._run_hook = lambda hook, domain, event, dry_run=False: (
        reborn.ran.append((hook['id'], domain, event))
        or {'success': True, 'hook': hook['id'], 'domain': domain})
    _configure(reborn, [_hook(window=NIGHT)])

    assert reborn.drain_pending(now=_at(9, 2, 30))['ran'] == 1
    assert reborn.ran == [('h1', 'example.com', 'renewed')]


def test_two_renewals_before_the_window_produce_one_deploy(manager, monkeypatch):
    """The hook reads the certificate from disk when it runs, so one deferred
    run always publishes the newest one. Queueing twice would restart the
    database twice for no gain."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 19))
    manager._execute_hooks('example.com', 'renewed')

    assert len(json.loads(manager._pending_path.read_text())) == 1
    assert manager.drain_pending(now=_at(9, 2, 30))['ran'] == 1


def test_the_first_queue_time_is_kept_across_repeats(manager, monkeypatch):
    """`queued_at` is what the stale warning measures. Refreshing it on every
    renewal would mean a deploy stuck for a month never looks stuck."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')
    first = json.loads(manager._pending_path.read_text())[
        'hook:h1:example.com']['queued_at']

    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(9, 13))
    manager._execute_hooks('example.com', 'renewed')
    entry = json.loads(manager._pending_path.read_text())['hook:h1:example.com']

    assert entry['queued_at'] == first
    assert entry['last_event_at'] >= first


def test_each_domain_queues_separately(manager, monkeypatch):
    """A global hook applies to every domain, and two domains renewing on the
    same night are two deploys, not one."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('a.example.com', 'renewed')
    manager._execute_hooks('b.example.com', 'renewed')

    assert manager.drain_pending(now=_at(9, 2, 30))['ran'] == 2
    assert {d for _id, d, _e in manager.ran} == {'a.example.com', 'b.example.com'}


# ---------------------------------------------------------------------------
# What the drain refuses to run
# ---------------------------------------------------------------------------

def test_a_hook_deleted_while_its_deploy_waited_is_dropped(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    _configure(manager, [])  # the operator removed it
    summary = manager.drain_pending(now=_at(9, 2, 30))

    assert summary == {'ran': 0, 'held': 0, 'dropped': 1, 'results': []}
    assert manager.ran == []
    assert not manager._pending_path.exists()


def test_a_hook_disabled_while_its_deploy_waited_is_dropped(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    _configure(manager, [_hook(window=NIGHT, enabled=False)])
    assert manager.drain_pending(now=_at(9, 2, 30))['dropped'] == 1
    assert manager.ran == []


def test_turning_deploy_hooks_off_drops_the_queue(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    _configure(manager, [_hook(window=NIGHT)], enabled=False)
    assert manager.drain_pending(now=_at(9, 2, 30))['dropped'] == 1
    assert manager.ran == []


def test_removing_the_window_releases_the_deploy_at_the_next_drain(
        manager, monkeypatch):
    """An operator who decides the window was a mistake should not have to wait
    for it one last time."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    _configure(manager, [_hook()])
    assert manager.drain_pending(now=_at(8, 14))['ran'] == 1


def test_a_failing_hook_is_not_retried_every_minute(manager, monkeypatch):
    """Failure-isolated like every other deploy path. Re-queueing would retry
    at every drain for as long as the window is open."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    def _boom(hook, domain, event, dry_run=False):
        raise RuntimeError('hook blew up')
    manager._run_hook = _boom

    summary = manager.drain_pending(now=_at(9, 2, 30))
    assert summary['ran'] == 1
    assert summary['results'][0]['success'] is False
    assert not manager._pending_path.exists(), 'a failed deploy was re-queued'


# ---------------------------------------------------------------------------
# Robustness of the queue itself
# ---------------------------------------------------------------------------

def test_an_empty_queue_is_a_no_op(manager):
    _configure(manager, [_hook()])
    assert manager.drain_pending(now=_at(9, 3)) == {
        'ran': 0, 'held': 0, 'dropped': 0, 'results': []}


def test_a_corrupt_queue_does_not_raise(manager, monkeypatch, caplog):
    """It is read by a scheduler job. Raising there would stop the job, and a
    stopped job means deploys silently stop happening."""
    manager._pending_path.parent.mkdir(parents=True, exist_ok=True)
    manager._pending_path.write_text('{ not json')
    _configure(manager, [_hook(window=NIGHT)])

    with caplog.at_level('ERROR'):
        assert manager.drain_pending(now=_at(9, 3))['ran'] == 0
    assert 'unreadable' in caplog.text, 'a lost queue was silent'


def test_an_unusable_window_deploys_rather_than_holding_forever(
        manager, monkeypatch, caplog):
    """save_config refuses these, so reaching this means a hand-edited file.
    Deploying at the wrong hour is a disruption; never deploying is an expired
    certificate on the far end.
    """
    _configure(manager, [_hook(window={'start': '02:00', 'end': 'nonsense'})])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))

    with caplog.at_level('WARNING'):
        manager._execute_hooks('example.com', 'renewed')

    assert manager.ran == [('h1', 'example.com', 'renewed')]
    assert 'unusable maintenance window' in caplog.text


def test_a_deploy_stuck_for_a_week_is_reported(manager, monkeypatch, caplog):
    _configure(manager, [_hook(window={'start': '02:00', 'end': '04:00',
                                       'days': ['sun']})])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(1, 13))
    manager._execute_hooks('example.com', 'renewed')

    with caplog.at_level('WARNING'):
        manager.drain_pending(now=_at(1, 13) + datetime.timedelta(days=8))
    assert 'has been waiting since' in caplog.text


def test_an_event_arriving_during_a_drain_is_not_lost(manager, monkeypatch):
    """The drain rewrites the queue at the end. If it wrote back its own
    snapshot, a deploy queued while it was running would vanish."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('a.example.com', 'renewed')

    def _run_and_queue_another(hook, domain, event, dry_run=False):
        manager.ran.append((hook['id'], domain, event))
        with manager._pending_lock:
            queue = manager._read_pending()
            queue['hook:h1:b.example.com'] = {
                'kind': 'hook', 'id': 'h1', 'domain': 'b.example.com',
                'event': 'renewed', 'queued_at': '2026-09-08T13:00:00Z',
                'last_event_at': '2026-09-08T13:00:00Z'}
            manager._write_pending(queue)
        return {'success': True, 'hook': hook['id'], 'domain': domain}
    manager._run_hook = _run_and_queue_another

    manager.drain_pending(now=_at(9, 2, 30))

    remaining = json.loads(manager._pending_path.read_text())
    assert 'hook:h1:b.example.com' in remaining, (
        'a deploy queued during the drain was discarded'
    )


def test_the_queue_is_written_under_a_lock(manager):
    """Events are dispatched on daemon threads, so two certificates renewing at
    once write this file concurrently. Last-writer-wins on a read-modify-write
    would drop one of the deploys."""
    _configure(manager, [_hook(window=NIGHT)])
    import modules.core.deployer as mod
    original = mod._utc_now
    mod._utc_now = lambda: _at(8, 13)
    try:
        threads = [threading.Thread(target=manager._execute_hooks,
                                    args=(f'd{i}.example.com', 'renewed'))
                   for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
    finally:
        mod._utc_now = original

    assert len(json.loads(manager._pending_path.read_text())) == 12


# ---------------------------------------------------------------------------
# Manual deploy ignores windows
# ---------------------------------------------------------------------------

def test_deploy_now_ignores_the_window(manager, monkeypatch):
    """An operator pressing Deploy Now has chosen this moment. Holding it until
    02:00 would make the button do nothing visible."""
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))

    result = manager.run_manual_deploy('example.com')

    assert result['ok'] and result['succeeded'] == 1
    assert manager.ran == [('h1', 'example.com', 'manual')]
    assert not manager._pending_path.exists()


# ---------------------------------------------------------------------------
# What the operator can see
# ---------------------------------------------------------------------------

def test_pending_deploys_can_be_listed(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')

    rows = manager.get_pending(now=_at(8, 13))

    assert len(rows) == 1
    assert rows[0]['domain'] == 'example.com'
    assert rows[0]['window'] == '02:00-04:00 UTC (every day)'
    assert rows[0]['next_run'] == _at(9, 2).isoformat()
    assert rows[0]['orphaned'] is False


def test_a_listing_marks_an_orphaned_entry(manager, monkeypatch):
    _configure(manager, [_hook(window=NIGHT)])
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(8, 13))
    manager._execute_hooks('example.com', 'renewed')
    _configure(manager, [])

    assert manager.get_pending(now=_at(8, 13))[0]['orphaned'] is True


# ---------------------------------------------------------------------------
# Validation happens at save time
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('window,message', [
    ({'start': '02:00', 'end': '02:00'}, 'same time'),
    ({'start': 'midnight', 'end': '04:00'}, 'HH:MM'),
    ({'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Genova'},
     'unknown timezone'),
    ({'start': '02:00', 'end': '04:00', 'days': ['funday']}, 'unknown day'),
])
def test_an_unusable_window_is_refused_when_it_is_saved(manager, window, message):
    ok, error = manager._validate_deploy_config(
        {'global_hooks': [_hook(window=window)]})
    assert not ok
    assert message in error


def test_a_valid_window_is_stored_in_canonical_form(manager):
    hook = _hook(window={'start': '02:00', 'end': '04:00',
                         'days': ['Monday', 'FRI'], 'timezone': ' Europe/Rome '})
    ok, error = manager._validate_deploy_config({'global_hooks': [hook]})
    assert ok, error
    assert hook['window'] == {'start': '02:00', 'end': '04:00',
                              'days': ['mon', 'fri'], 'timezone': 'Europe/Rome'}


def test_an_absent_window_is_not_invented(manager):
    """CONTROL: normalisation must not add an empty window to every hook, which
    would make `entity.get('window')` truthy and defer everything."""
    hook = _hook()
    assert manager._validate_deploy_config({'global_hooks': [hook]})[0]
    assert 'window' not in hook


def test_a_target_window_is_validated_the_same_way(manager):
    ok, error = manager._validate_deploy_config({'targets': [{
        'name': 'k8s', 'type': 'kubernetes-secret',
        'config': {'secret_name': 's', 'in_cluster': True},
        'window': {'start': '02:00', 'end': '02:00'}}]})
    assert not ok
    assert 'same time' in error
