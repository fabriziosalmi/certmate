"""Deploy Now and the deploy that was waiting for the window (#1058).

A hook with a maintenance window is not run when the certificate renews while the window is closed: it is
queued, and `drain_pending` runs it when the window opens. Deploy Now runs the same hook straight away, by
design (#109, #632). What it did not do was take the queued entry off the queue, so the window opened and the
hook ran a second time against the certificate it had already deployed. The reporter's hook only replaces a
file; a load balancer rebind or a service restart does not forgive a second, unannounced run hours later, and
a TARGET that carries the private key would deliver it twice.

What is held here:

* a successful Deploy Now consumes the matching queue entry, for hooks and for targets, and a second run does
  not happen when the window opens;
* a FAILED Deploy Now leaves it: the window deploy is then the retry;
* only the entries it handled: another domain, another hook, a hook it did not run;
* an entry queued AGAIN while Deploy Now was running stays, because a certificate newer than the one that run
  read is waiting behind it. That is a race, so it is tested as one: once by constructing the interleaving,
  and once with real threads and an invariant that must hold under any interleaving;
* the same rule in `drain_pending`, which said "only drop what this drain handled" and did it by key, so an
  entry re-queued while it ran was dropped with the one it had just run.
"""
import datetime
import json
import random
import threading
import time
from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager

pytestmark = [pytest.mark.unit]

UTC = datetime.timezone.utc
NIGHT = {'start': '02:00', 'end': '04:00'}
DOMAIN = 'example.com'


def _at(day, hour, minute=0, second=0):
    return datetime.datetime(2026, 9, day, hour, minute, second, tzinfo=UTC)


@pytest.fixture
def manager(tmp_path):
    manager = DeployManager(
        settings_manager=MagicMock(), shell_executor=MagicMock(),
        audit_logger=MagicMock(), event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs', data_dir=str(tmp_path / 'data'))
    manager.ran = []
    manager.outcome = {}                 # hook id -> success, default True

    def run_hook(hook, domain, event, dry_run=False):
        manager.ran.append((hook['id'], domain, event))
        return {'success': manager.outcome.get(hook['id'], True), 'hook': hook['id'], 'domain': domain}
    manager._run_hook = run_hook
    return manager


def _hook(hook_id='h1', window=NIGHT, **extra):
    hook = {'id': hook_id, 'name': hook_id, 'command': 'echo hi', 'enabled': True,
            'on_events': ['created', 'renewed'], **extra}
    if window is not None:
        hook['window'] = window
    return hook


def _target(name='k8s', window=NIGHT):
    target = {'type': 'webhook', 'id': name, 'name': name, 'enabled': True, 'domains': [DOMAIN],
              'on_events': ['created', 'renewed'], 'config': {'url': 'https://r.example/x',
                                                              'payload_template': '{"d": "{{domain}}"}'}}
    if window is not None:
        target['window'] = window
    return target


def _configure(manager, hooks=(), targets=()):
    config = {'enabled': True, 'global_hooks': list(hooks), 'domain_hooks': {}, 'targets': list(targets)}
    manager.get_config = lambda: config
    return config


def _closed(monkeypatch, day=8, hour=13):
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(day, hour))


def _queue(manager):
    return json.loads(manager._pending_path.read_text()) if manager._pending_path.exists() else {}


def _targets_succeed(manager, monkeypatch, names=('k8s',), success=True):
    """Stand in for the delivery itself; what is under test is the queue, not the receiver."""
    calls = []

    def execute(domain, event, config=None, targets=None):
        calls.append((domain, event))
        return [{'success': success, 'target': n, 'type': 'webhook', 'domain': domain} for n in names]
    monkeypatch.setattr(manager, '_execute_targets', execute)
    return calls


# --------------------------------------------------------------------------
# The reproduction, and its two halves
# --------------------------------------------------------------------------

def test_deploy_now_after_a_deploy_was_held_means_it_does_not_run_again_when_the_window_opens(manager, monkeypatch):
    """The issue, step for step."""
    _configure(manager, [_hook()])
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')                    # window closed: held
    assert manager.ran == [] and 'hook:h1:example.com' in _queue(manager)

    result = manager.run_manual_deploy(DOMAIN)                   # the operator presses Deploy Now
    assert result['ok'] is True and manager.ran == [('h1', DOMAIN, 'manual')]
    assert _queue(manager) == {}, 'the queued deploy is still there: it will run again'

    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(9, 3))
    manager.drain_pending()                                      # the window opens
    assert manager.ran == [('h1', DOMAIN, 'manual')], f'the hook ran again: {manager.ran}'


def test_the_same_for_a_target(manager, monkeypatch):
    """A target that sends the key must not send it twice."""
    _configure(manager, targets=[_target()])
    _closed(monkeypatch)
    calls = _targets_succeed(manager, monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')
    assert 'target:k8s:example.com' in _queue(manager)

    manager.run_manual_deploy(DOMAIN)
    assert _queue(manager) == {}


def test_a_failed_deploy_now_leaves_the_queued_deploy_as_the_retry(manager, monkeypatch):
    _configure(manager, [_hook()])
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')
    manager.outcome['h1'] = False
    assert manager.run_manual_deploy(DOMAIN)['ok'] is False
    assert 'hook:h1:example.com' in _queue(manager), 'a failed manual run dropped the retry'

    manager.outcome['h1'] = True
    monkeypatch.setattr('modules.core.deployer._utc_now', lambda: _at(9, 3))
    manager.drain_pending()
    assert manager.ran[-1] == ('h1', DOMAIN, 'renewed')


def test_a_failed_target_leaves_its_queued_deploy(manager, monkeypatch):
    _configure(manager, targets=[_target()])
    _closed(monkeypatch)
    _targets_succeed(manager, monkeypatch, success=False)
    manager._execute_hooks(DOMAIN, 'renewed')
    manager.run_manual_deploy(DOMAIN)
    assert 'target:k8s:example.com' in _queue(manager)


def test_only_the_entries_it_handled_are_consumed(manager, monkeypatch):
    """Another domain's entry, a hook Deploy Now did not run, and a hook that failed."""
    domain_hook = _hook('only-here')
    config = _configure(manager, [_hook('both'), _hook('failing')])
    config['domain_hooks'] = {DOMAIN: [domain_hook]}
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')
    manager._execute_hooks('other.example.net', 'renewed')
    assert len(_queue(manager)) == 5

    manager.outcome['failing'] = False
    manager.run_manual_deploy(DOMAIN)

    assert sorted(_queue(manager)) == ['hook:both:other.example.net', 'hook:failing:example.com',
                                       'hook:failing:other.example.net'], (
        'Deploy Now consumed an entry of another domain, or kept one it had handled successfully')


def test_a_disabled_hook_is_not_run_and_its_queued_deploy_is_not_consumed(manager, monkeypatch):
    config = _configure(manager, [_hook('h1')])
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')
    config['global_hooks'][0]['enabled'] = False
    manager.run_manual_deploy(DOMAIN)                            # nothing enabled: ok False, nothing run
    assert manager.ran == [] and 'hook:h1:example.com' in _queue(manager)


# --------------------------------------------------------------------------
# A newer certificate queued while Deploy Now was running
# --------------------------------------------------------------------------

def test_an_entry_queued_again_while_deploy_now_ran_is_not_consumed(manager, monkeypatch):
    """The certificate renewed AGAIN while the manual run was in progress: a newer one is waiting behind it."""
    _configure(manager, [_hook()])
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')
    first_stamp = _queue(manager)['hook:h1:example.com']['last_event_at']

    real_run = manager._run_hook

    def run_while_a_renewal_arrives(hook, domain, event, dry_run=False):
        result = real_run(hook, domain, event)
        # a renewal lands, the window is still closed: the same key is queued again, newer
        manager._defer_if_closed('hook', hook, domain, 'renewed', _at(8, 13, 5))
        return result
    manager._run_hook = run_while_a_renewal_arrives

    manager.run_manual_deploy(DOMAIN)
    entry = _queue(manager).get('hook:h1:example.com')
    assert entry is not None, 'the deploy of the NEWER certificate was consumed by the run that predates it'
    assert entry['last_event_at'] != first_stamp


def test_deploy_now_and_renewals_racing_never_lose_a_newer_entry_or_keep_a_handled_one():
    """Real threads, and an invariant that holds under any interleaving.

    A re-queues the key `n` times with increasing stamps while B runs Deploy Now. Two moments of B are observed
    from outside, without naming anything inside it: the first time B reads the queue, and the moment its hook
    starts (which is when the certificate is read from disk). Then:

    * a re-queue AFTER the hook started is a certificate B cannot have read: its entry must survive, with the
      last stamp A wrote. Losing it is a deploy that never happens;
    * a re-queue between B's first read and its hook starting may be kept or consumed (keeping it is the safe
      direction: a spare deploy later, never a lost one), but if it is kept it must be the last stamp;
    * if nothing was queued after B's first read, the entry B handled must be gone.
    """
    rng = random.Random(1058)
    for round_ in range(200):
        _check_one_round(rng, round_)


def _check_one_round(rng, round_):
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        manager = DeployManager(
            settings_manager=MagicMock(), shell_executor=MagicMock(), audit_logger=MagicMock(),
            event_bus=MagicMock(), cert_dir=Path(tmp) / 'certs', data_dir=str(Path(tmp) / 'data'))
        hook = _hook()
        config = {'enabled': True, 'global_hooks': [hook], 'domain_hooks': {}, 'targets': []}
        manager.get_config = lambda: config

        guard = threading.Lock()
        written = []                  # the stamp of every re-queue, in the order it was made
        seen = {}                     # 'first_read' / 'hook_start' -> how many re-queues had happened by then

        real_read = manager._read_pending

        def read_pending():
            if threading.current_thread().name == 'deploy-now':
                with guard:
                    seen.setdefault('first_read', len(written))
            return real_read()
        manager._read_pending = read_pending

        def run_hook(h, d, e, dry_run=False):
            with guard:
                seen.setdefault('hook_start', len(written))
            time.sleep(rng.random() * 0.002)
            return {'success': True, 'hook': h['id'], 'domain': d}
        manager._run_hook = run_hook

        manager._defer_if_closed('hook', hook, DOMAIN, 'renewed', _at(8, 13, 0, 0))     # the entry that is waiting
        n = rng.randint(1, 6)
        start = threading.Barrier(2)

        def renewals():
            start.wait()
            for i in range(1, n + 1):
                time.sleep(rng.random() * 0.002)
                now = _at(8, 13, 0, i)
                with guard:
                    written.append(now.isoformat())
                manager._defer_if_closed('hook', hook, DOMAIN, 'renewed', now)

        def deploy_now():
            start.wait()
            manager.run_manual_deploy(DOMAIN)

        threads = [threading.Thread(target=renewals, name='renewals'),
                   threading.Thread(target=deploy_now, name='deploy-now')]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert 'first_read' in seen, 'Deploy Now never looked at the queue, so it cannot have consumed anything'
        queue = json.loads(manager._pending_path.read_text()) if manager._pending_path.exists() else {}
        entry = queue.get('hook:h1:example.com')
        after_hook_start = len(written) > seen['hook_start']
        after_first_read = len(written) > seen['first_read']
        if after_hook_start:
            assert entry is not None and entry['last_event_at'] == written[-1], (
                f'round {round_}: {len(written) - seen["hook_start"]} certificate(s) were queued after the hook '
                f'started and the queue holds {entry}: a newer deploy was lost')
        elif after_first_read:
            assert entry is None or entry['last_event_at'] == written[-1], f'round {round_}: {entry}'
        else:
            assert entry is None, (
                f'round {round_}: nothing was queued after Deploy Now began and the entry it handled is still '
                f'there: {entry}')


# --------------------------------------------------------------------------
# The same rule in drain_pending
# --------------------------------------------------------------------------

def test_an_entry_queued_again_while_the_drain_ran_is_not_dropped_with_the_one_it_ran(manager, monkeypatch):
    """The window closes while the drain is running; a renewal lands and queues the same key again."""
    _configure(manager, [_hook()])
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')

    real_run = manager._run_hook

    def run_then_the_window_closes_and_a_renewal_lands(hook, domain, event, dry_run=False):
        result = real_run(hook, domain, event)
        manager._defer_if_closed('hook', hook, domain, 'renewed', _at(9, 4, 30))     # 04:30, closed
        return result
    manager._run_hook = run_then_the_window_closes_and_a_renewal_lands

    summary = manager.drain_pending(now=_at(9, 3))
    assert summary['ran'] == 1
    entry = _queue(manager).get('hook:h1:example.com')
    assert entry is not None, 'the drain dropped the entry of a certificate newer than the one it ran'
    assert entry['last_event_at'] == _at(9, 4, 30).isoformat()


def test_a_drain_that_ran_an_entry_nobody_touched_drops_it(manager, monkeypatch):
    """CONTROL: the stricter comparison must not keep what the drain handled."""
    _configure(manager, [_hook()])
    _closed(monkeypatch)
    manager._execute_hooks(DOMAIN, 'renewed')
    manager.drain_pending(now=_at(9, 3))
    assert _queue(manager) == {}
