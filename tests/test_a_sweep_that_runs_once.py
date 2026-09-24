"""`POST /api/inventory/scan` started a second sweep on top of the first.

The scheduler had this covered: each of its four jobs takes a cross-PROCESS
file lock (`factory._renewal_process_lock`, one lock file per job) before it
calls the manager. The Scan endpoint calls the same managers directly and went
past all of it, so two clicks — or one click landing on a scheduled run — ran
two sweeps side by side in the same worker.

What that costs, per leg:

* **discovery** probes every endpoint twice and has two writers on the
  inventory;
* **the CT poll** paces itself with `min_request_interval`, which paces ONE
  caller: two polls ask crt.sh twice as fast as either believes it is asking;
* **the registration check** does the same to the registries, which answer a
  burst with a temporary ban;
* **the name checks** ask the blocklists twice, and a refused resolver is the
  exact failure that module is written to avoid *reporting*.

The guard is in the sweep, not in the endpoint, because the endpoint is not
the only caller. A guard on the route would have stopped two clicks and let a
click land on a scheduled run — while looking like it had stopped both.
"""
import os
import secrets
import threading
import time
from unittest.mock import MagicMock

import pytest

from modules.core.utils import ALREADY_RUNNING, exclusive_run

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# The regression, with two real threads
# --------------------------------------------------------------------------- #

def _discovery_manager(probe):
    from modules.core.cert_discovery import CertDiscoveryManager

    settings = MagicMock()
    settings.load_settings.return_value = {
        'monitored_endpoints': {'enabled': True, 'include_managed': False,
                                'endpoints': ['a.example.test'],
                                'check_revocation': False},
        'domains': [],
    }
    inventory = MagicMock()
    inventory.count.return_value = 0
    return CertDiscoveryManager(settings, inventory, probe=probe)


def test_a_second_sweep_does_not_start_while_one_is_running():
    """THE regression. The probe blocks, a second caller arrives, and the
    question is whether the endpoint gets probed twice."""
    in_probe = threading.Event()
    release = threading.Event()
    probed = []

    def blocking_probe(host, **kwargs):
        probed.append(host)
        in_probe.set()
        release.wait(5)
        return {'status': 'unreachable', 'error': 'stub', 'revocation': None}

    manager = _discovery_manager(blocking_probe)
    first = {}
    runner = threading.Thread(target=lambda: first.update(manager.run_discovery()))
    runner.start()
    try:
        assert in_probe.wait(5), 'the first sweep never reached the probe'

        second = manager.run_discovery()

        assert second == {'skipped': True, 'reason': ALREADY_RUNNING, 'results': []}
        assert probed == ['a.example.test'], (
            f'the endpoint was probed {len(probed)} times by two overlapping '
            f'sweeps')
    finally:
        release.set()
        runner.join(5)

    assert first['skipped'] is False, 'the first sweep did not complete'


def test_the_next_sweep_runs_normally():
    """CONTROL, and the one that matters: a lock that is taken and never
    given back would satisfy the test above and stop discovery for good."""
    probed = []
    manager = _discovery_manager(
        lambda host, **kwargs: (probed.append(host),
                                {'status': 'unreachable', 'error': 'stub',
                                 'revocation': None})[1])

    first = manager.run_discovery()
    second = manager.run_discovery()

    assert first['skipped'] is False
    assert second['skipped'] is False
    assert probed == ['a.example.test', 'a.example.test']


def test_a_sweep_that_raises_still_gives_the_lock_back():
    """The sweep is meant never to raise, and `never` is a claim about today's
    code. A lock held by a dead run is an outage that survives restarts of
    nothing — only of the process."""
    def explode(host, **kwargs):
        raise RuntimeError('the inventory went away')

    manager = _discovery_manager(explode)

    # `discover_endpoints` isolates a crashing probe per endpoint, so this
    # comes back as a result rather than an exception — which is why the
    # lock is also exercised directly below, where something really does
    # raise through it.
    manager.run_discovery()

    assert manager._sweep_lock.acquire(blocking=False), (
        'the lock was not released')
    manager._sweep_lock.release()


def test_the_ct_poll_does_not_overlap_either():
    """crt.sh is a shared service, and `min_request_interval` paces one
    caller. Two polls halve the interval each one thinks it is honouring."""
    from modules.core.ct_monitor import CTMonitorManager

    settings = MagicMock()
    settings.load_settings.return_value = {
        'ct_monitoring': {'enabled': True, 'domains': ['a.example.test'],
                          'include_managed': False, 'only_valid': False,
                          'max_new_per_run': 1},
        'domains': [],
    }
    in_search = threading.Event()
    release = threading.Event()
    searched = []

    client = MagicMock()

    def search(domain):
        searched.append(domain)
        in_search.set()
        release.wait(5)
        return []

    client.search.side_effect = search
    manager = CTMonitorManager(settings, MagicMock(), client=client)

    runner = threading.Thread(target=manager.run_poll)
    runner.start()
    try:
        assert in_search.wait(5)
        second = manager.run_poll()

        assert second == {'skipped': True, 'reason': ALREADY_RUNNING}
        assert searched == ['a.example.test']
    finally:
        release.set()
        runner.join(5)


# --------------------------------------------------------------------------- #
# Every leg of the scan, not just the two the endpoint names first
# --------------------------------------------------------------------------- #

def _all_four(tmp_path):
    """The four managers the Scan endpoint drives, each with its lock.

    Built rather than described, so a leg that loses its guard fails here
    instead of being covered by a list that still names it.
    """
    from modules.core.cert_discovery import CertDiscoveryManager
    from modules.core.ct_monitor import CTMonitorManager
    from modules.core.domain_health import DomainHealthManager
    from modules.core.domain_registration import DomainRegistrationManager

    settings = MagicMock()
    settings.load_settings.return_value = {'domains': []}
    inventory = MagicMock()
    inventory.inventory_dir = str(tmp_path)

    return [
        ('discovery',
         CertDiscoveryManager(settings, inventory, probe=MagicMock()),
         '_sweep_lock', 'run_discovery'),
        ('ct_monitoring',
         CTMonitorManager(settings, inventory, client=MagicMock()),
         '_poll_lock', 'run_poll'),
        ('domain_registration',
         DomainRegistrationManager(settings, inventory, str(tmp_path),
                                   client=MagicMock()),
         '_check_lock', 'run_check'),
        ('domain_health',
         DomainHealthManager(settings, inventory, str(tmp_path)),
         '_check_lock', 'run_check'),
    ]


def test_every_leg_of_a_scan_declines_rather_than_overlaps(tmp_path):
    """Executed, not asserted from the source: each lock is held and each
    entry point is called for real."""
    for name, manager, lock_attr, entry in _all_four(tmp_path):
        lock = getattr(manager, lock_attr)
        assert lock.acquire(blocking=False), f'{name}: the lock started held'
        try:
            answer = getattr(manager, entry)()
        finally:
            lock.release()

        assert answer['skipped'] is True, name
        assert answer['reason'] == ALREADY_RUNNING, name


def test_a_free_leg_still_answers_for_itself(tmp_path):
    """CONTROL on the same four: with nothing held, each one runs and reports
    its own reason — `disabled` here, because none of them is switched on in
    a default configuration."""
    for name, manager, _lock_attr, entry in _all_four(tmp_path):
        answer = getattr(manager, entry)()

        assert answer['skipped'] is True, name
        assert answer['reason'] == 'disabled', name


# --------------------------------------------------------------------------- #
# What the helper itself guarantees
# --------------------------------------------------------------------------- #

def test_the_helper_declines_when_the_lock_is_held():
    lock = threading.Lock()
    lock.acquire()
    try:
        answer = exclusive_run(lock, lambda: {'ran': True}, label='probe',
                               extra={'results': []})
    finally:
        lock.release()

    assert answer == {'skipped': True, 'reason': ALREADY_RUNNING, 'results': []}


def test_the_helper_gives_the_lock_back_when_the_work_raises():
    """Directly, because the four sweeps each isolate their own failures and
    none of them can reach this branch on purpose."""
    lock = threading.Lock()

    with pytest.raises(ValueError):
        exclusive_run(lock, lambda: (_ for _ in ()).throw(ValueError('boom')),
                      label='probe')

    assert lock.acquire(blocking=False)
    lock.release()


def test_the_helper_does_not_wait():
    """Non-blocking is the whole point: a scan request that queued behind a
    running sweep would hold a worker thread for as long as the sweep takes,
    and answer with a summary that belongs to someone else's run."""
    lock = threading.Lock()
    lock.acquire()
    try:
        started = time.monotonic()
        exclusive_run(lock, lambda: None, label='probe')
        assert time.monotonic() - started < 0.5
    finally:
        lock.release()


# --------------------------------------------------------------------------- #
# What the endpoint answers
# --------------------------------------------------------------------------- #

@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('scan-409')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.core.factory import create_app
        app, container = create_app()
        yield app, container, token


def _scan(instance):
    app, _container, token = instance
    return app.test_client().post(
        '/api/inventory/scan',
        headers={'Authorization': f'Bearer {token}',
                 'Origin': 'http://localhost'})


def test_a_scan_that_did_not_happen_is_not_a_success(instance):
    """THE regression at the endpoint. 200 for a scan that was declined is
    the same defect as a backup route that says "Backup created" with no
    file: an answer about something that did not happen."""
    _app, container, _token = instance
    lock = container.managers['cert_discovery']._sweep_lock
    assert lock.acquire(blocking=False)
    try:
        response = _scan(instance)
    finally:
        lock.release()

    assert response.status_code == 409, response.get_data(as_text=True)
    body = response.get_json()
    assert body['code'] == 'SCAN_IN_PROGRESS'
    assert 'discovery' in body['error']
    assert body['discovery']['reason'] == ALREADY_RUNNING


def test_the_legs_that_did_run_are_still_reported(instance):
    """A 409 that threw the other summaries away would make the operator
    guess what happened. Discovery is the busy one; the CT poll is not, and
    its own answer is still in the body."""
    _app, container, _token = instance
    lock = container.managers['cert_discovery']._sweep_lock
    assert lock.acquire(blocking=False)
    try:
        body = _scan(instance).get_json()
    finally:
        lock.release()

    assert body['ct_monitoring']['reason'] == 'disabled'
    assert body['ct_monitoring']['reason'] != ALREADY_RUNNING


def test_a_scan_with_nothing_running_is_still_a_200(instance):
    """CONTROL. An endpoint that answered 409 whenever anything was skipped
    would pass the two tests above and break the button: `disabled` and
    `no_endpoints` are skips too, and they are the default state."""
    response = _scan(instance)

    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert body['discovery']['reason'] == 'disabled'
    assert 'code' not in body
