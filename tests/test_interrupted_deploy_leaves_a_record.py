"""A deploy killed part-way must be distinguishable from one that never began.

The deploy history entry, the audit record and the failure event were all
written *after* the command returned. So a hook interrupted by process
termination — SIGKILL, an OOM kill, the container stopped mid-deploy — left
none of them. The history showed nothing, and an operator reading it could not
tell "this hook never ran" from "this hook was half-way through publishing a
certificate when we died".

Those are not the same, and the second is the dangerous one: the target may
hold a partially written certificate, a reloaded service, a key without its
chain — and nothing anywhere says to go and look.

The fix is the shape a job runner uses. A `running` record is appended before
the command starts and superseded by the outcome afterwards. The file is
append-only JSONL, so "superseded" means a second record with the same
`run_id`, folded by the reader.

That leaves one thing to get right, and it is the whole value of the change: a
`running` record means either *this run is going on right now* or *the process
running it died*. Only the process that started it can tell — so the deployer
keeps the ids it has in flight, and that set does not survive a restart. After
a restart every leftover `running` record is reported as `interrupted`, which
is exactly what it is.
"""
import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.deployer import DeployManager

pytestmark = [pytest.mark.unit]

HOOK = {'id': 'h1', 'name': 'reload-nginx', 'command': 'echo deployed',
        'enabled': True, 'timeout': 30, 'on_events': ['renewed']}
TARGET = {'name': 'k8s-prod', 'type': 'kubernetes-secret', 'enabled': True,
          'on_events': ['renewed'], 'config': {'secret_name': 'tls'}}


@pytest.fixture
def data_dir():
    return tempfile.mkdtemp()


@pytest.fixture
def manager(data_dir):
    settings = MagicMock()
    settings.get_settings.return_value = {}
    return DeployManager(settings, MagicMock(), MagicMock(), MagicMock(),
                         cert_dir=Path(tempfile.mkdtemp()), data_dir=data_dir)


def _raw_records(manager):
    """Every line in the JSONL, unfolded — what is actually on disk."""
    path = manager._history_path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _completed(returncode=0, stdout='ok', stderr=''):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


# --- the record exists before the command does anything -----------------

def test_the_start_is_recorded_before_the_command_runs(manager):
    """The property everything else rests on: at the moment the subprocess is
    executing, the history already knows about it."""
    seen = []

    def run(cmd, **kwargs):
        seen.append(_raw_records(manager))
        return _completed()

    manager.shell_executor.run = run
    manager._run_hook(HOOK, 'example.com', 'renewed')

    assert seen, 'the command never ran'
    assert len(seen[0]) == 1, (
        'nothing was written to the history before the command started, so a '
        'kill here would leave no trace at all'
    )
    assert seen[0][0]['status'] == 'running'
    assert seen[0][0]['domain'] == 'example.com'
    assert seen[0][0]['hook_name'] == 'reload-nginx'


def test_a_completed_run_supersedes_its_own_start_record(manager):
    manager.shell_executor.run = lambda cmd, **kw: _completed()
    manager._run_hook(HOOK, 'example.com', 'renewed')

    raw = _raw_records(manager)
    assert len(raw) == 2, 'expected a start record and an outcome record'
    assert [r['status'] for r in raw] == ['running', 'success']
    assert raw[0]['run_id'] == raw[1]['run_id']

    history = manager.get_history()
    assert len(history) == 1, 'the pair was not folded into one entry'
    assert history[0]['status'] == 'success'


def test_a_failed_run_is_recorded_as_failure_not_interrupted(manager):
    """CONTROL: a hook that ran and exited non-zero is a different fact from
    one that was killed, and conflating them would make the new state
    meaningless."""
    manager.shell_executor.run = lambda cmd, **kw: _completed(
        returncode=3, stdout='', stderr='nginx: configuration file test failed')
    manager._run_hook(HOOK, 'example.com', 'renewed')

    history = manager.get_history()
    assert len(history) == 1
    assert history[0]['status'] == 'failure'
    assert history[0]['success'] is False
    assert 'exit code 3' in history[0]['error']


# --- what a kill actually leaves ----------------------------------------

def test_a_run_the_process_did_not_finish_reads_as_interrupted(manager):
    """Simulates the kill by doing what a kill does: the start record is on
    disk, the outcome record never arrives, and the process that owned the run
    is gone."""
    manager.shell_executor.run = lambda cmd, **kw: _completed()
    manager._run_hook(HOOK, 'example.com', 'renewed')

    # Strip the outcome record. This is the on-disk state after a SIGKILL
    # between the two writes.
    raw = _raw_records(manager)
    manager._history_path.write_text(json.dumps(raw[0]) + '\n')

    # A restart: a fresh manager over the same data directory, with nothing
    # in flight.
    restarted = DeployManager(MagicMock(), MagicMock(), MagicMock(),
                              MagicMock(),
                              cert_dir=manager.cert_dir,
                              data_dir=str(manager._history_path.parent))

    history = restarted.get_history()
    assert len(history) == 1
    assert history[0]['status'] == 'interrupted'
    assert history[0]['success'] is False
    assert 'Check the target' in history[0]['error'], (
        'the entry does not tell the operator what to do about it'
    )


def test_a_run_still_going_in_this_process_reads_as_running(manager):
    """CONTROL, and the reason the in-flight set exists. Reporting a live
    deploy as `interrupted` would cry wolf on every long hook."""
    observed = {}

    def run(cmd, **kwargs):
        observed['during'] = manager.get_history()
        return _completed()

    manager.shell_executor.run = run
    manager._run_hook(HOOK, 'example.com', 'renewed')

    assert observed['during'][0]['status'] == 'running', (
        'a hook that is executing right now was reported as interrupted'
    )


def test_the_in_flight_set_is_emptied_even_when_the_hook_raises(manager):
    """A leaked id would keep a dead run reporting as `running` forever."""
    manager.shell_executor.run = MagicMock(side_effect=OSError('fork failed'))
    manager._run_hook(HOOK, 'example.com', 'renewed')

    assert manager._in_flight == set()
    assert manager.get_history()[0]['status'] == 'failure'


def test_a_timeout_completes_the_record_rather_than_leaving_it_running(manager):
    """A hook that hit its own timeout was not interrupted — CertMate stopped
    it deliberately and knows the outcome."""
    import subprocess
    manager.shell_executor.run = MagicMock(
        side_effect=subprocess.TimeoutExpired('sh', 30))
    manager._run_hook(HOOK, 'example.com', 'renewed')

    history = manager.get_history()
    assert history[0]['status'] == 'failure'
    assert 'timeout' in history[0]['error']


# --- typed deploy targets have the same gap -----------------------------

def test_an_interrupted_target_batch_leaves_a_record(manager, monkeypatch):
    """`run_targets` publishes to every target and only then returns, so a
    kill part-way through was equally invisible."""
    domain = 'example.com'
    domain_dir = manager.cert_dir / domain
    domain_dir.mkdir(parents=True)
    (domain_dir / 'fullchain.pem').write_bytes(b'cert')
    (domain_dir / 'privkey.pem').write_bytes(b'key')

    seen = []
    monkeypatch.setattr('modules.core.deployer.run_targets',
                        lambda *a, **k: seen.append(_raw_records(manager)) or [])

    manager._execute_targets(domain, 'renewed',
                             targets=[TARGET])

    assert seen and len(seen[0]) == 1, (
        'nothing recorded before publishing to the targets began'
    )
    assert seen[0][0]['kind'] == 'target-batch'
    assert seen[0][0]['status'] == 'running'


def test_a_finished_target_batch_supersedes_its_start(manager, monkeypatch):
    domain = 'example.com'
    domain_dir = manager.cert_dir / domain
    domain_dir.mkdir(parents=True)
    (domain_dir / 'fullchain.pem').write_bytes(b'cert')
    (domain_dir / 'privkey.pem').write_bytes(b'key')

    monkeypatch.setattr('modules.core.deployer.run_targets',
                        lambda *a, **k: [])
    manager._execute_targets(domain, 'renewed',
                             targets=[TARGET])

    batches = [e for e in manager.get_history() if e.get('kind') == 'target-batch']
    assert len(batches) == 1
    assert batches[0]['status'] == 'success'


def test_a_target_batch_that_raises_still_closes_its_record(manager,
                                                            monkeypatch):
    """CONTROL: an exception inside run_targets must not leave a record that
    reads as interrupted — the process is alive and knows what happened."""
    domain = 'example.com'
    domain_dir = manager.cert_dir / domain
    domain_dir.mkdir(parents=True)
    (domain_dir / 'fullchain.pem').write_bytes(b'cert')
    (domain_dir / 'privkey.pem').write_bytes(b'key')

    monkeypatch.setattr('modules.core.deployer.run_targets',
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('x')))
    with pytest.raises(RuntimeError):
        manager._execute_targets(domain, 'renewed',
                                 targets=[TARGET])

    assert manager._in_flight == set()
    batches = [e for e in manager.get_history() if e.get('kind') == 'target-batch']
    assert batches[0]['status'] != 'interrupted'


# --- the history the reader hands out -----------------------------------

def test_history_written_before_run_ids_existed_still_reads(manager):
    """The history file survives upgrades. A deploy that happened is not less
    true for predating this change, and must not be relabelled."""
    manager._history_path.parent.mkdir(parents=True, exist_ok=True)
    manager._history_path.write_text(json.dumps({
        'hook_id': 'old', 'hook_name': 'legacy', 'domain': 'old.example.com',
        'success': True, 'exit_code': 0, 'timestamp': '2026-01-01T00:00:00Z',
    }) + '\n')

    history = manager.get_history()
    assert len(history) == 1
    assert history[0]['hook_name'] == 'legacy'
    assert history[0]['success'] is True
    assert 'status' not in history[0], (
        'an old record was given a status it never had'
    )


def test_the_limit_still_counts_runs_not_lines(manager):
    """Two records per run: a limit of 5 must still return 5 runs, not 2 and
    a half."""
    manager.shell_executor.run = lambda cmd, **kw: _completed()
    for i in range(8):
        manager._run_hook(dict(HOOK, id=f'h{i}'), f'd{i}.example.com', 'renewed')

    history = manager.get_history(limit=5)
    assert len(history) == 5
    assert len({e['run_id'] for e in history}) == 5, 'a run appeared twice'
    assert [e['domain'] for e in history] == [
        'd7.example.com', 'd6.example.com', 'd5.example.com',
        'd4.example.com', 'd3.example.com'], 'newest-first ordering broke'


def test_filtering_by_domain_still_folds_the_pairs(manager):
    manager.shell_executor.run = lambda cmd, **kw: _completed()
    manager._run_hook(HOOK, 'a.example.com', 'renewed')
    manager._run_hook(HOOK, 'b.example.com', 'renewed')

    history = manager.get_history(domain='a.example.com')
    assert len(history) == 1
    assert history[0]['domain'] == 'a.example.com'
    assert history[0]['status'] == 'success'


def test_concurrent_hooks_do_not_confuse_each_others_records(manager):
    """The in-flight set is written from EventBus listener threads."""
    manager.shell_executor.run = lambda cmd, **kw: _completed()
    threads = [threading.Thread(target=manager._run_hook,
                                args=(dict(HOOK, id=f'h{i}'),
                                      f'd{i}.example.com', 'renewed'))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    history = manager.get_history(limit=50)
    assert manager._in_flight == set()
    assert len(history) == 8
    assert all(e['status'] == 'success' for e in history)
