"""An instance past its capacity has to say so before certificates stop.

The nightly sweep counted what it did and logged the counts. That was the whole
of its self-knowledge: no duration, nothing exported, and no way to tell
"finished, nothing was due" from "died half way through". So an instance whose
sweep takes longer every night — and will eventually stop finishing between
runs — looked exactly like one that was fine, right up until certificates
stopped renewing.

Two artefacts, and neither needs a capacity number to be chosen in advance:

* a marker file recording that a sweep is in progress and roughly how far it
  has got, so the NEXT sweep can report that the previous one never finished
  and where it stopped — the failing process is by definition not around to
  report itself;
* four gauges, so the same thing is a graph:
  `certmate_renewal_sweep_duration_seconds`, `..._certificates_examined`,
  `..._completed_timestamp_seconds` and `..._unfinished`. The timestamp is the
  one a duration cannot replace: it stops moving when the sweep stops
  finishing.

What this deliberately does not do is *resume* from the stopping point.
Renewal is idempotent and ordered by settings.json, so a rerun re-examines
cheap not-due entries rather than losing work; reordering the sweep would be a
behaviour change for a problem nobody has reported. Recording where it stopped
is what makes that decision possible later, with evidence.
"""
import json
import logging
import time
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {'auto_renew': True, 'domains': []}
    settings.migrate_domains_format.side_effect = lambda s: s
    mgr = CertificateManager(tmp_path / 'certificates', settings,
                             dns_manager=None)
    return mgr


def _with_domains(manager, names):
    stored = {'auto_renew': True,
              'domains': [{'domain': n, 'auto_renew': True} for n in names]}
    manager.settings_manager.load_settings.return_value = stored
    manager.settings_manager.migrate_domains_format.side_effect = lambda s: s
    manager.get_certificate_info = MagicMock(
        return_value={'needs_renewal': False, 'dns_provider': 'cloudflare'})


def _marker(manager):
    path = manager._sweep_marker_path()
    return json.loads(path.read_text()) if path.exists() else None


# --- the sweep reports its own shape ------------------------------------

def test_the_summary_carries_the_duration_and_the_count(manager):
    _with_domains(manager, [f'd{i}.example.com' for i in range(5)])
    summary = manager.check_renewals()

    assert summary['examined'] == 5
    assert 'duration_seconds' in summary
    assert summary['duration_seconds'] >= 0


def test_completion_is_logged_with_the_duration(manager, caplog):
    _with_domains(manager, ['a.example.com'])
    with caplog.at_level(logging.INFO):
        manager.check_renewals()

    assert any('Renewal check complete in' in r.getMessage()
               for r in caplog.records), (
        'the completion line does not say how long the sweep took, which is '
        'the number that grows before anything breaks'
    )


def test_the_start_says_how_much_work_there_is(manager, caplog):
    """CONTROL for the pair: a duration is only readable next to a count."""
    _with_domains(manager, [f'd{i}.example.com' for i in range(3)])
    with caplog.at_level(logging.INFO):
        manager.check_renewals()

    assert any('3 certificate' in r.getMessage() for r in caplog.records)


def test_the_metrics_are_recorded_on_completion(manager, monkeypatch):
    recorded = {}
    monkeypatch.setattr(
        'modules.core.metrics.metrics_collector.record_renewal_sweep',
        lambda examined, duration, completed_at: recorded.update(
            examined=examined, duration=duration, completed_at=completed_at))

    _with_domains(manager, ['a.example.com', 'b.example.com'])
    manager.check_renewals()

    assert recorded['examined'] == 2
    assert recorded['duration'] >= 0
    assert recorded['completed_at'] > time.time() - 60


# --- a sweep that never finished ----------------------------------------

def test_an_unfinished_sweep_is_reported_by_the_next_one(manager, caplog):
    """The failing process cannot report itself. The marker is how the next
    sweep finds out."""
    marker = manager._sweep_marker_path()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({
        'started_at': time.time() - 3600, 'total': 400, 'examined': 130,
        'finished': False}))

    _with_domains(manager, ['a.example.com'])
    with caplog.at_level(logging.WARNING):
        manager.check_renewals()

    warnings = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.WARNING]
    assert any('did not finish' in m for m in warnings), (
        'a sweep that died half way through left no signal for the next one'
    )
    said = next(m for m in warnings if 'did not finish' in m)
    assert '130' in said and '400' in said, (
        f'the warning does not say how far it got: {said}'
    )
    assert 'duration_seconds' in said, (
        'the warning does not name the metric to watch'
    )


def test_a_finished_sweep_is_not_reported_as_unfinished(manager, caplog):
    """CONTROL: a warning after every successful night is a warning nobody
    reads, and it would fire on every single run."""
    _with_domains(manager, ['a.example.com'])
    manager.check_renewals()

    with caplog.at_level(logging.WARNING):
        manager.check_renewals()

    assert not [r for r in caplog.records
                if 'did not finish' in r.getMessage()]


def test_the_unfinished_gauge_is_set_and_then_cleared(manager, monkeypatch):
    flags = []
    monkeypatch.setattr(
        'modules.core.metrics.metrics_collector.record_renewal_sweep_unfinished',
        lambda: flags.append('unfinished'))
    monkeypatch.setattr(
        'modules.core.metrics.metrics_collector.record_renewal_sweep',
        lambda examined, duration, completed_at: flags.append('finished'))

    marker = manager._sweep_marker_path()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({'started_at': time.time() - 60,
                                  'total': 10, 'examined': 4,
                                  'finished': False}))
    _with_domains(manager, ['a.example.com'])
    manager.check_renewals()

    assert flags == ['unfinished', 'finished'], (
        'the unfinished flag must be raised by the next sweep and cleared '
        'when that sweep completes'
    )


def test_the_marker_records_progress_part_way_through(manager):
    """What makes "where it stopped" answerable at all."""
    seen = []
    _with_domains(manager, [f'd{i}.example.com' for i in range(25)])
    real = manager.get_certificate_info

    def spy(domain, **kw):
        seen.append(_marker(manager))
        return real(domain, **kw)

    manager.get_certificate_info = spy
    manager.check_renewals()

    part_way = [m for m in seen if m and not m['finished'] and m['examined']]
    assert part_way, (
        'the marker never recorded progress, so a sweep that died would only '
        'be known to have started'
    )
    assert max(m['examined'] for m in part_way) >= 20
    assert all(m['total'] == 25 for m in part_way)


def test_the_marker_is_left_finished_after_a_clean_run(manager):
    _with_domains(manager, ['a.example.com'])
    manager.check_renewals()

    marker = _marker(manager)
    assert marker['finished'] is True
    assert marker['examined'] == 1
    assert marker['duration_seconds'] >= 0


# --- telemetry must never be the reason a renewal stops -----------------

def test_a_marker_that_cannot_be_written_does_not_stop_the_sweep(manager,
                                                                 monkeypatch):
    """A read-only data volume is a real deployment, and telemetry must never
    be the reason certificates stop renewing — which is the one thing this
    whole mechanism exists to warn about."""
    monkeypatch.setattr(
        CertificateManager, '_atomic_json_write',
        staticmethod(lambda path, data: (_ for _ in ()).throw(
            OSError('read-only file system'))))
    _with_domains(manager, ['a.example.com'])

    summary = manager.check_renewals()

    assert summary['checked'] == 1, 'a failed marker write aborted the sweep'
    assert _marker(manager) is None, 'the marker was written after all'


def test_a_corrupt_marker_is_ignored_rather_than_believed(manager, caplog):
    marker = manager._sweep_marker_path()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text('{not json')

    _with_domains(manager, ['a.example.com'])
    with caplog.at_level(logging.WARNING):
        summary = manager.check_renewals()

    assert summary['checked'] == 1
    assert not [r for r in caplog.records
                if 'did not finish' in r.getMessage()], (
        'an unreadable marker was read as evidence of a failed sweep'
    )


def test_a_failing_metric_does_not_stop_the_sweep(manager, monkeypatch):
    monkeypatch.setattr(
        'modules.core.metrics.metrics_collector.record_renewal_sweep',
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('collector gone')))
    _with_domains(manager, ['a.example.com'])

    assert manager.check_renewals()['checked'] == 1


def test_the_globally_disabled_path_is_untouched(manager):
    """CONTROL: with auto_renew off the sweep returns early and must not
    leave a marker claiming a sweep ran."""
    manager.settings_manager.load_settings.return_value = {'auto_renew': False}
    summary = manager.check_renewals()

    assert summary.get('auto_renew_disabled') is True
    assert _marker(manager) is None
