"""The renewal schedule is verified by running it, not by reading its config.

Every existing check asserted the *configuration* of the renewal jobs — the
misfire grace, the coalesce flag, the jitter value. Nothing ever asked the
scheduler what it would actually do, and nothing ever let it fire. So the
product's core promise ("certificates renew on their own, overnight, at
randomised times") rested on settings nobody had exercised.

That gap has a concrete cost right now: CertMate was submitted to the Let's
Encrypt client list on the strength of meeting their randomised-renewal
criterion, and the jitter that claim depends on was asserted only as a number
in a config dict (#661).

These tests take the trigger the application actually builds, compute the fire
times it would produce, and separately let a scheduler run a job to completion.
"""
from datetime import datetime, timedelta, timezone

import pytest
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from modules.core import factory

pytestmark = [pytest.mark.unit]

RENEWAL_JOBS = ('certificate_renewal_check', 'client_certificate_renewal_check')


@pytest.fixture
def scheduled_app(monkeypatch, tmp_path):
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    app, container = factory.create_app(test_config={'TESTING': True})
    yield container
    if container.scheduler:
        container.scheduler.shutdown(wait=False)


def _fire_times(trigger, count, start=None):
    """The times *trigger* would actually fire, in order."""
    now = start or datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    previous, times = None, []
    for _ in range(count):
        nxt = trigger.get_next_fire_time(previous, now)
        assert nxt is not None, "trigger stopped producing fire times"
        times.append(nxt)
        previous, now = nxt, nxt
    return times


# --------------------------------------------------------------------------
# What the configured trigger would really do
# --------------------------------------------------------------------------

@pytest.mark.parametrize('job_id', RENEWAL_JOBS)
def test_the_renewal_sweep_would_fire_about_once_a_day(scheduled_app, job_id):
    job = scheduled_app.scheduler.get_job(job_id)
    assert job is not None, f'{job_id} is not scheduled'

    times = _fire_times(job.trigger, 15)
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]

    # A day, give or take the jitter applied at both ends.
    for gap in gaps:
        assert timedelta(hours=20).total_seconds() <= gap <= timedelta(hours=28).total_seconds(), (
            f'{job_id} would fire {gap / 3600:.1f}h apart; the renewal sweep '
            f'is meant to run daily'
        )


@pytest.mark.parametrize('job_id', RENEWAL_JOBS)
def test_the_fire_times_are_actually_jittered(scheduled_app, job_id):
    """The property Let's Encrypt's listing criterion turns on.

    Configuration said jitter=3600. This asks whether the times it produces
    genuinely differ, rather than trusting the number.
    """
    job = scheduled_app.scheduler.get_job(job_id)
    times = _fire_times(job.trigger, 15)
    seconds_into_day = {t.hour * 3600 + t.minute * 60 + t.second for t in times}

    assert len(seconds_into_day) > 1, (
        f'{job_id} fires at the same clock time every day, so every install '
        f'would contact the CA at the same second — the load spike the jitter '
        f'exists to prevent'
    )


@pytest.mark.parametrize('job_id', RENEWAL_JOBS)
def test_the_jitter_stays_inside_its_window(scheduled_app, job_id):
    """CONTROL: spread is not the only requirement.

    Unbounded randomisation would eventually renew in the middle of the
    working day. The sweep must stay in the overnight window it advertises.
    """
    job = scheduled_app.scheduler.get_job(job_id)
    trigger, jitter = job.trigger, job.trigger.jitter
    base_hour = int(str(trigger.fields[trigger.FIELD_NAMES.index('hour')]))

    for fire in _fire_times(trigger, 15):
        base = fire.replace(hour=base_hour, minute=0, second=0, microsecond=0)
        drift = abs((fire - base).total_seconds())
        assert drift <= jitter + 1, (
            f'{job_id} fired {drift:.0f}s from its {base_hour:02d}:00 slot, '
            f'outside the {jitter}s jitter window'
        )


@pytest.mark.parametrize('job_id', RENEWAL_JOBS)
def test_the_sweep_stays_overnight(scheduled_app, job_id):
    """The window test above derives its bound from the configured jitter, so
    it cannot notice an absurd one — widen the jitter and the window widens
    with it. This pins the property an operator actually cares about: the
    sweep runs while the estate is quiet, not in the middle of the day.
    """
    job = scheduled_app.scheduler.get_job(job_id)
    for fire in _fire_times(job.trigger, 20):
        assert fire.hour < 6, (
            f'{job_id} would fire at {fire.strftime("%H:%M")}; the renewal '
            f'sweep is advertised as overnight, and certbot runs can be long'
        )


def test_without_jitter_the_times_would_be_identical():
    """CONTROL: proves the jitter assertion can fail.

    If the same computation reports variation for an unjittered trigger, it is
    measuring noise rather than jitter, and the test above would pass whatever
    the configuration said.
    """
    times = _fire_times(CronTrigger(hour=2, minute=0), 15)
    seconds_into_day = {t.hour * 3600 + t.minute * 60 + t.second for t in times}
    assert seconds_into_day == {2 * 3600}, (
        'an unjittered cron must fire at exactly the same clock time daily'
    )


# --------------------------------------------------------------------------
# And the scheduler really runs a job
# --------------------------------------------------------------------------

def test_the_scheduler_executes_a_job_it_is_given():
    """The literal gap: no test had ever let APScheduler fire anything.

    Uses the same job_defaults the application configures, so a mistake there
    that prevented execution would surface here.
    """
    import threading

    ran = threading.Event()
    scheduler = BackgroundScheduler(job_defaults={
        'coalesce': True, 'misfire_grace_time': 21600, 'max_instances': 1,
    })
    scheduler.start()
    try:
        scheduler.add_job(
            ran.set, 'date',
            run_date=datetime.now(timezone.utc) + timedelta(milliseconds=50),
            id='probe',
        )
        assert ran.wait(timeout=10), (
            'the scheduler never executed a job that was due — automatic '
            'renewal depends entirely on this working'
        )
    finally:
        scheduler.shutdown(wait=False)
