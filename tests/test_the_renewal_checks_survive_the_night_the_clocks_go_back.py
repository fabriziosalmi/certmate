"""The renewal checks survive the night the clocks go back (#1372).

On 25 October 2026 a CertMate in `Europe/Zagreb` stopped: the renewal check, a
cron at 02:00 with an hour of jitter in the instance's own time zone, landed in
the hour that night repeats, and APScheduler 3.11.3 loses the fold when it adds
the jitter (agronholm/apscheduler#1183), so its next run never left that hour.
The job is stored, and the scheduler started before the jobs were replaced, so
every start spun on it and the application never came up.

So the two renewal checks are scheduled in UTC, which repeats and skips no hour,
and the jobs are added before the scheduler starts, so a stored job stuck in
that hour is replaced before the scheduler reads it.
"""
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from modules import factory

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
ZAGREB = ZoneInfo('Europe/Zagreb')
# The first 02:08 of the night the clocks went back, and the morning after.
IN_THE_REPEATED_HOUR = datetime(2026, 10, 25, 2, 8, tzinfo=ZAGREB)
THE_MORNING_AFTER = datetime(2026, 10, 26, 11, 0, tzinfo=ZAGREB)
CHECKS = {'certificate_renewal_check': 2, 'client_certificate_renewal_check': 3}


def test_the_renewal_checks_move_on_from_the_repeated_hour(monkeypatch, tmp_path):
    """Whatever the instance's own zone: here the scheduler's is forced to Zagreb."""
    import apscheduler.schedulers.base as base
    monkeypatch.setattr(base, 'get_localzone', lambda: ZAGREB)
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    _app, container = factory.create_app(test_config={'TESTING': True})
    try:
        for job_id, hour in CHECKS.items():
            trigger = container.scheduler.get_job(job_id).trigger
            # What the scheduler does with a missed run: ask for the next
            # one after it until one is due after now. Stuck, it never is.
            fire = IN_THE_REPEATED_HOUR
            for _ in range(10):
                fire = trigger.get_next_fire_time(fire, THE_MORNING_AFTER)
                if fire > THE_MORNING_AFTER:
                    break
            else:
                pytest.fail(f'{job_id} never gets past the repeated hour: {fire}')
            assert fire.utcoffset() == timedelta(0), f'{job_id} is not in UTC: {fire}'
            assert fire.hour == hour
            assert trigger.jitter == 3600
    finally:
        container.scheduler.shutdown(wait=False)


_STUCK_INSTANCE = textwrap.dedent('''
    import json, os, sys, time
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo
    from apscheduler.job import Job
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from sqlalchemy import create_engine

    root = sys.argv[1]
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('DATA_DIR', 'data'), ('CERTMATE_BACKUP_DIR', 'backups'),
                     ('CERTMATE_LOGS_DIR', 'logs'), ('ACME_CHALLENGES_DIR', 'challenges')):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
        os.environ[var] = os.path.join(root, sub)

    # The store as an affected instance left it: the renewal check, in the
    # instance's zone, due at the first 02:08 of the night the clocks went
    # back. Written into the store directly: a scheduler started on it would
    # spin on it, here, before the application is asked anything.
    zagreb = ZoneInfo('Europe/Zagreb')
    engine = create_engine('sqlite:///' + os.path.join(root, 'data', 'scheduler_jobs.sqlite'))
    store = SQLAlchemyJobStore(engine=engine)
    never_started = BackgroundScheduler(timezone=zagreb)
    store.start(never_started, 'default')
    store.add_job(Job(never_started, id='certificate_renewal_check',
                      func='modules.factory:_certificate_renewal_job', args=(), kwargs={},
                      trigger=CronTrigger(hour=2, minute=0, jitter=3600, timezone=zagreb),
                      executor='default', name='_certificate_renewal_job',
                      misfire_grace_time=21600, coalesce=True, max_instances=1,
                      next_run_time=datetime(2026, 10, 25, 2, 8, tzinfo=zagreb)))
    store.shutdown()
    engine.dispose()

    from modules.factory import create_app
    started = time.monotonic()
    app, container = create_app(test_config={'TESTING': True})
    job = container.scheduler.get_job('certificate_renewal_check')
    print(json.dumps({'seconds': time.monotonic() - started,
                      'next_run': job.next_run_time.isoformat(),
                      'now': datetime.now(timezone.utc).isoformat()}), flush=True)
    container.scheduler.shutdown(wait=False)
    os._exit(0)
''')


def test_an_instance_stuck_in_the_repeated_hour_starts_again(tmp_path):
    """In its own process, under the zone that hung, with a deadline: a start
    that spins is a timeout here, not a hung test run."""
    env = dict(os.environ, TZ='Europe/Zagreb', PYTHONPATH=str(REPO), FLASK_ENV='testing',
               TESTING='true')
    try:
        done = subprocess.run([sys.executable, '-c', _STUCK_INSTANCE, str(tmp_path)],
                              cwd=REPO, env=env, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        pytest.fail('create_app() did not return within 90 s: the scheduler is spinning '
                    'on the job stuck in the repeated hour')
    assert done.returncode == 0, done.stderr[-2000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    next_run = datetime.fromisoformat(result['next_run'])
    assert next_run > datetime.fromisoformat(result['now'])
    assert next_run.utcoffset() == timedelta(0)
    assert next_run.hour == 2
