"""Three from the #591 re-triage where the answer outlived the fact.

**A backup route said "Backup created" with no file.**
`create_unified_backup` returns None on failure — an unwritable directory, a
full disk — and the web route reported `200 {"message": "Backup created",
"filename": null}` regardless. An operator taking a backup before something
risky got a green toast and nothing on disk, which is the one moment that
answer has to be true. Three of the four callers already checked: the RESTX
twin answers 500, and the pre-restore path refuses to restore at all rather
than do the irreversible thing with no way back.

**A stream had no cap and no end.** Each live SSE connection holds a gunicorn
thread, and the product ships `--workers 1 --threads 8` — the Dockerfile
comment says so in as many words: "SSE holds 1 thread per browser tab; 4 was
too few". `subscribe()` appended to an unbounded list (20,000 of them
registered in 0.08s without complaint) and `stream()` was `while True`. Nine
tabs left nothing to answer an ordinary request with.

**A per-run cap counted outcomes, not requests.** The CT poll advanced its
counter only when `_ingest_new` SUCCEEDED, while the crt.sh fetch inside it
happened either way. Measured before: a cap of 5 against a client whose every
fetch failed issued **1000 requests** and reported `truncated: False`. After:
5 requests, whether the fetches succeed or fail.
"""
import logging
import threading
import time
from unittest.mock import MagicMock

import pytest

pytestmark = [pytest.mark.unit]


# --- the backup that was not taken ---------------------------------------

@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    """A real app, so the route is driven rather than read."""
    import os
    import secrets

    tmp = tmp_path_factory.mktemp('answers')
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
        from modules.factory import create_app
        app, container = create_app()
        yield app, container, token


def test_a_backup_that_did_not_happen_is_not_a_success(instance, monkeypatch):
    """THE regression, driven through the route.

    The first version of this asserted on the SOURCE — that the guard was
    written — which is not the same claim and left the new branch with no
    coverage at all. The per-module floor said so, and it was right: a
    branch nothing executes is a branch nothing has checked.
    """
    app, container, token = instance
    headers = {'Authorization': f'Bearer {token}', 'Origin': 'http://localhost'}

    monkeypatch.setattr(container.managers['file_ops'],
                        'create_unified_backup', lambda *a, **k: None)
    response = app.test_client().post('/api/web/backups/create',
                                      json={'include_secrets': False},
                                      headers=headers)

    assert response.status_code == 500, response.get_data(as_text=True)
    body = response.get_json()
    assert body.get('error')
    assert 'filename' not in body, (
        'the response still carries a filename field for a backup that was '
        'never written')


def test_a_backup_that_did_happen_still_reports_it(instance, monkeypatch):
    """CONTROL. A route that answered 500 unconditionally would satisfy the
    test above and break the feature."""
    app, container, token = instance
    headers = {'Authorization': f'Bearer {token}', 'Origin': 'http://localhost'}

    monkeypatch.setattr(container.managers['file_ops'],
                        'create_unified_backup',
                        lambda *a, **k: 'backup_20260924_real.zip')
    response = app.test_client().post('/api/web/backups/create',
                                      json={'include_secrets': False},
                                      headers=headers)

    assert response.status_code == 200
    body = response.get_json()
    assert body['filename'] == 'backup_20260924_real.zip'
    assert body['secrets_masked'] is True


def test_every_caller_of_the_backup_checks_its_answer():
    """This was the only one that did not. Asserted across all of them so
    the next caller inherits the rule rather than rediscovering it."""
    import pathlib
    import re

    repo = pathlib.Path(__file__).resolve().parent.parent
    for relative in ('modules/web/backup_cache_routes.py',
                     'modules/api/resources_backup.py',
                     'modules/core/settings.py'):
        source = (repo / relative).read_text(encoding='utf-8')
        if 'create_unified_backup(' not in source:
            continue
        # Each call site is followed, within a few lines, by a test of what
        # it returned — `if filename:`, `if not pre_restore_backup:`,
        # `if not result:`.
        for match in re.finditer(r'(\w+) = [\w.]*create_unified_backup\(',
                                 source):
            name = match.group(1)
            following = source[match.end():match.end() + 900]
            assert re.search(rf'if (not )?{name}\b', following), (
                f'{relative}: nothing checks what create_unified_backup '
                f'returned into {name!r}')


# --- the stream that never ended -----------------------------------------

def test_the_bus_refuses_more_streams_than_it_can_serve():
    """THE regression. Each live stream holds one of eight threads."""
    from modules.core.events import EventBus, TooManyStreams

    bus = EventBus(workers=1)
    held = [bus.subscribe() for _ in range(bus._max_streams)]

    with pytest.raises(TooManyStreams):
        bus.subscribe()

    assert len(held) == bus._max_streams


def test_a_closed_stream_gives_its_place_back():
    """CONTROL. A cap that only ever fills up would break the product after
    four tabs were ever opened, which is worse than the defect."""
    from modules.core.events import EventBus

    bus = EventBus(workers=1)
    held = [bus.subscribe() for _ in range(bus._max_streams)]
    bus.unsubscribe(held[0])

    replacement = bus.subscribe()

    assert replacement is not None


def test_a_stream_ends_on_its_own(monkeypatch):
    """`while True` meant "as long as the tab is open". EventSource
    reconnects by itself, so ending the response is invisible and returns
    the thread."""
    from modules.core.events import EventBus

    bus = EventBus(workers=1)
    bus._stream_seconds = 0.2
    q = bus.subscribe()

    chunks = []
    started = time.monotonic()
    for chunk in bus.stream(q):
        chunks.append(chunk)
        if time.monotonic() - started > 5:
            pytest.fail('the stream did not end on its own')

    assert chunks[0].startswith(': connected')
    assert chunks[-1].startswith(': reconnect')
    assert q not in bus._subscribers, 'the subscriber was not released'


def test_an_event_still_reaches_a_live_stream():
    """CONTROL. A deadline must not swallow what the stream is for."""
    from modules.core.events import EventBus

    bus = EventBus(workers=1)
    bus._stream_seconds = 5
    q = bus.subscribe()
    q.put({'event': 'certificate_renewed', 'data': {'domain': 'a.example.com'}})

    stream = bus.stream(q)
    first = next(stream)
    second = next(stream)
    stream.close()

    # Parsed, not searched. A hostname tested with `in` against a larger
    # string says nothing about WHERE it matched, which is what CodeQL's
    # incomplete-url-substring rule is about — and it is right about the
    # pattern even in a test. Splitting the SSE frame is also the stricter
    # assertion: it pins the event name and the payload separately.
    import json as _json

    lines = dict(line.split(': ', 1) for line in second.strip().split('\n'))

    assert first.startswith(': connected')
    assert lines['event'] == 'certificate_renewed'
    assert _json.loads(lines['data']) == {'domain': 'a.example.com'}


def test_the_limits_are_tunable_and_clamped(monkeypatch):
    """A typo in a limit must not take the feature out."""
    from modules.core.events import (
        DEFAULT_MAX_STREAMS, DEFAULT_STREAM_SECONDS, EventBus,
    )

    monkeypatch.setenv('CERTMATE_EVENT_MAX_STREAMS', '9')
    assert EventBus(workers=1)._max_streams == 9

    monkeypatch.setenv('CERTMATE_EVENT_MAX_STREAMS', '1000')
    assert EventBus(workers=1)._max_streams == 64

    monkeypatch.setenv('CERTMATE_EVENT_MAX_STREAMS', 'not a number')
    assert EventBus(workers=1)._max_streams == DEFAULT_MAX_STREAMS

    monkeypatch.setenv('CERTMATE_EVENT_STREAM_SECONDS', '1')
    assert EventBus(workers=1)._stream_seconds == 30      # clamped up
    monkeypatch.setenv('CERTMATE_EVENT_STREAM_SECONDS', 'x')
    assert EventBus(workers=1)._stream_seconds == DEFAULT_STREAM_SECONDS


# --- the cap that counted the wrong thing --------------------------------

def _poll_with(ingest_result, cap=5, entries=500):
    """Run the CT poll and report how many crt.sh fetches it made.

    The counter is read AFTER the poll. The first draft wrote
    `return calls['n'], mgr.run_poll()`, which Python evaluates left to
    right — so it reported zero requests for a run that had not happened
    yet.
    """
    from modules.core.ct_monitor import CTMonitorManager

    manager = CTMonitorManager.__new__(CTMonitorManager)
    # __new__ skips __init__, so every attribute the poll reads has to be set
    # here — including the lock that stops two polls overlapping. Without it
    # this raises AttributeError before the cap is ever exercised.
    manager._poll_lock = threading.Lock()
    manager.inventory = MagicMock()
    manager.inventory.find_by_serial.return_value = None
    manager.settings_manager = MagicMock()
    manager.settings_manager.load_settings.return_value = {'ct_monitoring': {
        'enabled': True, 'domains': ['a.example.com', 'b.example.com'],
        'max_new_per_run': cap, 'only_valid': False}}

    client = MagicMock()
    client.search.return_value = [
        {'serial_number': str(n), 'not_before': '2026-01-01T00:00:00'}
        for n in range(entries)]
    manager._resolve_client = lambda config: client

    fetches = {'count': 0}

    def _ingest(_client, _entry, _now):
        fetches['count'] += 1
        return ingest_result

    manager._ingest_new = _ingest

    summary = manager.run_poll()
    return fetches['count'], summary


def test_the_cap_bounds_requests_even_when_every_fetch_fails(caplog):
    """THE regression. Measured before: 1000 requests against a cap of 5,
    reported as `truncated: False`."""
    caplog.set_level(logging.CRITICAL)

    fetches, summary = _poll_with(ingest_result=False, cap=5)

    assert fetches == 5, f'{fetches} crt.sh requests against a cap of 5'
    assert summary['truncated'] is True
    assert summary['new'] == 0


def test_the_cap_bounds_requests_when_they_succeed_too(caplog):
    """CONTROL. The same ceiling either way — a fix that only counted
    failures would swap one asymmetry for another."""
    caplog.set_level(logging.CRITICAL)

    fetches, summary = _poll_with(ingest_result=True, cap=5)

    assert fetches == 5
    assert summary['truncated'] is True
    assert summary['new'] == 5


def test_a_poll_under_the_cap_is_not_truncated(caplog):
    """CONTROL. `truncated` must mean something: a run that fitted has to
    say so, or an operator cannot tell a full sweep from a clipped one."""
    caplog.set_level(logging.CRITICAL)

    fetches, summary = _poll_with(ingest_result=True, cap=50, entries=3)

    assert fetches == 6          # three entries, two domains
    assert summary['truncated'] is False
    assert summary['new'] == 6
