"""Two log lines from the same operation must be identifiable as such.

The structured logger has always had a `request_id` field and a `LogContext`
to fill it. Nothing ever set either. The field was read off `g.request_id`,
which no code assigned, and the slow-request watchdog took the raw
`X-Request-Id` header — so on the overwhelmingly common case of a caller that
sends no such header, every line carried `request_id: null`, and two lines from
one request were indistinguishable from two lines from different ones.

Background work had nothing at all. A renewal and the deploy hook it triggered
were two unrelated sets of lines, associable only by the clock — on a nightly
sweep where dozens of certificates renew within the same minute.

Three seams, and the third is the one that is easy to get wrong:

* **requests** get an id in `before_request`, honoured from the caller's header
  when it is an opaque token and generated otherwise, and echoed back so a
  caller who sent nothing can still quote it;
* **the renewal sweep** mints one for itself;
* **listener threads** get it from the queued item, because *contextvars do not
  cross a thread boundary*. A worker starts with an empty context, not a copy
  of the publisher's, so passing it implicitly is not an option — and a test
  that only checked the publisher's side would pass while the deploy hook
  logged nothing.
"""
import threading
import time

import pytest
from flask import Flask, g

from modules.core.events import EventBus
from modules.core.factory import setup_correlation_ids
from modules.core.structured_logging import (
    LogContext, clean_correlation_id, current_correlation_id,
    new_correlation_id,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app():
    application = Flask(__name__)
    setup_correlation_ids(application)

    @application.route('/thing')
    def thing():
        return {'seen': current_correlation_id(), 'g': g.request_id}

    return application


def _eventually(predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# --- the id itself -------------------------------------------------------

def test_a_generated_id_is_short_and_unique():
    ids = {new_correlation_id() for _ in range(1000)}
    assert len(ids) == 1000
    assert all(len(i) == 16 for i in ids), (
        'an id is meant to be grepped out of a log and pasted into a query'
    )


@pytest.mark.parametrize('supplied', [
    'abc-123', 'trace:0af7651916cd43dd', 'A' * 64, 'x.y_z-1',
])
def test_an_opaque_token_from_the_caller_is_honoured(supplied):
    """The point of the header is letting a caller stitch its logs to ours."""
    assert clean_correlation_id(supplied) == supplied


@pytest.mark.parametrize('hostile', [
    'evil\nINFO impersonated log line',
    'evil\r\nX-Injected: yes',
    'A' * 65,
    'has spaces',
    'semi;colon',
    '',
    '   ',
    None,
    42,
])
def test_anything_that_is_not_an_opaque_token_is_refused(hostile):
    """The id reaches a log line AND a response header. An unbounded or
    newline-carrying one would let a caller write its own log entries and
    split the header."""
    assert clean_correlation_id(hostile) is None


# --- requests ------------------------------------------------------------

def test_a_request_without_a_header_still_gets_an_id(app):
    body = app.test_client().get('/thing').get_json()
    assert body['seen'], 'the request produced no correlation id at all'
    assert body['seen'] == body['g'], (
        'the log context and g.request_id disagree, so the watchdog and the '
        'log lines would report different ids for one request'
    )


def test_the_id_is_echoed_back(app):
    response = app.test_client().get('/thing')
    assert response.headers['X-Request-Id'] == response.get_json()['seen'], (
        'a caller who sent no header cannot quote the id in a bug report'
    )


def test_a_supplied_id_is_used(app):
    response = app.test_client().get(
        '/thing', headers={'X-Request-Id': 'caller-abc'})
    assert response.get_json()['seen'] == 'caller-abc'
    assert response.headers['X-Request-Id'] == 'caller-abc'


@pytest.mark.parametrize('hostile', ['A' * 200, 'has spaces', 'a;b'])
def test_a_hostile_id_is_replaced_rather_than_sanitised(app, hostile):
    """Sanitising would produce an id the caller did not send and cannot
    match — worse than an honest new one.

    A newline is not among these: werkzeug refuses to put one in a header at
    all, on the way in as well as on the way out, so the case cannot be
    reached through the HTTP layer. `clean_correlation_id` still refuses it —
    the header is not the only thing that ever reaches that function — and
    that is asserted directly above.
    """
    response = app.test_client().get(
        '/thing', headers={'X-Request-Id': hostile})

    seen = response.get_json()['seen']
    assert seen != hostile, 'the hostile value was carried through'
    assert len(seen) == 16, 'the replacement is not a freshly generated id'
    assert response.headers['X-Request-Id'] == seen


def test_two_requests_get_different_ids(app):
    client = app.test_client()
    first = client.get('/thing').get_json()['seen']
    second = client.get('/thing').get_json()['seen']
    assert first != second


def test_the_context_does_not_leak_past_the_request(app):
    """CONTROL: contextvars persist per thread, and the test client runs on
    this one. A context never exited would tag everything that follows with a
    stale request's id."""
    app.test_client().get('/thing')
    assert current_correlation_id() is None, (
        'the request log context was never released'
    )


def test_a_view_that_raises_still_releases_the_context(app):
    """CONTROL: an unhandled exception is exactly when a context manager
    entered by hand gets skipped, and it is also when the id matters most."""
    @app.route('/boom')
    def boom():
        raise RuntimeError('kaboom')

    response = app.test_client().get('/boom')

    assert response.status_code == 500
    assert current_correlation_id() is None, (
        'a view that raised left its log context bound to this thread'
    )


# --- across the thread boundary -----------------------------------------

def test_a_listener_thread_sees_the_publisher_s_id():
    """The seam that cannot work by accident: a worker thread starts with an
    EMPTY context, not a copy of the publisher's."""
    seen = []
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: seen.append(current_correlation_id()))

    with LogContext(request_id='sweep-1234'):
        bus.publish('certificate_renewed', {'domain': 'x.example.com'})

    assert _eventually(lambda: len(seen) == 1)
    assert seen[0] == 'sweep-1234', (
        'the deploy hook logged under a different id than the renewal that '
        'triggered it, which is the whole defect'
    )


def test_a_publish_outside_any_context_carries_no_id():
    """CONTROL: inventing an id here would be worse than none — it would look
    like a correlated unit of work that nothing else belongs to."""
    seen = []
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: seen.append(current_correlation_id()))

    bus.publish('certificate_renewed', {'domain': 'x.example.com'})

    assert _eventually(lambda: len(seen) == 1)
    assert seen[0] is None


def test_the_id_does_not_leak_between_two_dispatches():
    """One worker handles both; the second must not inherit the first's id."""
    seen = []
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: seen.append(current_correlation_id()))

    with LogContext(request_id='first-one'):
        bus.publish('certificate_created', {'domain': 'a.example.com'})
    assert _eventually(lambda: len(seen) == 1)

    bus.publish('certificate_created', {'domain': 'b.example.com'})
    assert _eventually(lambda: len(seen) == 2)
    assert seen == ['first-one', None]


def test_concurrent_publishers_do_not_share_an_id():
    """Two requests renewing different domains at once must stay apart."""
    seen = {}
    bus = EventBus(workers=4)
    bus.add_listener(
        lambda event, data: seen.__setitem__(data['domain'],
                                             current_correlation_id()))

    def publish(name):
        with LogContext(request_id=f'req-{name}'):
            bus.publish('certificate_created', {'domain': name})

    threads = [threading.Thread(target=publish, args=(f'd{i}.example.com',))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert _eventually(lambda: len(seen) == 8)
    assert seen == {f'd{i}.example.com': f'req-d{i}.example.com'
                    for i in range(8)}


# --- the renewal sweep ---------------------------------------------------

def test_the_sweep_runs_under_an_id_and_releases_it(tmp_path):
    from unittest.mock import MagicMock
    from modules.core.certificates import CertificateManager

    settings = MagicMock()
    settings.load_settings.return_value = {
        'auto_renew': True,
        'domains': [{'domain': 'a.example.com', 'auto_renew': True}]}
    settings.migrate_domains_format.side_effect = lambda s: s
    manager = CertificateManager(tmp_path / 'certificates', settings,
                                 dns_manager=None)

    seen = []
    manager.get_certificate_info = MagicMock(
        side_effect=lambda domain, **kw: seen.append(current_correlation_id())
        or {'needs_renewal': False})

    manager.check_renewals()

    assert seen and seen[0], 'the sweep ran without a correlation id'
    assert current_correlation_id() is None, (
        'the sweep context leaked, so every later job on this scheduler '
        'thread would carry a stale sweep id'
    )


def test_the_sweep_releases_its_id_even_when_it_blows_up(tmp_path):
    """CONTROL: the release is in a finally for this reason."""
    from unittest.mock import MagicMock
    from modules.core.certificates import CertificateManager

    settings = MagicMock()
    settings.load_settings.return_value = {'auto_renew': True, 'domains': []}
    settings.migrate_domains_format.side_effect = (
        lambda s: (_ for _ in ()).throw(RuntimeError('settings exploded')))
    manager = CertificateManager(tmp_path / 'certificates', settings,
                                 dns_manager=None)

    with pytest.raises(RuntimeError):
        manager.check_renewals()
    assert current_correlation_id() is None
