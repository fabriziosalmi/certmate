"""A dashboard load must not be N network round trips, one after another.

`GET /api/certificates` called `get_certificate_info` once per domain in a
plain loop. On a local-filesystem instance that is four small reads per domain
out of the page cache and nobody notices. On an instance whose storage backend
is Azure Key Vault or AWS Secrets Manager, each of those is a network round
trip — so one dashboard load was N sequential round trips, and the page got
slower in proportion to how much the instance was actually being used for.

The reads are IO-bound and independent, so they run on a bounded pool. Three
properties are the point, and each is a test:

**Order is preserved.** The dashboard lists certificates in settings order. A
listing that reshuffled on every load would be a worse defect than the latency
it fixes, and `executor.map` preserving order is a fact about the API rather
than something obvious from reading the call.

**One bad certificate does not lose the rest.** `executor.map` re-raises the
first exception when its results are consumed, which would turn one unreadable
certificate into a 500 for the whole listing. The sequential loop did not do
that — it just got a falsy answer — so the concurrency must not introduce it.

**A small instance does not pay for threads.** Below the threshold the calls
stay on the request thread.

The settings dict is loaded once and passed in, which matters more now than it
did: `load_settings` caches on `flask.g` behind `has_request_context()`, and a
worker thread has no request context — so without passing it, every worker
would fall back to reading `settings.json` from disk and the change would make
things worse.
"""
import threading
import time

import pytest

from modules.api.resources_certificates import (
    LISTING_CONCURRENCY, LISTING_CONCURRENCY_THRESHOLD, _gather, _guarded,
)

pytestmark = [pytest.mark.unit]


# --- order ---------------------------------------------------------------

def test_results_come_back_in_the_order_they_went_in():
    items = [f'd{i}.example.com' for i in range(50)]
    assert _gather(lambda d: d.upper(), items) == [d.upper() for d in items]


def test_order_holds_when_the_slow_ones_are_first():
    """The case that would expose an as-completed implementation."""
    items = [f'd{i}.example.com' for i in range(20)]

    def fetch(domain):
        if domain.startswith('d0') or domain.startswith('d1.'):
            time.sleep(0.05)
        return domain

    assert _gather(fetch, items) == items


# --- one failure does not lose the rest ---------------------------------

def test_a_failing_read_yields_none_and_the_others_survive():
    items = [f'd{i}.example.com' for i in range(10)]

    def fetch(domain):
        if domain == 'd5.example.com':
            raise OSError('permission denied')
        return {'domain': domain}

    results = _gather(fetch, items)

    assert len(results) == 10
    assert results[5] is None
    assert results[0] == {'domain': 'd0.example.com'}
    assert results[9] == {'domain': 'd9.example.com'}


def test_a_failing_read_is_logged_with_the_domain():
    """Uses a handler on the module's own logger rather than caplog.

    caplog works through the root logger, so it is at the mercy of anything
    else in the suite that touches global logging configuration — this test
    passed alone and failed in the full run, which is a property of the
    measurement and not of the code. Attaching here measures the logger that
    actually emits.
    """
    import logging
    from modules.api import resources_certificates

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = Capture()
    module_logger = resources_certificates.logger
    module_logger.addHandler(handler)
    previous = module_logger.level
    module_logger.setLevel(logging.ERROR)
    try:
        _guarded(lambda d: (_ for _ in ()).throw(OSError('nope')),
                 'broken.example.com')
    finally:
        module_logger.removeHandler(handler)
        module_logger.setLevel(previous)

    # Positional equality, not membership: the claim is that the domain is
    # the FIRST formatting argument of the message, which is what puts it in
    # the log line. `in` on the args tuple would also accept it turning up as
    # the exception's text, and CodeQL cannot tell a tuple from a string, so
    # it reads that form as an incomplete URL check every time.
    assert records, (
        'a certificate that could not be read vanished from the listing with '
        'nothing saying which one, or why'
    )
    assert records[0].args[0] == 'broken.example.com'
    assert 'nope' in str(records[0].args[1]), 'the cause was not logged'



def test_every_read_failing_still_returns_a_list_the_caller_can_use():
    """CONTROL: the endpoint filters falsy results, so total failure must
    produce an empty listing rather than a 500."""
    items = [f'd{i}.example.com' for i in range(10)]
    results = _gather(lambda d: (_ for _ in ()).throw(OSError('gone')), items)
    assert results == [None] * 10


# --- the pool is bounded, and only used when it earns its keep ----------

def test_a_small_listing_stays_on_the_request_thread():
    """CONTROL: spawning a pool for three local reads costs more than the
    sequential loop it replaces."""
    threads = set()
    items = [f'd{i}.example.com'
             for i in range(LISTING_CONCURRENCY_THRESHOLD - 1)]
    _gather(lambda d: threads.add(threading.current_thread().name), items)
    assert threads == {threading.current_thread().name}


def test_a_large_listing_uses_more_than_one_thread():
    threads = set()
    items = [f'd{i}.example.com' for i in range(40)]

    def fetch(domain):
        threads.add(threading.current_thread().name)
        time.sleep(0.01)          # long enough that the pool actually spreads
        return domain

    _gather(fetch, items)
    assert len(threads) > 1, 'the listing is still sequential'


def test_the_pool_never_exceeds_its_ceiling():
    """One request must not be able to occupy more capacity than the process
    has for serving all of them."""
    concurrent = []
    live = {'n': 0}
    lock = threading.Lock()

    def fetch(domain):
        with lock:
            live['n'] += 1
            concurrent.append(live['n'])
        time.sleep(0.02)
        with lock:
            live['n'] -= 1
        return domain

    _gather(fetch, [f'd{i}.example.com' for i in range(60)])
    assert max(concurrent) <= LISTING_CONCURRENCY, (
        f'{max(concurrent)} reads ran at once against a ceiling of '
        f'{LISTING_CONCURRENCY}'
    )


def test_an_empty_listing_does_nothing():
    assert _gather(lambda d: d, []) == []


# --- the endpoint still hands the settings in ---------------------------

def test_the_endpoint_passes_the_settings_it_already_loaded():
    """Without this, each worker calls load_settings, which caches on flask.g
    behind has_request_context() — absent in a worker — so every one of them
    would read settings.json from disk and the change would be a regression.
    """
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'api' / 'resources_certificates.py').read_text()
    assert 'get_certificate_info(\n                        domain, settings=settings)' in source \
        or 'domain, settings=settings' in source, (
        'the listing no longer reuses the settings it loaded once'
    )
