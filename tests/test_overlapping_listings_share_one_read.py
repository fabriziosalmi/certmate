"""Overlapping certificate listings share one read (#1463).

`GET /api/certificates` read every certificate itself, on a pool of 8 threads
it started for that request. Four listings at once on 2,049 certificates each
took about 168 s where one alone took 15 s: every one of them did the whole
read, 32 threads parsed certificates against one interpreter lock, and the 8
gunicorn threads they held starved `/health`.

So a listing that starts while another with the same answer is running waits
for it and gets its result. "The same answer" is what the answer depends on:
the caller's scope, the settings, the UTC day (expiry fields count days), and
no certificate written since the running listing started. A write bumps
`CertificateManager.listing_generation` wherever it already clears the
certificate-info cache, so a listing never hands out what a write it began
before has changed. And every listing reads on one pool for the process, so
listings that cannot share still hold at most 8 reader threads between them.
"""
import secrets
import threading
import time

import pytest

from tests.contract_world import write_certificate

pytestmark = [pytest.mark.unit]

DOMAINS = [f'host{i}.share.example' for i in range(12)]


@pytest.fixture
def instance(tmp_path, monkeypatch):
    token = secrets.token_urlsafe(32)
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    from modules.factory import create_app
    app, container = create_app()
    for name in DOMAINS:
        write_certificate(tmp_path / 'certs' / name, name, [])
    certs = container.managers['certificates']
    return app, certs, {'Authorization': f'Bearer {token}'}


class Gate:
    """Counts reads and holds each one until released, so a test can start
    listings while the first one is still reading."""

    def __init__(self, certs, monkeypatch):
        self.reads = []
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.started = threading.Event()
        original = certs.get_certificate_info

        def counted(domain, settings=None, use_cache=True):
            with self.lock:
                self.reads.append(domain)
            self.started.set()
            assert self.release.wait(30), 'the test never released the reads'
            return original(domain, settings=settings, use_cache=False)

        monkeypatch.setattr(certs, 'get_certificate_info', counted)


def _list_in_thread(app, headers, results, index):
    with app.test_client() as client:
        response = client.get('/api/certificates', headers=headers)
        results[index] = (response.status_code, response.get_json())


def _start(app, headers, results, index):
    thread = threading.Thread(target=_list_in_thread, args=(app, headers, results, index))
    thread.start()
    return thread


def _wait_for_followers(app, count, timeout=10):
    from modules.api import resources_certificates as listing
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if listing.LISTINGS.waiting() >= count:
            return
        time.sleep(0.01)
    raise AssertionError(f'{count} listings never joined the running one')


def test_four_overlapping_listings_read_each_certificate_once(instance, monkeypatch):
    app, certs, headers = instance
    gate = Gate(certs, monkeypatch)
    results = [None] * 4
    first = _start(app, headers, results, 0)
    assert gate.started.wait(10)
    others = [_start(app, headers, results, i) for i in (1, 2, 3)]
    _wait_for_followers(app, 3)
    gate.release.set()
    for thread in [first, *others]:
        thread.join(30)
    assert sorted(gate.reads) == sorted(DOMAINS), (
        f'{len(gate.reads)} reads for {len(DOMAINS)} certificates: the listings did not share')
    assert all(status == 200 for status, _ in results)
    names = [[c['domain'] for c in body] for _, body in results]
    assert all(n == names[0] for n in names) and sorted(names[0]) == sorted(DOMAINS)


def test_each_listing_that_shares_a_read_gets_its_own_copy(instance):
    """Two listings that waited for the same read must not hand out one object:
    what one request does to its answer must not show in another's."""
    from modules.api import resources_certificates as listing
    release, calls, answers = threading.Event(), [], {}

    def compute():
        calls.append(1)
        assert release.wait(10)
        return [{'domain': 'a.example', 'tags': []}]

    def call(name):
        answers[name] = listing.LISTINGS.run(('copy',), compute)

    leader = threading.Thread(target=call, args=('leader',))
    leader.start()
    deadline = time.monotonic() + 10
    while not listing.LISTINGS.running(('copy',)) and time.monotonic() < deadline:
        time.sleep(0.01)
    followers = [threading.Thread(target=call, args=(n,)) for n in ('one', 'two')]
    for thread in followers:
        thread.start()
    deadline = time.monotonic() + 10
    while listing.LISTINGS.waiting() < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    release.set()
    for thread in [leader, *followers]:
        thread.join(10)
    assert len(calls) == 1, 'the two followers did not share the read'
    answers['one'][0]['tags'].append('changed')
    assert answers['two'][0]['tags'] == [] and answers['leader'][0]['tags'] == []


def test_a_listing_after_a_write_does_not_join_one_that_began_before(instance, monkeypatch):
    app, certs, headers = instance
    gate = Gate(certs, monkeypatch)
    results = [None] * 2
    first = _start(app, headers, results, 0)
    assert gate.started.wait(10)
    before = len(gate.reads)
    certs._invalidate_certificate_info_cache(DOMAINS[0])
    second = _start(app, headers, results, 1)
    deadline = time.monotonic() + 10
    while len(gate.reads) < before + 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    gate.release.set()
    first.join(30)
    second.join(30)
    assert len(gate.reads) == 2 * len(DOMAINS), (
        'a listing that started after a write was answered by one that began before it')
    assert results[0][0] == results[1][0] == 200


def test_listings_with_different_scopes_never_share(instance):
    from modules.api import resources_certificates as listing
    assert listing.listing_key(None, 0, {}) != listing.listing_key(['*.share.example'], 0, {})
    assert listing.listing_key(['b.example', 'a.example'], 0, {}) == \
        listing.listing_key(['A.example', 'b.example'], 0, {})


def test_listings_with_different_settings_never_share(instance):
    from modules.api import resources_certificates as listing
    assert listing.listing_key(None, 0, {'renewal_threshold_days': 30}) != \
        listing.listing_key(None, 0, {'renewal_threshold_days': 20})
    assert listing.listing_key(None, 0, {}) != listing.listing_key(None, 1, {})


def test_a_failed_listing_fails_its_followers_and_is_not_kept(instance):
    from modules.api import resources_certificates as listing
    release = threading.Event()
    errors = []

    def broken():
        assert release.wait(10)
        raise RuntimeError('storage went away')

    def follower():
        try:
            listing.LISTINGS.run(('fail',), broken)
        except RuntimeError as e:
            errors.append(str(e))

    leader = threading.Thread(target=follower)
    leader.start()
    deadline = time.monotonic() + 10
    while not listing.LISTINGS.running(('fail',)) and time.monotonic() < deadline:
        time.sleep(0.01)
    joined = threading.Thread(target=follower)
    joined.start()
    deadline = time.monotonic() + 10
    while listing.LISTINGS.waiting() < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    release.set()
    leader.join(10)
    joined.join(10)
    assert errors == ['storage went away', 'storage went away']
    assert listing.LISTINGS.run(('fail',), lambda: ['fresh']) == ['fresh']


def test_listings_that_cannot_share_still_hold_at_most_one_pool(instance):
    from modules.api import resources_certificates as listing
    live, peak, lock = [0], [0], threading.Lock()

    def fetch(item):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.02)
        with lock:
            live[0] -= 1
        return item

    threads = [threading.Thread(target=listing._gather, args=(fetch, list(range(40))))
               for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert peak[0] <= listing.LISTING_CONCURRENCY, (
        f'{peak[0]} reads at once across three listings, against {listing.LISTING_CONCURRENCY}')
