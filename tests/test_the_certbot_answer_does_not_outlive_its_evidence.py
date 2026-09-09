"""Readiness re-checks certbot instead of freezing the answer it got at boot.

`probe` ran `certbot --version` once per process and recorded the result; every
later caller got that recording, for the life of the process. Both directions
of that are wrong, and both are quiet:

* a transient failure at startup — a filesystem still settling, a fork refused
  under memory pressure — records FAILED, and /health/ready then returns 503
  "until this is fixed", which for a running container means until somebody
  restarts it. Under an orchestrator that is a restart loop rolling the same
  dice on every attempt;
* a certbot that breaks AFTER startup — a volume remounted, a dependency
  changed inside the container, a venv half-upgraded — never turns readiness
  red. The renewal sweep will fail per domain and publish certificate_failed,
  so it is not invisible; but the endpoint an orchestrator uses to decide
  whether to send traffic goes on saying yes while nothing can be issued.

The answer now has a TTL. That is what makes re-checking affordable: readiness
is scraped every few seconds and running certbot that often would be its own
problem, so at most one probe per TTL and the recorded answer in between.
"""
import pytest

from modules.core import issuance_readiness

pytestmark = [pytest.mark.unit]


class _Certbot:
    """A shell executor standing in for certbot, whose answer the test moves."""

    produces_artifacts = True

    def __init__(self, working=True):
        self.working = working
        self.runs = 0

    def run(self, cmd, timeout=None):
        self.runs += 1

        class _Result:
            def __init__(self, ok):
                self.returncode = 0 if ok else 1
                self.stdout = 'certbot 2.10.0' if ok else ''
                self.stderr = '' if ok else 'ImportError: cannot import X509Req'
        return _Result(self.working)


@pytest.fixture(autouse=True)
def clean_module_state():
    issuance_readiness.reset()
    yield
    issuance_readiness.reset()


# --- THE regression, both directions -------------------------------------

def test_a_transient_failure_at_startup_does_not_last_forever(monkeypatch):
    """The instance came up while certbot could not run, and then it could."""
    monkeypatch.setenv('CERTMATE_CERTBOT_PROBE_TTL', '30')
    certbot = _Certbot(working=False)

    first = issuance_readiness.probe(certbot)
    assert first['state'] == issuance_readiness.FAILED
    assert not issuance_readiness.is_ready(first)

    certbot.working = True
    _expire(monkeypatch)

    second = issuance_readiness.probe(certbot)
    assert second['state'] == issuance_readiness.OK
    assert issuance_readiness.is_ready(second)


def test_a_certbot_that_breaks_after_startup_stops_being_ready(monkeypatch):
    """The direction that matters more: readiness said yes for the life of the
    process while nothing could be issued."""
    monkeypatch.setenv('CERTMATE_CERTBOT_PROBE_TTL', '30')
    certbot = _Certbot(working=True)

    assert issuance_readiness.probe(certbot)['state'] == issuance_readiness.OK

    certbot.working = False
    _expire(monkeypatch)

    after = issuance_readiness.probe(certbot)
    assert after['state'] == issuance_readiness.FAILED
    assert not issuance_readiness.is_ready(after)
    assert 'X509Req' in after['error']


def _expire(monkeypatch):
    """Move the clock past the TTL rather than sleeping through it."""
    import time as _time
    now = _time.monotonic()
    monkeypatch.setattr(issuance_readiness.time, 'monotonic',
                        lambda: now + issuance_readiness.probe_ttl_seconds() + 1)


# --- the TTL is what keeps re-checking affordable ------------------------

def test_repeated_calls_inside_the_ttl_run_certbot_once():
    """CONTROL. A readiness probe every few seconds must not mean certbot every
    few seconds — that would be a worse problem than the one being fixed."""
    certbot = _Certbot()

    for _ in range(20):
        issuance_readiness.probe(certbot)

    assert certbot.runs == 1


def test_force_still_bypasses_the_ttl():
    certbot = _Certbot()
    issuance_readiness.probe(certbot)

    issuance_readiness.probe(certbot, force=True)

    assert certbot.runs == 2


@pytest.mark.parametrize('value,expected', [
    ('600', 600.0),
    ('1', 30.0),          # clamped up: "probe on every scrape" is not a setting
    ('99999', 3600.0),    # clamped down: "never re-probe" is the old defect
    ('not-a-number', 300.0),
    ('', 300.0),
])
def test_the_ttl_is_clamped_not_obeyed(monkeypatch, value, expected):
    monkeypatch.setenv('CERTMATE_CERTBOT_PROBE_TTL', value)

    assert issuance_readiness.probe_ttl_seconds() == expected


def test_two_threads_arriving_together_probe_once():
    """CONTROL for the lock: an expired answer and a burst of scrapes should
    run certbot once between them."""
    import threading

    certbot = _Certbot()
    start = threading.Barrier(8)

    def scrape():
        start.wait(timeout=5)
        issuance_readiness.probe(certbot)

    threads = [threading.Thread(target=scrape) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert certbot.runs == 1


# --- what the endpoints read ---------------------------------------------

def test_a_probe_that_did_not_run_is_not_a_failure():
    """CONTROL, unchanged behaviour: `skipped` and `unknown` are absence of
    evidence. Reporting them as failure would flip every test app and every
    startup window out of rotation."""
    class _Mock:
        produces_artifacts = False

        def run(self, *args, **kwargs):  # pragma: no cover - never called
            raise AssertionError('a mock executor must not be probed')

    status = issuance_readiness.probe(_Mock())

    assert status['state'] == issuance_readiness.SKIPPED
    assert issuance_readiness.is_ready(status)
    assert issuance_readiness.is_ready({'state': issuance_readiness.UNKNOWN})


def test_the_routes_ask_for_a_current_answer():
    """Both /health and /health/ready used to read managers['issuance_status'],
    the dict written once at startup — so a TTL inside the probe would have
    changed nothing for the endpoint an orchestrator actually calls."""
    import inspect

    from modules.web import misc_routes

    source = inspect.getsource(misc_routes.register_misc_routes)
    assert source.count('_current_issuance_status(managers)') >= 2, (
        'the health and readiness routes are not both asking for a current '
        'answer')
    helper = source[source.index('def _current_issuance_status'):]
    assert 'issuance_readiness.probe(' in helper
    assert "managers['issuance_status'] = status" in helper, (
        'the refreshed answer is not written back, so anything else reading '
        'that key still sees the startup snapshot')
