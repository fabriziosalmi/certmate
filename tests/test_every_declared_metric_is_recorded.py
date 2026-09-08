"""A metric that is exported and never incremented is worse than one that is missing.

Six recorder methods on the collector had no caller anywhere in the
application, so five series were exported at every scrape and were permanently
empty:

    certmate_certificate_requests_total
    certmate_certificate_creation_duration_seconds
    certmate_acme_rate_limit_hits_total
    certmate_cache_hits_total
    certmate_cache_misses_total

A missing metric is a gap somebody notices while building a dashboard. A dead
one is a flat line and an alert that never fires, which reads as "nothing is
going wrong" — and `monitoring/prometheus-alerts.yml` had a note omitting four
alerts for exactly that reason.

Two of them mattered operationally. Certificate CREATION incremented nothing at
all while renewal incremented three things, so 'how many did we issue this
week, and how many attempts failed' could not be answered from /metrics. And
`certmate_acme_rate_limit_hits_total` is the first series an operator of ACME
software would alert on.

The seventh recorder, `record_dns_api_call`, was deleted with its metric
instead: CertMate does not talk to a DNS provider's API in this process —
certbot does, in its own subprocess, and the DNS-alias hook is a separate
short-lived process whose counters never reach this registry.

These tests read the collector's own registry rather than mocking it, so they
fail if the wiring is removed AND if a metric is renamed out from under it.
"""
import pytest

from modules.core import metrics as metrics_module
from modules.core.certificates import CertificateManager
from modules.core.utils import DeploymentStatusCache, is_acme_rate_limit

pytestmark = [pytest.mark.unit]

prometheus = pytest.importorskip(
    'prometheus_client', reason='metrics are a no-op without the client library')


def _value(metric, **labels):
    """The current value of one labelled child, or 0.0 if it has none yet."""
    total = 0.0
    for sample_family in metric.collect():
        for sample in sample_family.samples:
            if not sample.name.endswith(('_total', '_count', '_sum')):
                continue
            if all(sample.labels.get(key) == value
                   for key, value in labels.items()):
                if sample.name.endswith('_sum'):
                    continue
                total += sample.value
    return total


@pytest.fixture
def manager(tmp_path):
    """A manager with nothing wired but the metrics path under test."""
    return CertificateManager.__new__(CertificateManager)


# --- issuance: the half that recorded nothing ----------------------------

def test_a_successful_issuance_counts_a_request_and_its_duration(manager):
    before = _value(metrics_module.certificate_requests_total,
                    domain='m1.example.com', status='success')
    before_duration = _value(metrics_module.certificate_creation_duration,
                             dns_provider='cloudflare')

    manager._record_creation_metrics('m1.example.com', 'cloudflare', True, 12.5)

    assert _value(metrics_module.certificate_requests_total,
                  domain='m1.example.com', status='success') == before + 1
    assert _value(metrics_module.certificate_creation_duration,
                  dns_provider='cloudflare') == before_duration + 1


def test_a_failed_issuance_counts_a_failure_and_an_acme_error(manager):
    before = _value(metrics_module.certificate_requests_total,
                    domain='m2.example.com', status='failure')
    before_errors = _value(metrics_module.acme_errors_total,
                           domain='m2.example.com', error_type='RuntimeError')

    manager._record_creation_metrics('m2.example.com', 'route53', False, 3.0,
                                     error=RuntimeError('certbot said no'))

    assert _value(metrics_module.certificate_requests_total,
                  domain='m2.example.com', status='failure') == before + 1
    assert _value(metrics_module.acme_errors_total,
                  domain='m2.example.com',
                  error_type='RuntimeError') == before_errors + 1


def test_an_unknown_provider_is_labelled_rather_than_dropped(manager):
    """A failure early enough that the provider was never resolved still has
    to be counted — that is exactly when issuance is broken."""
    before = _value(metrics_module.certificate_requests_total,
                    dns_provider='unknown', status='failure')

    manager._record_creation_metrics('m3.example.com', None, False, 0.2,
                                     error=ValueError('no provider'))

    assert _value(metrics_module.certificate_requests_total,
                  dns_provider='unknown', status='failure') == before + 1


def test_recording_never_raises(manager):
    """CONTROL. Telemetry must not be the reason an issuance that already
    obtained a certificate is reported as failed."""
    class Hostile:
        def __str__(self):
            raise RuntimeError('even the error is broken')

    manager._record_creation_metrics('m4.example.com', 'cloudflare', False,
                                     1.0, error=Hostile())


# --- the rate limit, which is not just another ACME error ----------------

def test_a_rate_limited_refusal_is_counted_separately(manager):
    before = _value(metrics_module.acme_rate_limit_hits,
                    limit_type='issuance', dns_provider='cloudflare')

    manager._record_creation_metrics(
        'm5.example.com', 'cloudflare', False, 4.0,
        error=RuntimeError(
            'urn:ietf:params:acme:error:rateLimited :: too many certificates '
            '(5) already issued for this exact set of domains'))

    assert _value(metrics_module.acme_rate_limit_hits,
                  limit_type='issuance',
                  dns_provider='cloudflare') == before + 1


def test_a_rate_limited_renewal_is_counted_under_renewal(manager):
    before = _value(metrics_module.acme_rate_limit_hits,
                    limit_type='renewal', dns_provider='azure')

    manager._record_renewal_metrics(
        'm6.example.com', {'dns_provider': 'azure'}, False, 9.0,
        error=RuntimeError('Error creating new order :: too many failed '
                           'authorizations recently'))

    assert _value(metrics_module.acme_rate_limit_hits,
                  limit_type='renewal', dns_provider='azure') == before + 1


def test_an_ordinary_failure_is_not_counted_as_a_rate_limit(manager):
    """CONTROL. If everything counted as a rate limit, the alert built on this
    series would fire on every DNS misconfiguration and be turned off."""
    before = _value(metrics_module.acme_rate_limit_hits,
                    limit_type='issuance', dns_provider='cloudflare')

    manager._record_creation_metrics(
        'm7.example.com', 'cloudflare', False, 2.0,
        error=RuntimeError('DNS problem: NXDOMAIN looking up TXT'))

    assert _value(metrics_module.acme_rate_limit_hits,
                  limit_type='issuance',
                  dns_provider='cloudflare') == before


@pytest.mark.parametrize('reason, expected', [
    ('urn:ietf:params:acme:error:rateLimited', True),
    ('too many certificates (5) already issued', True),
    ('too many failed authorizations recently', True),
    ('too many currently pending authorizations', True),
    ('Error creating new order :: too many new orders recently', True),
    ('DNS problem: NXDOMAIN looking up TXT', False),
    ('parsefail: renewal configuration is broken', False),
    # A DNS provider throttling us is not the CA rate limiting us, and
    # conflating them puts the wrong number in front of the operator.
    ('Cloudflare API error 971: rate limit exceeded', False),
    ('', False),
    (None, False),
])
def test_what_counts_as_a_ca_rate_limit(reason, expected):
    assert is_acme_rate_limit(reason) is expected


def test_the_api_gives_a_rate_limit_its_own_code():
    """The same question, asked by the other caller: an operator reading the
    API response gets a code that says retrying is the wrong move."""
    from modules.core.utils import classify_renewal_error

    message, code = classify_renewal_error(
        'too many certificates already issued for this exact set of domains')

    assert code == 'ACME_RATE_LIMITED'
    assert 'wait' in message.lower()


# --- the cache, counted where the lookup happens -------------------------

def test_a_cache_hit_and_a_cache_miss_are_both_counted():
    cache = DeploymentStatusCache(default_ttl=300)
    before_hits = _value(metrics_module.cache_hits_total)
    before_misses = _value(metrics_module.cache_misses_total)

    assert cache.get('nothing.example.com') is None
    cache.set('something.example.com', {'deployed': True})
    assert cache.get('something.example.com') == {'deployed': True}

    assert _value(metrics_module.cache_misses_total) == before_misses + 1
    assert _value(metrics_module.cache_hits_total) == before_hits + 1


def test_an_expired_entry_is_a_miss_not_a_hit():
    """CONTROL. Counting an expired entry as a hit would make the hit rate say
    the cache is working while every lookup goes to disk."""
    cache = DeploymentStatusCache(default_ttl=300)
    before_hits = _value(metrics_module.cache_hits_total)
    before_misses = _value(metrics_module.cache_misses_total)

    cache.set('stale.example.com', {'deployed': True}, ttl=-1)
    assert cache.get('stale.example.com') is None

    assert _value(metrics_module.cache_hits_total) == before_hits
    assert _value(metrics_module.cache_misses_total) == before_misses + 1


# --- what the module exports -------------------------------------------

def test_the_metric_that_cannot_be_recorded_is_not_exported():
    """It lived in this module, declared and never incremented, and the only
    place it could be incremented from is a subprocess whose registry never
    reaches this one. Removed rather than exported empty."""
    assert not hasattr(metrics_module, 'dns_provider_api_calls')
    assert not hasattr(metrics_module.metrics_collector, 'record_dns_api_call')


def test_every_recorder_has_a_caller_in_the_application():
    """THE regression, as a property rather than a list.

    Every `record_*` method on the collector must be called from somewhere that
    is not metrics.py itself. This is what would have caught the original
    defect, and it fails the day someone adds a metric and forgets to wire it.
    """
    import inspect
    import pathlib
    import re

    collector = type(metrics_module.metrics_collector)
    recorders = [name for name, _ in inspect.getmembers(collector, inspect.isfunction)
                 if name.startswith('record_')]
    assert recorders, 'no recorders found — this test is not looking at anything'

    root = pathlib.Path(__file__).resolve().parent.parent
    application = '\n'.join(
        path.read_text(encoding='utf-8')
        for path in sorted(root.glob('modules/**/*.py'))
        if path.name != 'metrics.py')

    unwired = [name for name in recorders
               if not re.search(rf'\.{name}\s*\(', application)]
    assert not unwired, (
        'these metrics are declared and exported but nothing in the '
        f'application increments them: {unwired}. Wire them where the outcome '
        'is known, or delete them — a series that is always zero reads as '
        '"nothing is going wrong".')
