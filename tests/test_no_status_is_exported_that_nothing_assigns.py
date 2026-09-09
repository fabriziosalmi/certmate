"""A gauge that is always zero is not a metric, it is a promise nobody keeps.

`certmate_certificates_by_status` was exported with five labels and the
collector assigned four. Every scrape, for every deployment, carried

    certmate_certificates_by_status{status="renewal_failed"} 0

An operator building a dashboard finds that series, writes
`certmate_certificates_by_status{status="renewal_failed"} > 0`, and has an
alert that can never fire — which reads, for as long as nobody checks, as "no
renewal has ever failed here". That is worse than the series not existing: an
absent series makes the rule visibly broken, or is caught by `absent()`.

It could not be assigned either, and that is the substance rather than an
oversight: it is not a state a certificate is IN. A certificate whose renewal
failed is still valid, or expiring soon, or expired — the other four partition
the set, and this one overlaps all of them. The failure is an EVENT, and it is
already counted as one:

    certmate_certificate_renewals_total{status="failure"}

which `_record_renewal_metrics` increments from the renewal sweep and which the
shipped `CertMateRenewalsFailing` rule alerts on with `increase(...)` over 6h —
what matters being that renewals are failing now, not that one ever did.

So the label is removed. This file pins both halves: it is gone, and what it
was meant to tell you is somewhere real.
"""
import pytest

from modules.core import metrics

pytestmark = [pytest.mark.unit]

EXPECTED = {'valid', 'expiring_soon', 'expired', 'missing'}


def _exported_statuses():
    """The label values actually present in the registry's output."""
    from prometheus_client import generate_latest

    body = generate_latest(metrics.REGISTRY).decode('utf-8') if hasattr(
        metrics, 'REGISTRY') else generate_latest().decode('utf-8')
    found = set()
    for line in body.splitlines():
        if line.startswith('certmate_certificates_by_status{'):
            found.add(line.split('status="', 1)[1].split('"', 1)[0])
    return found


@pytest.fixture
def collected(tmp_path):
    """One collection over a single valid certificate."""
    metrics.metrics_collector.last_collection = 0
    metrics.metrics_collector.collect_all_metrics({
        'settings': {'domains': [{'domain': 'a.example.com'}],
                     'renewal_threshold_days': 30},
        'cert_dir': tmp_path,
        'get_certificate_info': lambda domain: {
            'exists': True, 'days_left': 60, 'dns_provider': 'cloudflare'},
    })
    return _exported_statuses()


# --- THE regression -------------------------------------------------------

def test_no_status_is_exported_that_the_collector_cannot_assign(collected):
    assert 'renewal_failed' not in collected, (
        'certmate_certificates_by_status still exports a label the collector '
        'never assigns, so an alert written on it can never fire')


def test_the_four_real_statuses_are_still_exported(collected):
    """CONTROL. Removing the fifth must not have removed the metric: the
    shipped dashboard and the CertMateCertificatesExpired rule read three of
    these."""
    assert EXPECTED <= collected, f'missing: {sorted(EXPECTED - collected)}'


def test_the_source_does_not_carry_the_dead_label():
    """The collector builds its counts from a literal dict, and a key put back
    there is exported whether or not any branch can produce it."""
    import inspect

    source = inspect.getsource(
        metrics.CertMateMetricsCollector._collect_certificate_metrics)
    counts = source[source.index('status_counts = {'):]
    counts = counts[:counts.index('}')]

    assert 'renewal_failed' not in counts


# --- the four assignable statuses partition the certificates -------------

@pytest.mark.parametrize('days_left,expected', [
    (60, 'valid'),
    (10, 'expiring_soon'),
    (-1, 'expired'),
    (None, 'missing'),
])
def test_each_certificate_lands_in_exactly_one(tmp_path, days_left, expected):
    """Why a fifth could not be assigned: the branch picks one per domain, and
    'renewal_failed' is not an alternative to any of these — a certificate
    whose renewal failed is still in one of the four."""
    from prometheus_client import generate_latest

    metrics.metrics_collector.last_collection = 0
    metrics.metrics_collector.collect_all_metrics({
        'settings': {'domains': [{'domain': 'only.example.com'}],
                     'renewal_threshold_days': 30},
        'cert_dir': tmp_path,
        'get_certificate_info': lambda domain: {
            'exists': True, 'days_left': days_left, 'dns_provider': 'cf'},
    })

    body = generate_latest().decode('utf-8')
    counts = {}
    for line in body.splitlines():
        if line.startswith('certmate_certificates_by_status{'):
            status = line.split('status="', 1)[1].split('"', 1)[0]
            counts[status] = float(line.rsplit(' ', 1)[1])

    assert counts[expected] == 1.0
    assert sum(counts.values()) == 1.0


# --- what it was meant to tell you, where it really is -------------------

def test_renewal_failures_are_counted_somewhere_real():
    """The replacement has to exist, or this change loses information."""
    from prometheus_client import generate_latest

    metrics.metrics_collector.record_certificate_renewal(
        'fails.example.com', 'cloudflare', success=False)

    body = generate_latest().decode('utf-8')
    assert any('certmate_certificate_renewals_total{' in line
               and 'status="failure"' in line
               and 'fails.example.com' in line
               for line in body.splitlines()), (
        'nothing records a failed renewal, so removing the status label would '
        'lose the information rather than move it')


def test_the_renewal_sweep_is_what_records_it():
    """CONTROL against the counter going the way of the label: it is recorded
    from one place, and if that call goes the metric is silently empty again."""
    import inspect

    from modules.core.certificates import CertificateManager

    source = inspect.getsource(CertificateManager._record_renewal_metrics)

    assert 'record_certificate_renewal(' in source


def test_the_shipped_alert_uses_the_counter():
    """The rule an operator would otherwise have written against the constant
    zero. It ships, and it reads the metric that moves."""
    import pathlib

    rules = (pathlib.Path(__file__).resolve().parent.parent
             / 'monitoring' / 'prometheus-alerts.yml').read_text(encoding='utf-8')

    assert 'certmate_certificate_renewals_total{status="failure"}' in rules
    assert 'renewal_failed' not in rules


def test_the_dashboard_no_longer_styles_a_series_that_cannot_exist():
    """A field override for a series nothing emits is a reader's evidence that
    the series should be there."""
    import pathlib

    dashboard = (pathlib.Path(__file__).resolve().parent.parent
                 / 'monitoring' / 'grafana-dashboard.json').read_text(encoding='utf-8')

    assert 'renewal_failed' not in dashboard
