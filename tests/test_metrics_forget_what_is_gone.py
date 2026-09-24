"""Two metrics defects found by the certmate-website session.

**The version metric never worked.** `certmate_build_info` was declared as
``Info(name, doc, ['version', 'python_version'])`` — an Info WITH labelnames is
a family, and calling ``.info()`` on the family parent raises AttributeError on
every prometheus_client this project has ever pinned. The caller caught it and
built a Gauge in the handler, so the Gauge was always the metric that carried
the value while `/metrics` exported a permanently sample-less
`certmate_build_info_info` stanza. The handler was not defending against a
version difference; it *was* the code path.

**Deleted certificates never went away.** The per-domain gauges are only ever
``.labels(...).set(...)``. A Gauge keeps its last value, and a deleted domain
simply stops being collected, so its series freezes instead of disappearing.
`monitoring/prometheus-alerts.yml` alerts on
``min by (domain) (certmate_certificate_expiry_days)``: a certificate deleted
while expiring pins a low value and alerts for ever, and one deleted while
healthy hides its own disappearance behind a stale `valid`.
"""
import pytest

from modules.core import metrics as M

pytestmark = [pytest.mark.unit]


def _render():
    return M.generate_latest().decode('utf-8')


CERT_DIR = None


def _series(text, name):
    return sorted(line for line in text.splitlines()
                  if line.startswith(name + '{'))


@pytest.fixture
def collector(tmp_path):
    """A collector plus a settings/cert_dir context it can be driven with.

    `cert_dir` must be a real directory: `_collect_certificate_metrics`
    returns immediately when any of settings/cert_dir/get_certificate_info is
    falsy, so a None here makes every assertion below pass for the wrong
    reason.
    """
    global CERT_DIR
    CERT_DIR = tmp_path
    instance = M.CertMateMetricsCollector()
    for gauge in (M.certificate_expiry_days, M.certificate_next_renewal,
                  M.certificate_last_renewal):
        gauge.clear()
    return instance


def _context(domains, infos):
    return {
        'settings': {'domains': domains, 'renewal_threshold_days': 30},
        'cert_dir': CERT_DIR,
        'get_certificate_info': lambda domain: infos.get(domain),
    }


def _info(days_left):
    return {'exists': True, 'days_left': days_left, 'dns_provider': 'cloudflare'}


# --- the version metric ---------------------------------------------------

def test_the_version_metric_carries_a_sample():
    """THE regression. Before, `certmate_build_info_info` was exported with a
    HELP and a TYPE and no samples at all."""
    M.CertMateMetricsCollector()

    lines = _series(_render(), 'certmate_version_info')

    assert lines, 'certmate_version_info has no samples'
    assert 'version=' in lines[0] and 'python_version=' in lines[0]


def test_the_metric_that_never_worked_is_gone():
    """Keeping both would leave the dead one exported next to the live one,
    which is how it survived three releases."""
    text = _render()

    assert 'certmate_build_info' not in text


def test_no_handler_hides_the_version_metric_failing():
    """CONTROL on the fix's shape: if a try/except comes back around this
    call, the next breakage is swallowed exactly as this one was."""
    import inspect

    source = inspect.getsource(M.CertMateMetricsCollector.__init__)

    assert 'application_version.labels(' in source
    assert 'except' not in source.split('application_version.labels')[0][-400:]


# --- stale per-domain series ----------------------------------------------

def test_a_deleted_certificate_stops_being_reported(collector):
    """THE regression. `b.example.com` is collected, then deleted; its series
    must not survive the next pass."""
    both = _context(['a.example.com', 'b.example.com'],
                    {'a.example.com': _info(40), 'b.example.com': _info(3)})
    collector._collect_certificate_metrics(both)

    assert len(_series(_render(), 'certmate_certificate_expiry_days')) == 2

    only_a = _context(['a.example.com'], {'a.example.com': _info(40)})
    collector._collect_certificate_metrics(only_a)

    remaining = _series(_render(), 'certmate_certificate_expiry_days')
    assert len(remaining) == 1
    assert 'a.example.com' in remaining[0]
    assert 'b.example.com' not in _render()


def test_the_survivor_keeps_its_value(collector):
    """CONTROL. A fix that cleared everything each pass would also pass the
    test above — and would empty /metrics between scrapes."""
    collector._collect_certificate_metrics(
        _context(['a.example.com', 'b.example.com'],
                 {'a.example.com': _info(40), 'b.example.com': _info(3)}))
    collector._collect_certificate_metrics(
        _context(['a.example.com'], {'a.example.com': _info(40)}))

    line = _series(_render(), 'certmate_certificate_expiry_days')[0]

    assert line.endswith(' 40.0')


def test_all_three_per_domain_gauges_are_forgotten(collector):
    """Expiry was the one in the alert rules, but a stale next-renewal
    timestamp is just as wrong and last-renewal only cleaned itself when the
    domain was still being collected."""
    collector._collect_certificate_metrics(
        _context(['gone.example.com'],
                 {'gone.example.com': dict(_info(10), renewed_at='2026-01-01T00:00:00Z')}))

    assert 'gone.example.com' in _render()

    collector._collect_certificate_metrics(_context([], {}))

    assert 'gone.example.com' not in _render()


def test_a_collection_that_finds_nothing_does_not_wipe_a_live_registry(collector):
    """CONTROL on the failure mode this must not introduce: the removal is
    driven by what THIS collector recorded, so an unrelated series set by
    something else is untouched."""
    collector._collect_certificate_metrics(
        _context(['a.example.com'], {'a.example.com': _info(40)}))
    M.certificate_expiry_days.labels(domain='other.example.com',
                                     dns_provider='manual').set(7)

    collector._collect_certificate_metrics(_context([], {}))

    assert 'other.example.com' in _render()
    assert 'a.example.com' not in _render()
