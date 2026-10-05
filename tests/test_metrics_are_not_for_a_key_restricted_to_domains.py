"""`/metrics` gives a key restricted with `allowed_domains` its own domains' series.

The series are about the whole instance: every managed domain is a label, and
the rest are its totals. A restricted key gets the series whose `domain` its
scope covers, under the rule every certificate route applies (the scope has to
cover every name the certificate covers), and nothing else: a total of what it
may not see is still something about it. A key without the restriction gets
everything, as before.
"""
import json
import os
import secrets

import pytest

from tests.contract_world import write_certificate

pytestmark = [pytest.mark.unit]

# Names no other test uses. The registry is one per process, so in the full
# suite it also holds the counters other tests left for their own domains, and
# a scope shared with them would let those through here.
SCOPE = ['*.metrics-team.example']
MINE = 'app.metrics-team.example'
THEIRS = 'shop.metrics-other.example'
MIXED = 'api.metrics-team.example'  # filed in scope, and covers a name outside it
INSTANCE_WIDE = ('certmate_certificates_total', 'certmate_domains_total',
                 'certmate_certificates_by_provider', 'certmate_certificates_by_status',
                 'certmate_dns_provider_accounts', 'certmate_application_uptime_seconds',
                 'certmate_version_info', 'certmate_issuance_queue_depth',
                 'process_', 'python_')


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    from modules.core import metrics
    tmp = tmp_path_factory.mktemp('metrics-scope')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        sans = {MINE: ['www.metrics-team.example'], THEIRS: [], MIXED: ['api.metrics-other.example']}
        for name, extra in sans.items():
            write_certificate(tmp / 'certs' / name, name, extra)
            (tmp / 'certs' / name / 'metadata.json').write_text(json.dumps(
                {'domain': name, 'san_domains': extra, 'dns_provider': 'cloudflare'}), encoding='utf-8')
        settings = container.managers['settings']
        current = settings.load_settings()
        current['domains'] = [{'domain': name, 'dns_provider': 'cloudflare'} for name in sans]
        settings.save_settings(current)
        # A counter for each, as an issuance would leave it.
        for name in sans:
            metrics.certificate_requests_total.labels(domain=name, dns_provider='cloudflare', status='success').inc()
        headers = {}
        for name, scope in (('restricted', SCOPE), ('viewer', None)):
            ok, key = container.managers['auth'].create_api_key(name, role='viewer', allowed_domains=scope)
            assert ok, key
            headers[name] = {'Authorization': f"Bearer {key['token']}"}
        yield app.test_client(), headers


def _scrape(instance, who):
    """The collector gathers at most once per interval, for the whole process:
    asked fresh here, and left fresh for whichever test scrapes next."""
    from modules.core import metrics
    client, headers = instance
    metrics.metrics_collector.last_collection = 0
    try:
        response = client.get('/metrics', headers=headers[who])
    finally:
        metrics.metrics_collector.last_collection = 0
    assert response.status_code == 200, response.get_data(as_text=True)[:200]
    return response.get_data(as_text=True)


def test_a_restricted_key_gets_its_own_domains_series(instance):
    text = _scrape(instance, 'restricted')
    assert f'certmate_certificate_expiry_days{{dns_provider="cloudflare",domain="{MINE}"}}' in text
    assert f'domain="{MINE}"' in next(line for line in text.splitlines()
                                      if line.startswith('certmate_certificate_requests_total'))


def test_it_gets_no_series_about_another_domain(instance):
    text = _scrape(instance, 'restricted')
    assert THEIRS not in text
    assert 'metrics-other.example' not in text


def test_a_certificate_that_also_covers_another_name_is_not_described_to_it(instance):
    """The rule of the certificate routes: every name, not only the one it is filed under."""
    assert MIXED not in _scrape(instance, 'restricted')


def test_it_gets_nothing_about_the_instance_as_a_whole(instance):
    text = _scrape(instance, 'restricted')
    names = {line.split('{')[0].split(' ')[0] for line in text.splitlines()
             if line and not line.startswith('#')}
    assert names, 'nothing at all was answered'
    offending = sorted(n for n in names if n.startswith(INSTANCE_WIDE))
    assert not offending, offending
    for line in text.splitlines():
        if line and not line.startswith('#'):
            assert 'domain="' in line, f'a series with no domain: {line}'


def test_what_it_gets_is_still_prometheus_text(instance):
    from prometheus_client.parser import text_string_to_metric_families
    families = list(text_string_to_metric_families(_scrape(instance, 'restricted')))
    by_name = {family.name: family for family in families}
    assert by_name['certmate_certificate_expiry_days'].type == 'gauge'
    assert by_name['certmate_certificate_requests'].type == 'counter'
    assert all(sample.labels['domain'] == MINE for family in families for sample in family.samples)


def test_a_key_without_the_restriction_gets_everything(instance):
    """CONTROL: the other domains, the mixed certificate and the totals are there to be left out."""
    text = _scrape(instance, 'viewer')
    for name in (MINE, THEIRS, MIXED):
        assert f'domain="{name}"' in text
    assert 'certmate_certificates_total' in text
    assert 'certmate_application_uptime_seconds' in text
