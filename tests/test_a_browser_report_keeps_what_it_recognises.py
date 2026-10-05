"""A browser's deployment report is kept in the form the dashboard sends it.

The dashboard of whoever is signed in reports that it could reach a domain,
and the read-only role is enough to send one. The report is written into the
certificate's metadata and shown to every other user. So its three free
fields are kept only when they are what they claim to be: `method` and
`source` a short lower-case label, `checked_at` an ISO date-time. Anything
else is replaced by what the dashboard itself would have sent.
"""
import json
import os
import secrets

import pytest

from tests.contract_world import write_certificate

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.team.example'


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('browser-report')
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
        write_certificate(tmp / 'certs' / DOMAIN, DOMAIN)
        (tmp / 'certs' / DOMAIN / 'metadata.json').write_text(
            json.dumps({'domain': DOMAIN, 'san_domains': [], 'dns_provider': 'cloudflare'}), encoding='utf-8')
        ok, key = container.managers['auth'].create_api_key('reader', role='viewer')
        assert ok, key
        yield app.test_client(), {'Authorization': f"Bearer {key['token']}"}, tmp / 'certs' / DOMAIN / 'metadata.json'


def _report(instance, **fields):
    client, viewer, metadata = instance
    response = client.post('/api/certificates/deployment-status/browser', headers=viewer,
                           json={'reports': [{'domain': DOMAIN, 'reachable': True, **fields}]})
    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.get_json()['updated'] == [DOMAIN]
    return json.loads(metadata.read_text(encoding='utf-8'))['deployment_status']['browser']


def test_what_the_dashboard_sends_is_kept_as_sent(instance):
    """CONTROL: the three values dashboard.js sends, and the instant in the form it writes it."""
    kept = _report(instance, method='browser-fallback', source='browser',
                   checked_at='2026-10-05T12:34:56.789Z')
    assert kept == {'reachable': True, 'checked_at': '2026-10-05T12:34:56.789Z',
                    'method': 'browser-fallback', 'source': 'browser'}
    assert _report(instance, method='unavailable')['method'] == 'unavailable'


@pytest.mark.parametrize('method', [
    '<img src=x onerror=alert(1)>', 'Reachable. Call the helpdesk on 555-0100', 'a' * 33,
    'UPPER', 'with space', '-leading', '', 'caf\u00e9',
    # A line break at the very end: `$` in the pattern would let it through.
    'browser-fallback\n',
])
def test_a_method_that_is_not_a_short_label_becomes_the_default(instance, method):
    assert _report(instance, method=method)['method'] == 'browser-fallback'


@pytest.mark.parametrize('source', ['x' * 5000, 'browser\nadmin', 'browser\n'])
def test_a_source_that_is_not_a_short_label_becomes_the_default(instance, source):
    assert _report(instance, source=source)['source'] == 'browser'


@pytest.mark.parametrize('checked_at', ['yesterday', '2026-13-40T00:00:00Z', 'x' * 4000,
                                        '2026-10-05T12:00:00Z; drop'])
def test_an_instant_that_is_not_one_becomes_the_servers_own(instance, checked_at):
    from datetime import datetime
    kept = _report(instance, checked_at=checked_at)['checked_at']
    assert kept != checked_at
    datetime.fromisoformat(kept.replace('Z', '+00:00'))


@pytest.mark.parametrize('field,value', [('method', 7), ('method', None), ('method', ['list']),
                                         ('source', {'a': 1}), ('checked_at', 12)])
def test_a_value_that_is_not_text_is_refused_by_the_routes_model(instance, field, value):
    """Before the recorder is reached, and nothing is written."""
    client, viewer, metadata = instance
    before = metadata.read_bytes()
    response = client.post('/api/certificates/deployment-status/browser', headers=viewer,
                           json={'reports': [{'domain': DOMAIN, 'reachable': True, field: value}]})
    assert response.status_code == 400, response.get_data(as_text=True)
    assert metadata.read_bytes() == before


def test_the_recorder_does_not_rely_on_the_model(tmp_path):
    """Called directly, as any other caller of it would: the same rule."""
    from unittest import mock

    from modules.core.certificates import CertificateManager
    manager = CertificateManager(tmp_path, mock.MagicMock(), mock.MagicMock())
    (tmp_path / DOMAIN).mkdir()
    kept = manager.record_browser_deployment_status(
        DOMAIN, {'reachable': 1, 'method': 7, 'source': {'a': 1}, 'checked_at': 12})['browser']
    assert kept['method'] == 'browser-fallback' and kept['source'] == 'browser'
    assert kept['reachable'] is True and isinstance(kept['checked_at'], str)


def test_the_record_stays_small_whatever_is_sent(instance):
    _client, _viewer, metadata = instance
    _report(instance, method='m' * 200000, source='s' * 200000, checked_at='c' * 200000)
    assert metadata.stat().st_size < 2000
