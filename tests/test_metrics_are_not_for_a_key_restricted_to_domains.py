"""A key restricted with `allowed_domains` does not get `/metrics`.

The series are about the whole instance: every managed domain is a label. It
is the rule the client-certificate and backup routes apply
(`domain_restricted_refusal`). A view limited to the key's domains would
replace the refusal, and is a change of its own.
"""
import os
import secrets

import pytest

from tests.contract_world import write_certificate

pytestmark = [pytest.mark.unit]

THEIRS = 'shop.other.example'


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
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
        write_certificate(tmp / 'certs' / THEIRS, THEIRS)
        settings = container.managers['settings']
        current = settings.load_settings()
        current['domains'] = [{'domain': THEIRS, 'dns_provider': 'cloudflare'}]
        settings.save_settings(current)
        headers = {}
        for name, scope in (('restricted', ['*.team.example']), ('viewer', None)):
            ok, key = container.managers['auth'].create_api_key(name, role='viewer', allowed_domains=scope)
            assert ok, key
            headers[name] = {'Authorization': f"Bearer {key['token']}"}
        yield app.test_client(), headers, container


def test_a_restricted_key_is_refused(instance):
    client, headers, container = instance
    response = client.get('/metrics', headers=headers['restricted'])
    assert response.status_code == 403, response.get_data(as_text=True)[:200]
    assert response.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'
    assert THEIRS not in response.get_data(as_text=True)
    entries = container.managers['audit'].get_recent_entries(limit=20)
    assert any(e.get('status') == 'denied' and e.get('resource_type') == 'metrics' for e in entries)


def test_a_viewer_key_without_the_restriction_still_scrapes(instance):
    """CONTROL: and what it scrapes does name the domain, which is the premise."""
    from modules.core import metrics
    client, headers, _container = instance
    # The collector gathers at most once per interval, for the whole process:
    # asked fresh here, and left fresh for whichever test scrapes next.
    metrics.metrics_collector.last_collection = 0
    try:
        response = client.get('/metrics', headers=headers['viewer'])
    finally:
        metrics.metrics_collector.last_collection = 0
    assert response.status_code == 200
    assert f'domain="{THEIRS}"' in response.get_data(as_text=True)
