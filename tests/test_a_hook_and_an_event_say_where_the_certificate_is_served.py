"""Hooks, webhook targets and events say where a certificate is served (#854).

Every certificate answer carries `host` since API contract 2.59 (#1364). What
runs after an issuance or a renewal learns it too: a deploy hook from
``CERTMATE_HOST``, a webhook target from ``{{host}}``, and every event about a
server certificate from ``host`` in its payload, which is what notifications
and the event stream deliver. ``CERTMATE_DOMAIN`` and ``domain`` stay the
certificate's name, so a hook written for them does what it did.
"""

import json
from unittest.mock import MagicMock

import pytest

from modules.core.deploy_target_webhook import WebhookTarget, validate_webhook_target
from modules.core.deployer import DeployManager
from modules.core.domain_paths import certificate_dir
from modules.core.events import EventBus, with_certificate_host
from modules.core.shell import MockShellExecutor
from modules.core.utils import certificate_host
from tests import test_an_ip_certificate_is_created_and_renewed_through_the_api as _ip_api
from tests.tls_support import make_cert, pem

pytestmark = [pytest.mark.unit]

# The IP-certificate API module's application: a certbot that writes what
# Let's Encrypt issues for an address.
instance = _ip_api.instance

NAME = 'internal.example.net'
HOST = 'example.com'


def _on_disk(cert_dir, name, metadata=None):
    directory = certificate_dir(cert_dir, name)
    directory.mkdir(parents=True, exist_ok=True)
    leaf, _key = make_cert(name)
    for filename in ('cert.pem', 'fullchain.pem', 'chain.pem'):
        (directory / filename).write_bytes(pem(leaf))
    if metadata is not None:
        (directory / 'metadata.json').write_text(json.dumps({'domain': name, **metadata}))
    return directory


# --------------------------------------------------------------------------- #
# A deploy hook
# --------------------------------------------------------------------------- #

def _hook_env(cert_dir, name):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0, stdout='')
    manager = DeployManager(settings_manager=MagicMock(), shell_executor=shell,
                            audit_logger=MagicMock(), event_bus=MagicMock(),
                            cert_dir=cert_dir, data_dir=str(cert_dir.parent / 'data'))
    hook = {'id': 'h', 'name': 'probe', 'command': 'true', 'enabled': True,
            'timeout': 10, 'on_events': ['renewed']}
    manager._run_hook(hook, name, 'renewed')
    return shell.envs_executed[-1]


@pytest.mark.parametrize('name,metadata,host', [
    (NAME, {'host': HOST}, HOST),
    ('ip-203-0-113-5', {}, '203.0.113.5'),
    ('shop.example.com', {}, 'shop.example.com'),
    ('shop.example.com', None, 'shop.example.com'),   # no metadata at all
])
def test_a_hook_is_told_where_the_certificate_is_served(tmp_path, name, metadata, host):
    _on_disk(tmp_path / 'certs', name, metadata)
    env = _hook_env(tmp_path / 'certs', name)
    assert (env['CERTMATE_DOMAIN'], env['CERTMATE_HOST']) == (name, host)


# --------------------------------------------------------------------------- #
# A webhook target
# --------------------------------------------------------------------------- #

TARGET = {'id': 't', 'name': 'lb', 'type': 'webhook', 'enabled': True, 'domains': [NAME],
          'config': {'url': 'https://lb.example.net/cert',
                     'payload_template': '{"name": "{{domain}}", "host": "{{host}}"}'}}


def test_a_webhook_target_may_name_the_host():
    assert validate_webhook_target(TARGET) == (True, None)


def test_a_webhook_target_is_given_the_host(tmp_path):
    directory = _on_disk(tmp_path, NAME, {'host': HOST})
    variables = WebhookTarget(TARGET)._variables(lambda f: (directory / f).read_bytes(), NAME, 'renewed')
    assert (variables['domain'], variables['host']) == (NAME, HOST)


def test_a_webhook_target_without_metadata_is_given_the_name(tmp_path):
    directory = _on_disk(tmp_path, 'shop.example.com')
    variables = WebhookTarget(TARGET)._variables(
        lambda f: (directory / f).read_bytes(), 'shop.example.com', 'renewed')
    assert variables['host'] == 'shop.example.com'


def test_the_preview_shows_the_host_too():
    body = json.loads(WebhookTarget(TARGET).preview(domain='app.example.com')['body'])
    assert body == {'name': 'app.example.com', 'host': 'app.example.com'}


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #

def _published(event, data, host_of=lambda name: {NAME: HOST}.get(name) or certificate_host(name)):
    bus = EventBus(workers=1)
    bus.set_enricher(with_certificate_host(host_of))
    stream = bus.subscribe()
    try:
        bus.publish(event, data)
        return stream.get(timeout=5)['data']
    finally:
        bus.stop(timeout=5)


@pytest.mark.parametrize('event', ['certificate_created', 'certificate_renewed', 'certificate_failed',
                                   'certificate_expiring', 'certificate_deployed',
                                   'certificate_deploy_incomplete', 'certificate_deleted',
                                   'deploy_hook_failed'])
def test_an_event_about_a_server_certificate_says_where_it_is_served(event):
    assert _published(event, {'domain': NAME}) == {'domain': NAME, 'host': HOST}


def test_an_event_that_names_its_host_keeps_it():
    assert _published('certificate_created', {'domain': NAME, 'host': 'other.example.com'})['host'] \
        == 'other.example.com'


@pytest.mark.parametrize('event,data', [
    ('certificate_revoked', {'domain': 'laptop-01', 'resource_type': 'client_certificate'}),
    ('domain_expiring', {'domain': 'example.com'}),
    ('settings_saved', {}),
])
def test_other_events_are_left_as_they_are(event, data):
    assert _published(event, data) == data


def test_the_application_announces_where_a_new_certificate_is_served(instance):
    client, container, _certbot, _certs = instance
    stream = container.managers['events'].subscribe()
    try:
        response = client.post('/api/certificates/create', json={'domain': '1.0.0.3'})
        assert response.status_code == 201, response.get_json()
        seen = []
        while not stream.empty():
            seen.append(stream.get_nowait())
    finally:
        container.managers['events'].unsubscribe(stream)
    created = [m['data'] for m in seen if m['event'] == 'certificate_created']
    assert [(d['domain'], d['host']) for d in created] == [('ip-1-0-0-3', '1.0.0.3')]


@pytest.mark.parametrize('data', [{}, {'domain': None}, {'error': 'no certificate named'}])
def test_an_event_that_names_no_certificate_is_left_as_it_is(data):
    assert _published('certificate_failed', data) == data
