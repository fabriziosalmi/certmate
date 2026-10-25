"""A certificate is looked for at its host, which its name need not be (#854).

A certificate's name is what identifies it: its directory, its settings entry,
the routes about it. Its host is where it is served. They are the same string
for a certificate named after its domain, and differ for an IP certificate
(``ip-<dashed>``, served at the address) and, once #1149 lets a certificate be
named apart from its domain, for a certificate named ``internal.example.net``
served at ``example.com``. Such a certificate records its host in its metadata as
``host``; nothing writes it yet.

``certificate_host(name, metadata)`` reads it, and every place that goes
looking for a certificate asks: the deployment check, discovery, CT
monitoring, domain health and domain registration.
"""

import json
import os
import secrets
from unittest.mock import MagicMock

import pytest

from modules.core.cert_discovery import CertDiscoveryManager, _managed_domain_map
from modules.core.cert_inventory import CertInventory
from modules.core.certificates import CertificateManager
from modules.core.ct_monitor import CTMonitorManager, _managed_domains
from modules.core.domain_health import DomainHealthManager
from modules.core.domain_paths import certificate_dir
from modules.core.domain_registration import DomainRegistrationManager
from modules.core.utils import certificate_host
from tests.test_an_ip_certificate_is_looked_for_at_its_address import _deployment_status

pytestmark = [pytest.mark.unit]

# A name the routes accept today; #1149 decides the names a certificate may take.
NAME = 'internal.example.net'
HOST = 'example.com'


@pytest.mark.parametrize('name,metadata,host', [
    (NAME, {'host': HOST}, HOST),
    ('wild.example.net', {'host': '*.example.com'}, '*.example.com'),
    ('shop.example.com', {}, 'shop.example.com'),
    ('shop.example.com', None, 'shop.example.com'),
    ('ip-203-0-113-5', {}, '203.0.113.5'),
    # A host that is not a host name is not used: the name stands, as it
    # would with no metadata at all.
    (NAME, {'host': '../etc'}, NAME),
    (NAME, {'host': 'example.com\n'}, NAME),
    (NAME, {'host': ['example.com']}, NAME),
    (NAME, {'host': ''}, NAME),
])
def test_where_a_certificate_is_served(name, metadata, host):
    assert certificate_host(name, metadata) == host


def _write(cert_dir, name, metadata=None):
    directory = certificate_dir(cert_dir, name)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'cert.pem').write_text('x')
    if metadata is not None:
        (directory / 'metadata.json').write_text(json.dumps(metadata))


def test_the_manager_reads_the_host_from_the_metadata(tmp_path):
    _write(tmp_path, NAME, {'domain': NAME, 'host': HOST})
    _write(tmp_path, 'shop.example.com', {'domain': 'shop.example.com'})
    manager = CertificateManager(tmp_path, MagicMock(), MagicMock())

    assert manager.certificate_host(NAME) == HOST
    assert manager.certificate_host('shop.example.com') == 'shop.example.com'
    assert manager.certificate_host('ip-203-0-113-5') == '203.0.113.5'


# --------------------------------------------------------------------------- #
# The deployment check
# --------------------------------------------------------------------------- #

def test_the_deployment_check_probes_the_host(tmp_path, monkeypatch):
    calls, body = _deployment_status(tmp_path, monkeypatch, NAME, metadata={'host': HOST})
    assert calls == [HOST]
    assert body['probe_host'] == HOST


def test_a_wildcard_host_is_not_probed_at_its_apex(tmp_path, monkeypatch):
    calls, body = _deployment_status(tmp_path, monkeypatch, 'wild.example.net',
                                     metadata={'host': '*.example.com'})
    assert calls == []
    assert body['probe_status'] == 'unverifiable'
    assert body['mismatch_reason'] == (
        'Wildcard certificate *.example.com cannot be verified automatically: a wildcard '
        'does not cover its apex (example.com), so probing example.com would compare against '
        'the wrong host. Set the probe host to a name this wildcard covers (for example '
        'www.example.com) to enable the check: Settings → Probe in the UI, or deployment_host '
        'via PATCH /api/certificates/wild.example.net.')


def test_a_deployment_host_still_wins(tmp_path, monkeypatch):
    calls, _body = _deployment_status(tmp_path, monkeypatch, NAME,
                                      metadata={'host': HOST, 'deployment_host': 'lb.example.net'})
    assert calls == ['lb.example.net']


# --------------------------------------------------------------------------- #
# Discovery, CT monitoring, domain health, domain registration
# --------------------------------------------------------------------------- #

SETTINGS = {'domains': [{'domain': NAME}, {'domain': 'shop.example.com'}]}
HOSTS = {NAME: HOST}.get


def _host_of(name):
    return HOSTS(name) or certificate_host(name)


def test_discovery_probes_the_host_and_links_the_name():
    assert _managed_domain_map(SETTINGS, _host_of) == {HOST: NAME, 'shop.example.com': 'shop.example.com'}


def test_the_discovery_manager_asks_where_each_certificate_is_served(tmp_path):
    probed = []

    def probe(host, port=443, timeout=None, allow_private=False, check_revocation=False):
        probed.append(host)
        return {'status': 'unreachable', 'host': host, 'port': port, 'error': 'test'}

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = dict(SETTINGS, monitored_endpoints={
        'enabled': True, 'endpoints': [], 'include_managed': True, 'check_revocation': False})
    CertDiscoveryManager(settings_manager, CertInventory(tmp_path / 'data'), probe=probe,
                         host_of=_host_of).run_discovery()

    assert sorted(probed) == [HOST, 'shop.example.com']


def test_ct_monitoring_queries_the_host():
    assert _managed_domains(SETTINGS, _host_of) == [HOST, 'shop.example.com']


def test_ct_monitoring_leaves_out_a_wildcard_or_an_address_host():
    hosts = {'wild.example.net': '*.example.com', 'ip-203-0-113-5': '203.0.113.5'}
    settings = {'domains': [{'domain': name} for name in hosts]}
    assert _managed_domains(settings, lambda name: hosts[name]) == []


def test_the_ct_manager_asks_where_each_certificate_is_served(tmp_path):
    searched = []
    client = MagicMock()
    client.search.side_effect = lambda domain: searched.append(domain) or []
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = dict(SETTINGS, ct_monitoring={
        'enabled': True, 'domains': [], 'include_managed': True})
    CTMonitorManager(settings_manager, CertInventory(tmp_path / 'data'), client=client,
                     host_of=_host_of).run_poll()

    assert searched == [HOST, 'shop.example.com']


def _with_two_certificates(cert_dir):
    _write(cert_dir, NAME, {'domain': NAME, 'host': HOST, 'san_domains': ['api.example.com']})
    _write(cert_dir, 'ip-203-0-113-5', {'domain': 'ip-203-0-113-5'})
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'domains': [{'domain': NAME}, {'domain': 'ip-203-0-113-5'}]}
    return settings_manager


def test_domain_health_checks_the_host(tmp_path):
    settings_manager = _with_two_certificates(tmp_path / 'certs')
    health = DomainHealthManager(settings_manager, CertInventory(tmp_path / 'data'), tmp_path / 'certs')

    tracked = health.tracked_names(config={'include_inventory': False, 'extra_domains': []})

    assert tracked == {'api.example.com': False, HOST: True}


def test_domain_registration_follows_the_host(tmp_path):
    settings_manager = _with_two_certificates(tmp_path / 'certs')
    registration = DomainRegistrationManager(
        settings_manager, CertInventory(tmp_path / 'data'), tmp_path / 'certs')

    assert registration.tracked_domains(config={'include_inventory': False, 'extra_domains': []}) == [HOST]


# --------------------------------------------------------------------------- #
# The application wires the manager's resolver into discovery and CT
# --------------------------------------------------------------------------- #

@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('certificate-host')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        _app, container = create_app()
        _write(tmp / 'certs', NAME, {'domain': NAME, 'host': HOST})
        yield container


def test_the_application_looks_for_a_certificate_at_its_host(instance, monkeypatch):
    container = instance
    container.managers['settings'].update(lambda s: s.update({
        'domains': [{'domain': NAME}],
        'monitored_endpoints': {'enabled': True, 'endpoints': [], 'include_managed': True,
                                'check_revocation': False},
        'ct_monitoring': {'enabled': True, 'domains': [], 'include_managed': True},
    }), 'test_certificate_host')
    probed, searched = [], []

    def probe(host, port=443, timeout=None, allow_private=False, check_revocation=False):
        probed.append(host)
        return {'status': 'unreachable', 'host': host, 'port': port, 'error': 'test'}

    client = MagicMock()
    client.search.side_effect = lambda domain: searched.append(domain) or []
    monkeypatch.setattr(container.managers['cert_discovery'], '_probe', probe)
    monkeypatch.setattr(container.managers['ct_monitor'], '_client', client)

    container.managers['cert_discovery'].run_discovery()
    container.managers['ct_monitor'].run_poll()

    assert probed == [HOST]
    assert searched == [HOST]


def test_a_name_that_cannot_name_a_directory_stands_for_itself(tmp_path):
    """Settings are screened on save; the resolver does not depend on it."""
    manager = CertificateManager(tmp_path, MagicMock(), MagicMock())
    assert manager.certificate_host('../etc') == '../etc'


def test_ct_monitoring_skips_an_entry_that_names_nothing():
    settings = {'domains': [{'domain': ''}, {}, 42, {'domain': 'shop.example.com'}]}
    assert _managed_domains(settings, _host_of) == ['shop.example.com']


@pytest.mark.parametrize('content', ['["example.com"]', '"example.com"', '{not json'])
def test_metadata_of_another_shape_leaves_the_name(tmp_path, content):
    from modules.core.inventory_sources import certificate_names
    directory = certificate_dir(tmp_path, NAME)
    directory.mkdir()
    (directory / 'metadata.json').write_text(content)

    assert certificate_names(tmp_path, NAME) == (NAME, [])
