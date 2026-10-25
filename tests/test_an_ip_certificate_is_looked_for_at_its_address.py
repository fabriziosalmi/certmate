"""An IP certificate is looked for at its address, never at its name.

A certificate for a public IPv4 address (#1130) is named ``ip-<dashed>``: the
address cannot name a directory, so ``ip-203-0-113-5`` stands for
``203.0.113.5``. It is the first certificate whose name is not what it
certifies (#854), and every place that took the name for a host name went
looking for a host called ``ip-203-0-113-5``: the deployment check, the browser
check that backs it up, discovery, CT monitoring and domain health.

``certificate_host`` answers where a certificate is served, and those places
ask it. CT monitoring and domain health leave an IP certificate out: crt.sh
answers a query for an address with every certificate whose names contain its
digits, and the domain health checks are about names (HSTS is ignored for an
IP literal, RFC 6797 section 8.1).
"""

import json
import pathlib
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import modules.api.resources_deployment as api_resources_module
from modules.core.cert_discovery import _managed_domain_map, discover_endpoints
from modules.core.cert_inventory import CertInventory
from modules.core.ct_monitor import _managed_domains
from modules.core.domain_health import DomainHealthManager
from modules.core.utils import certificate_host
from tests.test_deployment_status_route import _build_app, _passthrough_decorator

pytestmark = [pytest.mark.unit]

NAME = 'ip-203-0-113-5'
ADDRESS = '203.0.113.5'
SETTINGS = {'domains': [{'domain': NAME}, {'domain': 'shop.example.com'}, {'domain': '*.example.com'}]}


@pytest.mark.parametrize('name,host', [
    (NAME, ADDRESS),
    ('shop.example.com', 'shop.example.com'),
    ('*.example.com', '*.example.com'),
    ('ip-203-0-113', 'ip-203-0-113'),   # not a derived name: a name like any other
])
def test_where_a_certificate_is_served(name, host):
    assert certificate_host(name) == host


# --------------------------------------------------------------------------- #
# The deployment check
# --------------------------------------------------------------------------- #

def _deployment_status(tmp_path, monkeypatch, name, metadata=None):
    (tmp_path / name).mkdir()
    (tmp_path / name / 'cert.pem').write_bytes(b'stored')
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough_decorator)
    managers = {
        'auth': auth, 'settings': MagicMock(), 'dns': MagicMock(),
        'certificates': MagicMock(cert_dir=Path(tmp_path), storage_manager=None,
                                  get_certificate_info=MagicMock(return_value={'exists': True}),
                                  _load_metadata=MagicMock(return_value=metadata or {})),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(get_deployment_status=MagicMock(return_value=None),
                           set_deployment_status=MagicMock()),
    }
    calls = []
    monkeypatch.setattr(api_resources_module, '_certificate_fingerprint', lambda served: 'fp')

    def probe(target, **kwargs):
        calls.append(kwargs.get('probe_host') or target)
        return {'reachable': True, 'certificate_bytes': b'stored'}

    monkeypatch.setattr(api_resources_module, '_probe_tls_certificate', probe)
    body = _build_app(managers).test_client().get(
        f'/api/certificates/{name}/deployment-status').get_json()
    return calls, body


def test_the_deployment_check_connects_to_the_address(tmp_path, monkeypatch):
    calls, body = _deployment_status(tmp_path, monkeypatch, NAME)
    assert calls == [ADDRESS]
    assert body['probe_host'] == ADDRESS


def test_a_deployment_host_still_wins_for_an_ip_certificate(tmp_path, monkeypatch):
    calls, body = _deployment_status(tmp_path, monkeypatch, NAME,
                                     metadata={'deployment_host': 'lb.example.net'})
    assert calls == ['lb.example.net']
    assert body['probe_host'] == 'lb.example.net'


def test_a_named_certificate_is_checked_as_before(tmp_path, monkeypatch):
    calls, body = _deployment_status(tmp_path, monkeypatch, 'shop.example.com')
    assert calls == ['shop.example.com']
    assert body['probe_host'] == 'shop.example.com'


# --------------------------------------------------------------------------- #
# Discovery, CT monitoring, domain health
# --------------------------------------------------------------------------- #

def test_discovery_probes_the_address_and_links_the_name():
    assert _managed_domain_map(SETTINGS) == {ADDRESS: NAME, 'shop.example.com': 'shop.example.com'}


def test_a_discovered_ip_certificate_is_linked_to_its_name(tmp_path):
    probed = []

    def probe(host, port=443, timeout=None, allow_private=False, check_revocation=False):
        probed.append(host)
        return {'status': 'ok', 'host': host, 'port': port, 'error': None,
                'certificate': {'fingerprint_sha256': 'fpIP', 'subject_cn': None,
                                'san_dns': [], 'key': {}},
                'validation': {}, 'chain': []}

    inventory = CertInventory(tmp_path / 'data')
    managed = _managed_domain_map(SETTINGS)
    discover_endpoints(list(managed), inventory, probe=probe, managed_domains=managed)

    assert ADDRESS in probed and NAME not in probed
    assert inventory.get('fpIP')['managed_domain'] == NAME


def test_ct_monitoring_leaves_an_ip_certificate_out():
    assert _managed_domains(SETTINGS) == ['shop.example.com']


def test_domain_health_leaves_an_ip_certificate_out(tmp_path):
    for name in (NAME, 'shop.example.com'):
        (tmp_path / name).mkdir()
        (tmp_path / name / 'cert.pem').write_text('x')
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = SETTINGS
    health = DomainHealthManager(settings_manager, CertInventory(tmp_path / 'data'), tmp_path)

    tracked = health.tracked_names(config={'include_inventory': False, 'extra_domains': []},
                                   settings={'domains': SETTINGS['domains'][:2]})

    assert NAME not in tracked
    assert 'shop.example.com' in tracked


# --------------------------------------------------------------------------- #
# The browser check that backs the deployment check up (dashboard.js)
# --------------------------------------------------------------------------- #

REPO = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD = (REPO / 'static' / 'js' / 'dashboard.js').read_text(encoding='utf-8')


def _function(name):
    match = re.search(r'\n    function ' + name + r'\(.*?\n    \}\n', DASHBOARD, re.S)
    assert match, f'{name} not found in dashboard.js'
    return match.group(0)


def _browser_fetches(domain, certificates, server):
    """The URLs the dashboard fetches for one deployment check, run in node.

    *server* is the deployment-status answer, or None for a server that fails.
    """
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not available')
    script = (
        "var fetched = [];\n"
        "var allCertificates = " + json.dumps(certificates) + ";\n"
        "var server = " + json.dumps(server) + ";\n"
        "var API_HEADERS = {};\n"
        "var element = {className: '', innerHTML: '', getAttribute: function () { return "
        + json.dumps(domain) + "; }};\n"
        "var document = {querySelectorAll: function () { return [element]; }};\n"
        "var deploymentCache = {get: function () { return null; }, set: function () {}};\n"
        "function updateDeploymentUI() {}\n"
        "function queueBrowserDeploymentReport() {}\n"
        "function fetch(url) {\n"
        "  fetched.push(url);\n"
        "  if (url.indexOf('/api/') === 0) {\n"
        "    if (!server) { return Promise.resolve({ok: false}); }\n"
        "    return Promise.resolve({ok: true, json: function () { return Promise.resolve(server); }});\n"
        "  }\n"
        "  return Promise.resolve({});\n"
        "}\n"
        + _function('servedHost') + _function('checkDeploymentViaBrowser')
        + _function('checkDeploymentStatus')
        + "checkDeploymentStatus(" + json.dumps(domain) + ", null, true).then(function () {\n"
        "  console.log(JSON.stringify(fetched));\n"
        "});\n"
    )
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


IP_CERTIFICATE = [{'domain': NAME, 'ip_address': ADDRESS}]


def test_the_browser_checks_the_host_the_server_probed():
    fetched = _browser_fetches(NAME, IP_CERTIFICATE, {
        'reachable': False, 'protocol': 'https-tls', 'port': 443, 'probe_host': ADDRESS})
    assert fetched[1:] == [f'https://{ADDRESS}:443']


def test_the_browser_checks_the_address_when_the_server_cannot_answer():
    fetched = _browser_fetches(NAME, IP_CERTIFICATE, None)
    assert fetched[1:] == [f'https://{ADDRESS}']


def test_the_browser_checks_a_deployment_host_the_server_probed():
    fetched = _browser_fetches('shop.example.com', [{'domain': 'shop.example.com'}], {
        'reachable': False, 'protocol': 'https-tls', 'port': 8443, 'probe_host': 'lb.example.net'})
    assert fetched[1:] == ['https://lb.example.net:8443']


def test_the_browser_checks_a_named_certificate_as_before():
    fetched = _browser_fetches('shop.example.com', [{'domain': 'shop.example.com'}], None)
    assert fetched[1:] == ['https://shop.example.com']
