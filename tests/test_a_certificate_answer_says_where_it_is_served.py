"""Every certificate answer says where the certificate is served: `host` (#854).

A certificate's `domain` in every answer is its name, which is what every
later request takes. Where it is served is another thing for an IP
certificate (its address) and for a certificate named apart from its domain
(the host its metadata names, #1360). Since API contract 2.59 the answers say
so in `host`, always: the name for every other certificate, so a client never
has to rebuild it from `domain` and `ip_address`.
"""

import json
import shutil
import subprocess

import pytest

import tests.contract_world as world
from modules.core.domain_paths import certificate_dir
from tests import test_an_ip_certificate_is_created_and_renewed_through_the_api as _ip_api
from tests.test_an_ip_certificate_is_looked_for_at_its_address import _function

pytestmark = [pytest.mark.unit]

# The IP-certificate API module's application and its helper: the same
# instance shape, with a certbot that writes what Let's Encrypt issues.
instance = _ip_api.instance
_issued = _ip_api._issued

NAME = 'internal.example.net'
HOST = 'example.com'


def _on_disk(certs, name, metadata=None, *, torn=False):
    directory = certificate_dir(certs, name)
    if torn:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'cert.pem').write_bytes(b'-----BEGIN CERTIFICATE-----\ntorn')
    else:
        world.write_certificate(directory, name)
    (directory / 'metadata.json').write_text(json.dumps({'domain': name, **(metadata or {})}))


def _register(container, *names):
    settings = container.managers['settings']
    current = settings.load_settings()
    current['domains'] = [*current.get('domains', []), *({'domain': n} for n in names)]
    settings.save_settings(current)


def _listed(client):
    return {c['domain']: c for c in client.get('/api/certificates').get_json()}


def test_the_create_answer_says_where_it_is_served(instance):
    client, _container, _certbot, _certs = instance
    response = client.post('/api/certificates/create', json={'domain': '1.0.0.2'})
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert (body['domain'], body['host']) == ('ip-1-0-0-2', '1.0.0.2')


def test_the_list_and_the_detail_say_where_each_certificate_is_served(instance):
    client, container, _certbot, certs = instance
    ip_name = _issued(instance, '1.1.1.1')
    _on_disk(certs, 'shop.example.com')
    _on_disk(certs, NAME, {'host': HOST})
    _register(container, 'shop.example.com', NAME)

    listed = _listed(client)
    assert {name: listed[name]['host'] for name in (ip_name, 'shop.example.com', NAME)} == {
        ip_name: '1.1.1.1', 'shop.example.com': 'shop.example.com', NAME: HOST}
    detail = client.get(f'/api/certificates/{NAME}').get_json()
    assert (detail['domain'], detail['host'], detail['ip_address']) == (NAME, HOST, None)


def test_a_certificate_that_cannot_be_read_still_says_where_it_is_served(instance):
    client, container, _certbot, certs = instance
    _on_disk(certs, 'torn.example.net', {'host': 'torn.example.com'}, torn=True)
    _register(container, 'torn.example.net')

    detail = client.get('/api/certificates/torn.example.net').get_json()
    assert detail['host'] == 'torn.example.com'


def test_a_registered_certificate_not_yet_on_disk_says_where_it_will_be_served(instance):
    client, container, _certbot, _certs = instance
    _register(container, 'pending.example.com')

    listed = _listed(client)['pending.example.com']
    assert (listed['exists'], listed['host']) == (False, 'pending.example.com')


# --------------------------------------------------------------------------- #
# The dashboard asks where a certificate is served before checking it
# --------------------------------------------------------------------------- #

def _served_host(domain, certificates):
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not available')
    script = ("var allCertificates = " + json.dumps(certificates) + ";\n"
              + _function('servedHost')
              + "console.log(JSON.stringify(servedHost(" + json.dumps(domain) + ")));\n")
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize('certificate,served', [
    ({'domain': NAME, 'host': HOST}, HOST),
    ({'domain': 'ip-1-1-1-1', 'host': '1.1.1.1', 'ip_address': '1.1.1.1'}, '1.1.1.1'),
    ({'domain': 'ip-1-1-1-1', 'ip_address': '1.1.1.1'}, '1.1.1.1'),   # a server before 2.59
    ({'domain': 'shop.example.com'}, 'shop.example.com'),
])
def test_the_dashboard_checks_a_certificate_where_it_is_served(certificate, served):
    assert _served_host(certificate['domain'], [certificate]) == served
