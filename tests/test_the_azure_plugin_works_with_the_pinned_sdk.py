"""certbot-dns-azure against the azure-mgmt-dns this repository pins.

Dependabot moved `azure-mgmt-dns` 8.1.0 -> 9.0.0 on 2026-08-21 (#586) and the
release notes of v2.26.1 recorded the check that justified it: the plugin imports,
and the three operations it calls exist on 9.0.0 with the signature it uses. All
true, and none of it is the line that breaks. The plugin builds its client as

    DnsManagementClient(credential, subscription_id, None, arm_endpoint, credential_scopes=[...])

five positional arguments, and 9.0.0 takes four, so the first Azure challenge died
with a TypeError. Every release from v2.26.1 to v2.45.1 shipped it. Nothing in the
suite ever ran the plugin's own code against the SDK it is installed with: the
provider was covered by tests of CertMate's side (credentials file, zone
discovery), and the point where the two meet was read, not run.

These tests run it. The plugin's own `_perform` and `_cleanup` execute against the
installed SDK, with the HTTP layer replaced, so a change on either side of the pin
that breaks the construction or the shape of a call fails here and not on a user's
first renewal.
"""
import re
import time
from unittest.mock import MagicMock

import pytest
import requests_mock
from azure.core.credentials import AccessToken

from certbot_dns_azure._internal.dns_azure import Authenticator

pytestmark = [pytest.mark.unit]

SUBSCRIPTION = '00000000-0000-0000-0000-000000000001'
RESOURCE_GROUP = 'rg-dns'
ZONE = 'example.org'
DOMAIN = 'www.example.org'
VALIDATION_NAME = '_acme-challenge.www.example.org'
ARM = 'https://management.azure.com'
RECORD_URL = re.compile(
    r'https://management\.azure\.com/subscriptions/' + SUBSCRIPTION +
    r'/resourceGroups/' + RESOURCE_GROUP + r'/providers/Microsoft\.Network/dnsZones/' +
    ZONE + r'/TXT/_acme-challenge\.www.*')


class _Credential:
    """A token source that never leaves the process."""

    def get_token(self, *scopes, **kwargs):
        return AccessToken('not-a-real-token', int(time.time()) + 3600)


def _plugin():
    plugin = Authenticator(MagicMock(), 'dns-azure')
    plugin.credential = _Credential()
    plugin._arm_endpoint = ARM
    plugin.domain_zoneid = {
        ZONE: f'/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}'}
    plugin.ttl = 60
    return plugin


def _recordset(values):
    return {'id': 'x', 'name': '_acme-challenge.www', 'etag': 'W/"1"',
            'properties': {'TTL': 60, 'TXTRecords': [{'value': [v]} for v in values]}}


def test_the_plugin_can_build_its_dns_client_with_the_pinned_sdk():
    """The line that broke: the plugin's own constructor call, against the real class."""
    client = _plugin()._get_azure_client(SUBSCRIPTION)
    assert type(client).__name__ == 'DnsManagementClient'


def test_a_challenge_record_is_created_through_the_sdk():
    plugin = _plugin()
    with requests_mock.Mocker() as http:
        http.get(RECORD_URL, status_code=404, json={'error': {'code': 'NotFound', 'message': 'no record'}})
        put = http.put(RECORD_URL, status_code=200, json=_recordset(['token-1']))
        plugin._perform(DOMAIN, VALIDATION_NAME, 'token-1')

    assert put.call_count == 1
    sent = put.last_request.json()
    assert sent['properties']['TXTRecords'] == [{'value': ['token-1']}], sent
    assert sent['properties']['TTL'] == 60
    assert put.last_request.headers['Authorization'] == 'Bearer not-a-real-token'


def test_a_challenge_record_is_removed_through_the_sdk():
    plugin = _plugin()
    with requests_mock.Mocker() as http:
        http.get(RECORD_URL, status_code=200, json=_recordset(['token-1']))
        delete = http.delete(RECORD_URL, status_code=200)
        http.put(RECORD_URL, status_code=200, json=_recordset(['token-1']))
        plugin._cleanup(DOMAIN, VALIDATION_NAME, 'token-1')

    assert delete.call_count == 1, 'the cleanup never deleted the record'
    assert delete.last_request.method == 'DELETE'


def test_a_second_challenge_on_the_same_name_keeps_the_first_value():
    """A wildcard and its apex share one record name; the plugin merges rather than overwrites."""
    plugin = _plugin()
    with requests_mock.Mocker() as http:
        http.get(RECORD_URL, status_code=200, json=_recordset(['token-1']))
        put = http.put(RECORD_URL, status_code=200, json=_recordset(['token-1', 'token-2']))
        plugin._perform(DOMAIN, VALIDATION_NAME, 'token-2')

    values = sorted(r['value'][0] for r in put.last_request.json()['properties']['TXTRecords'])
    assert values == ['token-1', 'token-2']
