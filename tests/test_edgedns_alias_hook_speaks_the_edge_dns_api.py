"""The EdgeDNS alias hook against the Edge DNS API as Akamai documents it.

The hook added in #122 posted a bare record set to
``/config-dns/v2/zones/{zone}/recordsets`` (which takes ``{"recordsets": [...]}``)
and sent PUT and DELETE to ``/zones/{zone}/recordsets/{name}/TXT``, a path the
API does not have: a single record set lives at
``/zones/{zone}/names/{name}/types/{type}`` (techdocs.akamai.com/edge-dns,
"Get a record set", "Create a record set"), which is also what
``certbot-plugin-edgedns`` uses. Nothing ran the hook against anything that
checked a URL, so it shipped that way.

It also wrote a TXT record set with only its own value. A wildcard with its
apex (``*.example.com`` and ``example.com``) needs two values under one name,
and certbot's manual plugin runs the auth hook for every challenge before any
is validated: the second write replaced the first, and the first challenge
could not pass. Cleanup deleted the whole record set.

The stand-in below knows only the documented paths and answers 404 to any
other, so a hook that talks to a path Akamai does not have fails here the way
it would against Akamai.
"""
import json
import re
from unittest import mock

import pytest

import modules.core.dns_alias_hook as hook

pytestmark = [pytest.mark.unit]

ZONE = 'example.net'
ALIAS = 'alias.example.net'
NAME = f'_acme-challenge.{ALIAS}'
BASE = 'https://akab-test.luna.akamaiapis.net'
RECORD_PATH = re.compile(
    rf'^{re.escape(BASE)}/config-dns/v2/zones/(?P<zone>[^/]+)/names/(?P<name>[^/]+)/types/(?P<type>[A-Z]+)$')


class _Response:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body) if body is not None else ''

    def json(self):
        return self._body


class FakeEdgeDNS:
    """Record sets as Edge DNS keeps them: one per (name, type), TXT data
    returned quoted, a POST onto an existing set refused with 409."""

    def __init__(self):
        self.sets = {}
        self.calls = []

    def _record(self, url):
        match = RECORD_PATH.match(url)
        if not match or match['zone'] != ZONE:
            return None
        return (match['name'], match['type'])

    def get(self, url, **kwargs):
        self.calls.append(('GET', url))
        if url == f'{BASE}/config-dns/v2/zones/{ZONE}':
            return _Response(200, {'zone': ZONE})
        key = self._record(url)
        if key is None or key not in self.sets:
            return _Response(404, {'title': 'Not Found'})
        rdata = [f'"{value}"' for value in self.sets[key]]
        return _Response(200, {'name': key[0], 'type': key[1], 'ttl': 60, 'rdata': rdata})

    def post(self, url, json=None, **kwargs):
        self.calls.append(('POST', url))
        key = self._record(url)
        if key is None:
            return _Response(404, {'title': 'Not Found'})
        if key in self.sets:
            return _Response(409, {'title': 'Conflict'})
        assert json['name'] == key[0] and json['type'] == key[1]
        self.sets[key] = [value.strip('"') for value in json['rdata']]
        return _Response(201, json)

    def put(self, url, json=None, **kwargs):
        self.calls.append(('PUT', url))
        key = self._record(url)
        if key is None or key not in self.sets:
            return _Response(404, {'title': 'Not Found'})
        self.sets[key] = [value.strip('"') for value in json['rdata']]
        return _Response(200, json)

    def delete(self, url, **kwargs):
        self.calls.append(('DELETE', url))
        key = self._record(url)
        if key is None or key not in self.sets:
            return _Response(404, {'title': 'Not Found'})
        del self.sets[key]
        return _Response(204)

    def values(self):
        return self.sets.get((NAME, 'TXT'))


@pytest.fixture
def edge():
    fake = FakeEdgeDNS()
    with mock.patch.object(hook, '_edgegrid_auth', return_value=(fake, BASE)):
        yield fake


def _change(validation, action):
    hook._edgedns_change({'domain_alias': ALIAS}, validation, action)


def test_one_challenge_is_published_and_removed(edge):
    _change('only-value', 'create')
    assert edge.values() == ['only-value']
    _change('only-value', 'delete')
    assert edge.values() is None


def test_a_wildcard_and_its_apex_keep_both_values_until_both_are_validated(edge):
    """certbot runs the auth hook for every challenge, then validates: both
    values must be in the record set at the same time."""
    _change('value-for-wildcard', 'create')
    _change('value-for-apex', 'create')
    assert sorted(edge.values()) == ['value-for-apex', 'value-for-wildcard']

    _change('value-for-wildcard', 'delete')
    assert edge.values() == ['value-for-apex']
    _change('value-for-apex', 'delete')
    assert edge.values() is None


def test_cleanup_leaves_a_value_it_did_not_write(edge):
    """Another order's value under the same name stays when this one cleans up."""
    edge.sets[(NAME, 'TXT')] = ['someone-else']
    _change('mine', 'create')
    _change('mine', 'delete')
    assert edge.values() == ['someone-else']


def test_a_repeated_create_does_not_duplicate_the_value(edge):
    _change('same', 'create')
    _change('same', 'create')
    assert edge.values() == ['same']


def test_cleanup_of_a_record_that_is_already_gone_is_quiet(edge):
    _change('never-written', 'delete')
    assert edge.values() is None


def test_only_documented_paths_are_used(edge):
    """CONTROL on the stand-in: every request the hook made went to a path
    Edge DNS has. A path it does not have answers 404 here, and the tests above
    would fail; this states the reason in one place."""
    _change('a', 'create')
    _change('b', 'create')
    _change('a', 'delete')
    _change('b', 'delete')
    zone_path = re.compile(rf'^{re.escape(BASE)}/config-dns/v2/zones/[^/]+$')
    for method, url in edge.calls:
        # GET /zones/{zone} is how the zone is found (each guess in turn);
        # everything else must be the one record-set path.
        assert (method == 'GET' and zone_path.match(url)) or RECORD_PATH.match(url), (method, url)


def test_an_api_error_is_reported_with_its_status(edge):
    with mock.patch.object(edge, 'post', return_value=_Response(403, {'title': 'Forbidden'})):
        with pytest.raises(hook.DNSAliasError, match='403'):
            _change('x', 'create')
