"""The PowerDNS hook, against a fake PowerDNS API that answers the way the real one does.

The fake is a real HTTP server on 127.0.0.1, so what is exercised is the hook's
own requests: the zone lookup, the PATCH that adds or removes one TXT value, the
notify. It holds zones in memory and answers:

* GET  /api/v1/servers/<id>/zones/<zone>.   200 and the zone, or the status set
  for that name (404 for a zone it does not have, as PowerDNS 4.x does, unless a
  test asks for 422, what older PowerDNS answered, or 401/403);
* PATCH the same URL with ``{"rrsets": [...]}``: REPLACE sets the record set's
  values, DELETE removes it, 204;
* PUT  .../notify: 200.

What each test pins is said in its name; the pull request that added the hook
shows each one failing with the check it pins disabled.
"""
import json
import os
import re
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

import pytest

from modules.core import powerdns_dns_hook as hook

pytestmark = [pytest.mark.unit]

API_KEY = 'pdns-key'
CHALLENGE = '_acme-challenge'


class FakePowerDNS:
    """Zones in memory, the API PowerDNS 4.x speaks, and every request it was sent."""

    def __init__(self, zones, *, missing=404, statuses=None, write_status=None, notify_status=None,
                 server_id='localhost'):
        self.zones = {name: {'name': name + '.', 'kind': kind, 'rrsets': []}
                      for name, kind in zones.items()}
        self.missing = missing
        self.statuses = dict(statuses or {})
        self.write_status, self.notify_status = write_status, notify_status
        self.server_id = server_id
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, status, payload=None):
                body = json.dumps(payload).encode() if payload is not None else b''
                self.send_response(status)
                if body:
                    self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self):
                length = int(self.headers.get('Content-Length') or 0)
                body = json.loads(self.rfile.read(length) or b'null') if length else None
                fake.requests.append((self.command, unquote(self.path), self.headers.get('X-API-Key'), body))
                prefix = f'/api/v1/servers/{fake.server_id}/zones/'
                path = unquote(self.path)
                if not path.startswith(prefix):
                    return self._answer(404, {'error': 'Not Found'})
                rest = path[len(prefix):]
                notify = rest.endswith('/notify')
                zone = rest.removesuffix('/notify').rstrip('.')
                if self.headers.get('X-API-Key') != API_KEY:
                    return self._answer(401, {'error': 'Unauthorized'})
                if zone in fake.statuses:
                    return self._answer(fake.statuses[zone], {'error': 'refused'})
                if zone not in fake.zones:
                    return self._answer(fake.missing, {'error': f'Could not find domain {zone}.'})
                if notify:
                    return self._answer(fake.notify_status or 200, {'result': 'Notification queued'})
                if self.command == 'GET':
                    return self._answer(200, fake.zones[zone])
                if fake.write_status:
                    return self._answer(fake.write_status, {'error': 'refused'})
                for change in body['rrsets']:
                    rrsets = [r for r in fake.zones[zone]['rrsets']
                              if not (r['name'] == change['name'] and r['type'] == change['type'])]
                    if change['changetype'] == 'REPLACE':
                        rrsets.append({'name': change['name'], 'type': change['type'],
                                       'ttl': change['ttl'], 'records': change['records']})
                    fake.zones[zone]['rrsets'] = rrsets
                return self._answer(204)

            do_GET = do_PATCH = do_PUT = _handle

            def log_message(self, *args):
                pass

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01},
                         daemon=True).start()

    def values(self, zone, name):
        for rrset in self.zones[zone]['rrsets']:
            if rrset['name'] == name + '.' and rrset['type'] == 'TXT':
                return sorted(record['content'].strip('"') for record in rrset['records'])
        return []

    def asked_for(self):
        return [path.split('/zones/')[1].rstrip('.') for method, path, _, _ in self.requests
                if method == 'GET']

    def changes(self):
        return [body['rrsets'][0] for method, _, _, body in self.requests if method == 'PATCH']

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def pdns():
    servers = []

    def start(zones, **kwargs):
        server = FakePowerDNS(zones, **kwargs)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def _run(server, action, domain, validation, **config):
    hook.run({'api_url': server.url, 'api_key': API_KEY, **config}, action,
             {'CERTBOT_DOMAIN': domain, 'CERTBOT_VALIDATION': validation})


# --------------------------------------------------------------------------
# Finding the zone
# --------------------------------------------------------------------------

def test_the_zone_is_found_at_the_parent_after_a_404(pdns):
    """Current PowerDNS answers 404 for a zone it does not have (the plugin's bug)."""
    server = pdns({'example.com': 'Native'}, missing=404)
    _run(server, 'auth', 'sub.example.com', 'token-1')
    assert server.values('example.com', f'{CHALLENGE}.sub.example.com') == ['token-1']
    assert server.asked_for() == [f'{CHALLENGE}.sub.example.com', 'sub.example.com', 'example.com']


def test_the_zone_is_found_at_the_parent_after_a_422(pdns):
    """What older PowerDNS answered, and all the plugin looked for."""
    server = pdns({'example.com': 'Native'}, missing=422)
    _run(server, 'auth', 'sub.example.com', 'token-1')
    assert server.values('example.com', f'{CHALLENGE}.sub.example.com') == ['token-1']


def test_a_separately_hosted_sub_zone_gets_the_record(pdns):
    server = pdns({'example.com': 'Native', 'sub.example.com': 'Native'})
    _run(server, 'auth', 'app.sub.example.com', 'token-1')
    assert server.values('sub.example.com', f'{CHALLENGE}.app.sub.example.com') == ['token-1']
    assert server.values('example.com', f'{CHALLENGE}.app.sub.example.com') == []
    assert server.asked_for() == [f'{CHALLENGE}.app.sub.example.com', 'app.sub.example.com', 'sub.example.com']


def test_a_zone_of_the_challenge_name_itself_is_used(pdns):
    """A common way to hand the challenge to a separate server."""
    server = pdns({'example.com': 'Native', f'{CHALLENGE}.example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-1')
    assert server.values(f'{CHALLENGE}.example.com', f'{CHALLENGE}.example.com') == ['token-1']


def test_a_wildcard_is_validated_on_its_base_name(pdns):
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', '*.example.com', 'token-1')
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['token-1']


@pytest.mark.parametrize(('status', 'who'), [
    (403, 'or a proxy in front of the PowerDNS API'),
    (401, 'check the API key')])
def test_a_refusal_stops_the_lookup_with_its_own_message(pdns, status, who):
    """A 401/403 is about the key or a proxy, not the zone: moving on would end as
    'zone not found' and send the operator looking for a zone that is there."""
    server = pdns({'example.com': 'Native'}, statuses={f'{CHALLENGE}.sub.example.com': status})
    with pytest.raises(hook.PowerDNSHookError) as raised:
        _run(server, 'auth', 'sub.example.com', 'token-1')
    message = str(raised.value)
    assert f'HTTP {status}' in message and who in message
    assert 'No PowerDNS zone holds' not in message
    assert server.asked_for() == [f'{CHALLENGE}.sub.example.com']
    assert server.changes() == []


def test_a_wrong_key_is_reported_as_the_key(pdns):
    server = pdns({'example.com': 'Native'})
    with pytest.raises(hook.PowerDNSHookError, match=r'HTTP 401.*API key'):
        hook.run({'api_url': server.url, 'api_key': 'wrong'}, 'auth',
                 {'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 't'})


def test_any_other_answer_stops_the_lookup_and_is_reported(pdns):
    server = pdns({'example.com': 'Native'}, statuses={f'{CHALLENGE}.example.com': 500})
    with pytest.raises(hook.PowerDNSHookError, match='HTTP 500'):
        _run(server, 'auth', 'example.com', 'token-1')
    assert server.asked_for() == [f'{CHALLENGE}.example.com']


def test_the_lookup_stops_at_the_registered_domain_and_names_what_it_asked_for(pdns):
    server = pdns({'other.org': 'Native'})
    with pytest.raises(hook.PowerDNSHookError) as raised:
        _run(server, 'auth', 'a.b.example.co.uk', 'token-1')
    assert server.asked_for() == [
        f'{CHALLENGE}.a.b.example.co.uk', 'a.b.example.co.uk', 'b.example.co.uk', 'example.co.uk']
    assert str(raised.value).endswith('b.example.co.uk (404), example.co.uk (404)')


@pytest.mark.parametrize(('domain', 'expected'), [
    ('host.corp.lan', [f'{CHALLENGE}.host.corp.lan', 'host.corp.lan', 'corp.lan']),
    ('app.example.internal', [f'{CHALLENGE}.app.example.internal', 'app.example.internal', 'example.internal']),
    ('example.com', [f'{CHALLENGE}.example.com', 'example.com']),
])
def test_a_name_under_no_public_suffix_stops_at_two_labels(domain, expected):
    """The zones a private ACME CA issues for: never ask PowerDNS for a bare 'lan'."""
    assert hook.zone_candidates(domain) == expected


def test_an_internal_zone_gets_the_record(pdns):
    server = pdns({'corp.lan': 'Native'})
    _run(server, 'auth', 'host.corp.lan', 'token-1')
    assert server.values('corp.lan', f'{CHALLENGE}.host.corp.lan') == ['token-1']


# --------------------------------------------------------------------------
# Writing and removing the value
# --------------------------------------------------------------------------

def test_a_second_value_on_the_same_name_is_added_not_written_over(pdns):
    """A wildcard and its apex are validated on the same _acme-challenge name."""
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-apex')
    _run(server, 'auth', '*.example.com', 'token-wild')
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['token-apex', 'token-wild']


def test_the_value_is_written_quoted_with_a_short_ttl(pdns):
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-1')
    change = server.changes()[0]
    assert change['changetype'] == 'REPLACE' and change['type'] == 'TXT'
    assert change['name'] == f'{CHALLENGE}.example.com.'
    assert change['records'] == [{'content': '"token-1"', 'disabled': False}]
    assert change['ttl'] == hook.TXT_TTL_SECONDS


def test_a_value_already_there_is_not_written_again(pdns):
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-1')
    _run(server, 'auth', 'example.com', 'token-1')
    assert len(server.changes()) == 1


def test_cleanup_removes_only_the_value_it_created(pdns):
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-apex')
    _run(server, 'auth', '*.example.com', 'token-wild')
    _run(server, 'cleanup', 'example.com', 'token-apex')
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['token-wild']
    assert server.changes()[-1]['changetype'] == 'REPLACE'


def test_cleanup_of_the_last_value_deletes_the_record_set(pdns):
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-1')
    _run(server, 'cleanup', 'example.com', 'token-1')
    assert server.zones['example.com']['rrsets'] == []
    assert server.changes()[-1] == {
        'name': f'{CHALLENGE}.example.com.', 'type': 'TXT', 'changetype': 'DELETE'}


def test_cleanup_leaves_records_it_did_not_create(pdns):
    server = pdns({'example.com': 'Native'})
    server.zones['example.com']['rrsets'].append({
        'name': f'{CHALLENGE}.example.com.', 'type': 'TXT', 'ttl': 300,
        'records': [{'content': '"someone-elses"', 'disabled': False}]})
    _run(server, 'cleanup', 'example.com', 'token-never-added')
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['someone-elses']
    assert server.changes() == []


def test_a_primary_zone_notifies_its_secondaries(pdns):
    server = pdns({'example.com': 'Master'})
    _run(server, 'auth', 'example.com', 'token-1')
    assert ('PUT', '/api/v1/servers/localhost/zones/example.com./notify') in [
        (method, path) for method, path, _, _ in server.requests]


def test_a_failed_notify_does_not_fail_the_challenge(pdns, capsys):
    """Secondaries still refresh on their own; the record is written."""
    server = pdns({'example.com': 'Master'}, notify_status=500)
    _run(server, 'auth', 'example.com', 'token-1')
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['token-1']
    assert 'notifying the secondaries of example.com failed' in capsys.readouterr().err


@pytest.mark.parametrize(('status', 'expected'), [
    (403, 'or a proxy in front of the PowerDNS API'),
    (422, 'refused the change to zone example.com (HTTP 422)')])
def test_a_zone_that_can_be_read_but_not_written_is_reported(pdns, status, expected):
    """A proxy may let a key read a zone and still refuse the write."""
    server = pdns({'example.com': 'Native'}, write_status=status)
    with pytest.raises(hook.PowerDNSHookError, match=re.escape(expected)):
        _run(server, 'auth', 'example.com', 'token-1')


def test_a_native_zone_is_not_notified(pdns):
    server = pdns({'example.com': 'Native'})
    _run(server, 'auth', 'example.com', 'token-1')
    assert all(method != 'PUT' for method, _, _, _ in server.requests)


# --------------------------------------------------------------------------
# The configuration
# --------------------------------------------------------------------------

@pytest.mark.parametrize('api_url', ['{url}', '{url}/', '{url}/api/v1', '{url}/api/v1/'])
def test_the_api_url_is_accepted_with_or_without_the_api_path(pdns, api_url):
    server = pdns({'example.com': 'Native'})
    hook.run({'api_url': api_url.format(url=server.url), 'api_key': API_KEY}, 'auth',
             {'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 'token-1'})
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['token-1']


def test_a_server_id_is_used_when_set(pdns):
    server = pdns({'example.com': 'Native'}, server_id='ns1')
    _run(server, 'auth', 'example.com', 'token-1', server_id='ns1')
    assert server.values('example.com', f'{CHALLENGE}.example.com') == ['token-1']


def test_the_api_key_is_sent_on_every_request(pdns):
    server = pdns({'example.com': 'Master'})
    _run(server, 'auth', 'sub.example.com', 'token-1')
    assert {key for _, _, key, _ in server.requests} == {API_KEY}


@pytest.mark.parametrize('missing', ['api_url', 'api_key'])
def test_a_missing_credential_is_named(missing):
    config = {'api_url': 'http://127.0.0.1:9', 'api_key': API_KEY}
    config[missing] = ''
    with pytest.raises(hook.PowerDNSHookError, match=missing):
        hook.run(config, 'auth', {'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 't'})


@pytest.mark.parametrize(('api_url', 'reason'), [
    ('file:///etc/passwd', 'must use http or https'),
    ('http://169.254.169.254', 'metadata'),
])
def test_an_api_url_that_is_not_an_api_is_refused_before_any_request(api_url, reason):
    with pytest.raises(hook.PowerDNSHookError, match=reason):
        hook.run({'api_url': api_url, 'api_key': API_KEY}, 'auth',
                 {'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 't'})


def test_the_hook_runs_as_certbot_runs_it(tmp_path):
    """certbot runs the file as a script, where only its own directory is importable."""
    import subprocess
    import sys
    config = tmp_path / 'powerdns.json'
    config.write_text(json.dumps({'api_url': 'http://169.254.169.254', 'api_key': API_KEY}))
    result = subprocess.run(
        [sys.executable, hook.__file__, '--config', str(config), '--action', 'auth'],
        capture_output=True, text=True, timeout=60, cwd=tmp_path,
        env={**os.environ, 'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 't'})
    assert result.returncode == 1
    assert 'PowerDNS challenge failed' in result.stderr and 'metadata' in result.stderr


def test_an_unreachable_api_is_reported_as_such():
    with pytest.raises(hook.PowerDNSHookError, match='could not be reached'):
        hook.run({'api_url': 'http://127.0.0.1:9', 'api_key': API_KEY}, 'auth',
                 {'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 't'})


def test_the_configured_wait_follows_the_record(pdns, monkeypatch):
    server = pdns({'example.com': 'Native'})
    slept = []
    monkeypatch.setattr(hook.time, 'sleep', slept.append)
    monkeypatch.setenv('CERTMATE_DNS_PROPAGATION_SECONDS', '45')
    _run(server, 'auth', 'example.com', 'token-1')
    assert slept == [45]


# --------------------------------------------------------------------------
# As certbot runs it
# --------------------------------------------------------------------------

def _config_file(tmp_path, server):
    path = tmp_path / 'powerdns.json'
    path.write_text(json.dumps({'api_url': server.url, 'api_key': API_KEY}))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return str(path)


def test_main_answers_the_challenge(pdns, tmp_path, monkeypatch):
    server = pdns({'example.com': 'Native'})
    monkeypatch.setenv('CERTBOT_DOMAIN', 'sub.example.com')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    assert hook.main(['--config', _config_file(tmp_path, server), '--action', 'auth']) == 0
    assert server.values('example.com', f'{CHALLENGE}.sub.example.com') == ['token-1']


def test_main_fails_the_challenge_when_the_record_cannot_be_written(pdns, tmp_path, monkeypatch, capsys):
    server = pdns({'other.org': 'Native'})
    monkeypatch.setenv('CERTBOT_DOMAIN', 'example.com')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    assert hook.main(['--config', _config_file(tmp_path, server), '--action', 'auth']) == 1
    assert 'PowerDNS challenge failed: No PowerDNS zone holds' in capsys.readouterr().err


def test_a_failed_cleanup_never_fails_the_issuance(pdns, tmp_path, monkeypatch, capsys):
    server = pdns({'example.com': 'Native'}, statuses={f'{CHALLENGE}.example.com': 403})
    monkeypatch.setenv('CERTBOT_DOMAIN', 'example.com')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    assert hook.main(['--config', _config_file(tmp_path, server), '--action', 'cleanup']) == 0
    assert 'PowerDNS cleanup failed' in capsys.readouterr().err


def test_cleanup_without_a_challenge_does_nothing():
    hook.run({}, 'cleanup', {})


def test_auth_without_a_challenge_is_refused():
    with pytest.raises(hook.PowerDNSHookError, match='CERTBOT_DOMAIN and CERTBOT_VALIDATION'):
        hook.run({'api_url': 'http://127.0.0.1:9', 'api_key': API_KEY}, 'auth', {})
