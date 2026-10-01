"""CertMate's own Azure DNS hook, run against the real Azure SDK (#103).

`certbot-dns-azure` has no release for certbot 4 or later, and the line where it
met the SDK had already broken once (#1072). The hook replaces it: the TXT record
is written with `azure-mgmt-dns` from a certbot `--manual` hook. These tests run
the hook's code on the installed SDK, with only the network replaced
(`requests_mock`) and the token source stubbed, so the request that would reach
Azure is the one asserted on: its method, its path, its body and the ETag headers
that make two challenges on the same name safe.

What the plugin did, and the hook has to keep, is pinned here: the longest zone
wins, several values share one name, cleanup removes only its own, a conflicting
write is retried, and a failed cleanup never fails the issuance.
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests_mock
from azure.core.credentials import AccessToken

from modules.core import azure_dns_hook as hook

pytestmark = [pytest.mark.unit]

SUBSCRIPTION = '00000000-0000-0000-0000-000000000001'
RESOURCE_GROUP = 'rg-dns'
SECRET = 'a-secret-that-must-never-be-printed'
RECORD = re.compile(
    r'https://management\.azure\.com/subscriptions/' + SUBSCRIPTION +
    r'/resourceGroups/' + RESOURCE_GROUP + r'/providers/Microsoft\.Network/dnsZones/'
    r'(?P<zone>[^/]+)/TXT/(?P<name>[^?]+)')
HOOK_SCRIPT = Path(hook.__file__)


class _Credential:
    def get_token(self, *scopes, **kwargs):
        return AccessToken('not-a-real-token', int(time.time()) + 3600)


@pytest.fixture(autouse=True)
def no_token_endpoint_and_no_waiting(monkeypatch):
    """The service principal never leaves the process, and nothing sleeps."""
    monkeypatch.setattr('azure.identity.ClientSecretCredential', lambda **kwargs: _Credential())
    slept = []
    monkeypatch.setattr(hook.time, 'sleep', slept.append)
    return slept


def _config(**overrides):
    config = {'tenant_id': 't', 'client_id': 'c', 'client_secret': SECRET,
              'subscription_id': SUBSCRIPTION, 'resource_group': RESOURCE_GROUP,
              'zones': ['example.org']}
    config.update(overrides)
    return config


def _challenge(domain='www.example.org', validation='token-1'):
    return {'CERTBOT_DOMAIN': domain, 'CERTBOT_VALIDATION': validation}


def _recordset(*values, etag='W/"etag-1"'):
    return {'id': 'x', 'name': 'n', 'etag': etag,
            'properties': {'TTL': 60, 'TXTRecords': [{'value': [v]} for v in values]}}


def _not_found():
    return {'status_code': 404, 'json': {'error': {'code': 'NotFound', 'message': 'no such record'}}}


def _values(request):
    return [r['value'][0] for r in request.json()['properties']['TXTRecords']]


# --------------------------------------------------------------------------
# Choosing the zone and the record
# --------------------------------------------------------------------------

def test_the_longest_configured_zone_wins():
    zones = ['example.org', 'sub.example.org']
    assert hook.zone_for('www.sub.example.org', zones) == 'sub.example.org'
    assert hook.zone_for('www.example.org', zones) == 'example.org'


def test_a_name_is_under_a_zone_only_on_a_label_boundary():
    with pytest.raises(hook.AzureDNSHookError, match='No Azure DNS zone'):
        hook.zone_for('notexample.org', ['example.org'])


def test_a_wildcard_domain_is_validated_under_its_base_name_and_zone_case_is_ignored():
    assert hook.zone_for('*.Example.ORG.', ['EXAMPLE.org']) == 'example.org'
    assert hook.record_name('*.example.org', 'example.org') == '_acme-challenge'


def test_a_name_with_no_configured_zone_lists_the_zones_it_had():
    with pytest.raises(hook.AzureDNSHookError) as err:
        hook.zone_for('www.other.net', ['example.org', 'example.com'])
    assert 'www.other.net' in str(err.value) and 'example.org' in str(err.value)


@pytest.mark.parametrize('domain, zone, expected', [
    ('www.example.org', 'example.org', '_acme-challenge.www'),
    ('example.org', 'example.org', '_acme-challenge'),
    ('a.b.example.org', 'example.org', '_acme-challenge.a.b'),
    # The zone CNAME-delegated challenges are answered in: the record is the apex.
    ('example.org', '_acme-challenge.example.org', '@'),
])
def test_the_record_name_is_relative_to_the_zone(domain, zone, expected):
    assert hook.record_name(domain, zone) == expected


# --------------------------------------------------------------------------
# auth: publishing the challenge
# --------------------------------------------------------------------------

def test_a_challenge_creates_the_record_and_refuses_to_overwrite_a_racing_one():
    with requests_mock.Mocker() as http:
        http.get(RECORD, **_not_found())
        put = http.put(RECORD, status_code=200, json=_recordset('token-1'))
        hook.run(_config(), 'auth', _challenge())

    assert put.call_count == 1
    request = put.last_request
    assert request.path.endswith('/dnszones/example.org/txt/_acme-challenge.www')
    assert _values(request) == ['token-1']
    assert request.json()['properties']['TTL'] == 60
    assert request.headers['If-None-Match'] == '*'
    assert 'If-Match' not in request.headers
    assert request.headers['Authorization'] == 'Bearer not-a-real-token'


def test_a_second_value_on_the_same_name_is_added_not_written_over_the_first():
    """A wildcard and its apex are validated on one `_acme-challenge` name."""
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('token-1'))
        put = http.put(RECORD, status_code=200, json=_recordset('token-1', 'token-2'))
        hook.run(_config(), 'auth', _challenge(validation='token-2'))

    assert sorted(_values(put.last_request)) == ['token-1', 'token-2']
    assert put.last_request.headers['If-Match'] == 'W/"etag-1"'
    assert 'If-None-Match' not in put.last_request.headers


def test_a_value_that_is_already_there_is_not_written_again():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('token-1'))
        put = http.put(RECORD, status_code=200, json=_recordset('token-1'))
        hook.run(_config(), 'auth', _challenge(validation='token-1'))

    assert put.call_count == 0


def test_the_placeholder_value_a_pinned_record_used_to_carry_is_not_kept():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('-'))
        put = http.put(RECORD, status_code=200, json=_recordset('token-1'))
        hook.run(_config(), 'auth', _challenge())

    assert _values(put.last_request) == ['token-1']


def test_a_conflicting_write_is_read_again_and_retried(no_token_endpoint_and_no_waiting):
    """412: someone changed the record between our read and our write."""
    with requests_mock.Mocker() as http:
        reads = http.get(RECORD, [
            {'status_code': 200, 'json': _recordset('token-1', etag='W/"old"')},
            {'status_code': 200, 'json': _recordset('token-1', 'token-3', etag='W/"new"')}])
        writes = http.put(RECORD, [
            {'status_code': 412, 'json': {'error': {'code': 'PreconditionFailed', 'message': 'etag'}}},
            {'status_code': 200, 'json': _recordset('token-1', 'token-2', 'token-3')}])
        hook.run(_config(), 'auth', _challenge(validation='token-2'))

    assert reads.call_count == 2 and writes.call_count == 2
    # The retry wrote what it read the second time, including the other writer's value.
    assert sorted(_values(writes.last_request)) == ['token-1', 'token-2', 'token-3']
    assert writes.last_request.headers['If-Match'] == 'W/"new"'
    assert len(no_token_endpoint_and_no_waiting) == 2     # one jitter, then the propagation wait


def test_conflicts_that_never_stop_end_in_an_error(monkeypatch):
    monkeypatch.setattr(hook, 'MAX_CONFLICT_RETRIES', 2)
    with requests_mock.Mocker() as http:
        http.get(RECORD, **_not_found())
        put = http.put(RECORD, status_code=412, json={'error': {'code': 'PreconditionFailed', 'message': 'etag'}})
        with pytest.raises(Exception) as err:
            hook.run(_config(), 'auth', _challenge())

    assert getattr(err.value, 'status_code', None) == 412
    assert put.call_count == 3


def test_the_wait_follows_the_record_and_is_taken_from_the_environment(monkeypatch, no_token_endpoint_and_no_waiting):
    monkeypatch.setenv('CERTMATE_DNS_PROPAGATION_SECONDS', '45')
    with requests_mock.Mocker() as http:
        http.get(RECORD, **_not_found())
        http.put(RECORD, status_code=200, json=_recordset('token-1'))
        hook.run(_config(), 'auth', _challenge())

    assert no_token_endpoint_and_no_waiting == [45]


@pytest.mark.parametrize('value, expected', [('', 0), ('abc', 0), ('-5', 0), ('99999', 3600), ('180', 180)])
def test_the_wait_is_a_bounded_number_of_seconds(monkeypatch, value, expected):
    monkeypatch.setenv('CERTMATE_DNS_PROPAGATION_SECONDS', value)
    assert hook._wait_seconds() == expected


# --------------------------------------------------------------------------
# cleanup: removing only what this challenge added
# --------------------------------------------------------------------------

def test_cleanup_removes_its_own_value_and_keeps_the_other_challenges():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('token-1', 'token-2'))
        put = http.put(RECORD, status_code=200, json=_recordset('token-2'))
        delete = http.delete(RECORD, status_code=200)
        hook.run(_config(), 'cleanup', _challenge(validation='token-1'))

    assert _values(put.last_request) == ['token-2']
    assert put.last_request.headers['If-Match'] == 'W/"etag-1"'
    assert delete.call_count == 0


def test_cleanup_deletes_the_record_when_nothing_else_is_left():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('token-1'))
        delete = http.delete(RECORD, status_code=200)
        put = http.put(RECORD, status_code=200, json=_recordset())
        hook.run(_config(), 'cleanup', _challenge(validation='token-1'))

    assert delete.call_count == 1 and put.call_count == 0
    assert delete.last_request.headers['If-Match'] == 'W/"etag-1"'


def test_cleanup_of_a_record_that_is_gone_is_not_an_error():
    with requests_mock.Mocker() as http:
        http.get(RECORD, **_not_found())
        delete = http.delete(RECORD, status_code=200)
        hook.run(_config(), 'cleanup', _challenge())

    assert delete.call_count == 0


def test_cleanup_of_a_record_that_vanishes_before_the_delete_is_not_an_error():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('token-1'))
        http.delete(RECORD, **_not_found())
        hook.run(_config(), 'cleanup', _challenge())


def test_cleanup_that_cannot_delete_the_record_says_so_instead_of_pretending():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('token-1'))
        http.delete(RECORD, status_code=403, json={'error': {'code': 'AuthorizationFailed', 'message': 'no'}})
        with pytest.raises(Exception) as err:
            hook.run(_config(), 'cleanup', _challenge())
    assert getattr(err.value, 'status_code', None) == 403


def test_the_sdk_not_being_installed_is_an_error_that_says_how_to_fix_it(monkeypatch):
    monkeypatch.setitem(sys.modules, 'azure.identity', None)
    with pytest.raises(hook.AzureDNSHookError, match='requirements-azure.txt'):
        hook._client(_config())


def test_cleanup_leaves_a_record_that_does_not_hold_its_value_alone():
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=200, json=_recordset('someone-elses'))
        put = http.put(RECORD, status_code=200, json=_recordset('someone-elses'))
        delete = http.delete(RECORD, status_code=200)
        hook.run(_config(), 'cleanup', _challenge(validation='token-1'))

    assert put.call_count == 0 and delete.call_count == 0


def test_a_cleanup_with_no_challenge_in_the_environment_does_nothing():
    hook.run(_config(), 'cleanup', {})


def test_an_auth_with_no_challenge_in_the_environment_is_an_error():
    with pytest.raises(hook.AzureDNSHookError, match='CERTBOT_DOMAIN'):
        hook.run(_config(), 'auth', {})


# --------------------------------------------------------------------------
# What certbot sees: exit codes and what is printed
# --------------------------------------------------------------------------

def _write(tmp_path, config):
    path = tmp_path / 'azure.json'
    path.write_text(json.dumps(config), encoding='utf-8')
    return str(path)


def test_a_failed_challenge_exits_nonzero_and_says_why_without_printing_the_secret(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('CERTBOT_DOMAIN', 'www.example.org')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=403, json={'error': {'code': 'AuthorizationFailed', 'message': 'not allowed'}})
        code = hook.main(['--config', _write(tmp_path, _config()), '--action', 'auth'])

    err = capsys.readouterr().err
    assert code == 1
    assert 'Azure DNS challenge failed' in err and 'AuthorizationFailed' in err
    assert SECRET not in err


def test_a_failed_cleanup_exits_zero_so_it_cannot_fail_the_issuance(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('CERTBOT_DOMAIN', 'www.example.org')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    with requests_mock.Mocker() as http:
        http.get(RECORD, status_code=500, json={'error': {'code': 'InternalError', 'message': 'boom'}})
        code = hook.main(['--config', _write(tmp_path, _config()), '--action', 'cleanup'])

    assert code == 0
    assert 'Azure DNS cleanup failed' in capsys.readouterr().err


def test_a_missing_credential_is_named_by_field_and_never_by_value(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('CERTBOT_DOMAIN', 'www.example.org')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    config = _config()
    del config['client_id']
    code = hook.main(['--config', _write(tmp_path, config), '--action', 'auth'])

    err = capsys.readouterr().err
    assert code == 1 and 'client_id' in err and SECRET not in err


def test_a_domain_with_no_zone_is_refused_before_anything_is_sent(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('CERTBOT_DOMAIN', 'www.other.net')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'token-1')
    with requests_mock.Mocker() as http:
        code = hook.main(['--config', _write(tmp_path, _config()), '--action', 'auth'])
        assert http.call_count == 0
    assert code == 1 and 'No Azure DNS zone' in capsys.readouterr().err


@pytest.mark.parametrize('content', ['not json', '[]', ''])
def test_a_config_that_is_not_a_json_object_is_an_error_not_a_traceback(tmp_path, capsys, content):
    path = tmp_path / 'azure.json'
    path.write_text(content, encoding='utf-8')
    assert hook.main(['--config', str(path), '--action', 'auth']) == 1
    assert 'Traceback' not in capsys.readouterr().err


def test_a_config_file_that_is_gone_is_an_error_for_auth_and_a_warning_for_cleanup(tmp_path, capsys):
    missing = str(tmp_path / 'gone.json')
    assert hook.main(['--config', missing, '--action', 'auth']) == 1
    assert hook.main(['--config', missing, '--action', 'cleanup']) == 0


def test_run_as_a_script_the_way_certbot_runs_it(tmp_path):
    """The exact invocation certbot uses: the interpreter, the file, two flags, the environment."""
    environment = {'PATH': '/usr/bin:/bin'}          # no CERTBOT_* variables at all
    result = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT), '--config', _write(tmp_path, _config()), '--action', 'auth'],
        capture_output=True, text=True, env=environment, timeout=60)
    assert result.returncode == 1
    assert 'CERTBOT_DOMAIN' in result.stderr and 'Traceback' not in result.stderr
    cleanup = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT), '--config', _write(tmp_path, _config()), '--action', 'cleanup'],
        capture_output=True, text=True, env=environment, timeout=60)
    assert cleanup.returncode == 0
