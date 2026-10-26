"""The SDK and the CLI name a certificate apart from its domain (#854, step 4: #1149).

`POST /api/certificates/create` takes `name` since API contract 2.61 (#1367). The
SDK's `create_certificate` takes `name=`, and the CLI's `cert create` takes
`--name`. A server before 2.61 does not refuse the field: it ignores it, and
issues the certificate under its domain. So a request that names a certificate
asks the server's contract first (`/health`) and is refused, before anything
is sent, by a server that would ignore the name. The MCP server's create tool
does the same; its test is `mcp/test-name.js`.
"""
import json

import httpx
import pytest
from certmate import Client, Job

pytestmark = [pytest.mark.unit]

HOST = 'example.com'
NAME = 'internal.example.com'


def _client(contract):
    """A client whose server reports *contract* (None: reports none) and accepts a create."""
    seen = []

    def answer(request):
        seen.append(request)
        if request.url.path == '/health':
            body = {'status': 'healthy'}
            if contract is not None:
                body['api_contract_version'] = contract
            return httpx.Response(200, json=body)
        if request.url.path == '/api/certificates/create':
            sent = json.loads(request.content)
            return httpx.Response(202, json={
                'job_id': 'j1', 'status': 'queued', 'operation': 'create',
                'domain': sent.get('name') or sent['domain'],
                'status_url': '/api/certificates/jobs/j1'})
        return httpx.Response(404, json={'error': 'not here'})

    client = Client('http://certmate.test', token='t')
    client._http = httpx.Client(base_url='http://certmate.test', transport=httpx.MockTransport(answer))
    return client, seen


def _posted(seen):
    return [json.loads(r.content) for r in seen if r.method == 'POST']


@pytest.mark.parametrize('contract', ['2.61', '2.70', '3.0'])
def test_the_sdk_sends_the_name_to_a_server_that_takes_it(contract):
    client, seen = _client(contract)

    job = client.create_certificate(HOST, name=NAME)

    assert [(body['domain'], body['name']) for body in _posted(seen)] == [(HOST, NAME)]
    assert job.domain == NAME


@pytest.mark.parametrize('contract', ['2.60', '2.9', None, 'not-a-version'])
def test_the_sdk_refuses_a_name_a_server_would_ignore_before_sending_anything(contract):
    from certmate import UnsupportedByServer
    client, seen = _client(contract)

    with pytest.raises(UnsupportedByServer, match=r'2\.61'):
        client.create_certificate(HOST, name=NAME)

    assert _posted(seen) == []


@pytest.mark.parametrize('name', [None, ''])
def test_the_sdk_asks_nothing_of_the_server_without_a_name(name):
    client, seen = _client('2.60')

    client.create_certificate(HOST, name=name)

    assert [r.url.path for r in seen] == ['/api/certificates/create']
    assert 'name' not in _posted(seen)[0]


# --- the CLI ------------------------------------------------------------------------

def _cli(args, contract='2.61', **methods):
    """Run the CLI against a stand-in client whose server reports *contract*,
    under the SDK's own rule for it."""
    pytest.importorskip('certmate_cli', reason='certmate-cli not installed')
    from unittest.mock import MagicMock, patch

    from certmate_cli.main import app
    from typer.testing import CliRunner
    client = MagicMock()
    for method, value in methods.items():
        getattr(client, method).return_value = value
    client.api_contract_version.return_value = contract
    client.require_contract.side_effect = (
        lambda needed, field: Client.require_contract(client, needed, field))
    with patch('certmate_cli.main._client', return_value=client):
        result = CliRunner().invoke(app, args)
    output = result.output
    try:
        output += result.stderr
    except (AttributeError, ValueError):
        pass
    return result, client, output


def test_the_cli_passes_the_name():
    result, client, output = _cli(['cert', 'create', HOST, '--name', NAME, '--no-wait'],
                                  create_certificate=Job.from_dict({'job_id': 'j1', 'domain': NAME}))
    assert result.exit_code == 0, output
    assert client.create_certificate.call_args.kwargs['name'] == NAME


def test_the_cli_passes_no_name_when_given_none():
    result, client, output = _cli(['cert', 'create', HOST, '--no-wait'],
                                  create_certificate=Job.from_dict({'job_id': 'j1', 'domain': HOST}))
    assert result.exit_code == 0, output
    assert client.create_certificate.call_args.kwargs['name'] is None


def test_the_cli_says_what_it_issued_and_under_which_name():
    result, _, output = _cli(['cert', 'create', HOST, '--name', NAME, '--wait'],
                             create_certificate=Job.from_dict(
                                 {'job_id': 'j1', 'domain': NAME, 'status': 'succeeded'}))
    assert result.exit_code == 0, output
    assert f'{HOST} as {NAME}' in output


@pytest.mark.parametrize('name', ['*.example.com', '../etc', 'two words'])
def test_a_dry_run_refuses_a_name_the_server_would_refuse(name):
    result, client, output = _cli(['cert', 'create', HOST, '--name', name, '--dry-run'])
    assert result.exit_code == 1, output
    assert 'name' in output
    client.create_certificate.assert_not_called()


@pytest.mark.parametrize('contract,code', [('2.61', 0), ('2.60', 1), (None, 1)])
def test_a_dry_run_says_whether_the_server_takes_a_name(contract, code):
    result, client, output = _cli(['cert', 'create', HOST, '--name', NAME, '--dry-run'],
                                  contract=contract)
    assert result.exit_code == code, output
    assert (f'as {NAME}' in output) == (code == 0)
    client.create_certificate.assert_not_called()
