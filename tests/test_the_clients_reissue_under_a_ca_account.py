"""The CLI reissues under the CA account it is given (#1546).

`POST /api/certificates/<domain>/reissue` takes `ca_account_id` since API
contract 2.76 (#1465): an id is that account, `""` is the CA's default account,
and an omitted field keeps the account the certificate was issued under. The
SDK passes whatever body it is given, but `certmate cert reissue` had no option
for it, so a reissue from the CLI always kept the recorded account.

A server before 2.76 does not refuse the field, it ignores it, and the reissue
quietly keeps the recorded account: the very thing the option is there to
change. So a reissue that names an account asks the server's contract first and
is refused, before anything is sent, by a server that would ignore it.

These drive the real CLI over the real SDK against a mock transport, so what is
checked is the request body that leaves the process, not a call on a mock. The
MCP server's reissue tool does the same; its test is `mcp/test-ca-account.js`.
"""
import json
import re
from unittest.mock import patch

import httpx
import pytest
from certmate import Client

pytestmark = [pytest.mark.unit]

pytest.importorskip('certmate_cli', reason='certmate-cli not installed')
from certmate_cli.main import app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

DOMAIN = 'example.com'
REISSUE = f'/api/certificates/{DOMAIN}/reissue'


def _run(args, contract='2.76'):
    """Run the CLI against a server that reports *contract* and accepts a reissue."""
    seen = []

    def answer(request):
        seen.append(request)
        if request.url.path == '/health':
            body = {'status': 'healthy'}
            if contract is not None:
                body['api_contract_version'] = contract
            return httpx.Response(200, json=body)
        if request.url.path == REISSUE:
            return httpx.Response(200, json={'message': 'reissued', 'domain': DOMAIN})
        return httpx.Response(404, json={'error': 'not here'})

    client = Client('http://certmate.test', token='t')
    client._http = httpx.Client(base_url='http://certmate.test',
                                transport=httpx.MockTransport(answer))
    with patch('certmate_cli.main._client', return_value=client):
        result = CliRunner().invoke(app, ['cert', 'reissue', DOMAIN, *args])
    output = result.output
    try:
        output += result.stderr
    except (AttributeError, ValueError):
        pass
    return result, seen, output


def _reissues(seen):
    return [json.loads(r.content) for r in seen
            if r.method == 'POST' and r.url.path == REISSUE]


def test_without_the_option_the_field_is_left_out_and_nothing_is_asked_first():
    # An omitted field keeps the recorded account, on any server, so the
    # contract is not asked: an old server must still take a plain reissue.
    result, seen, output = _run([], contract='2.75')

    assert result.exit_code == 0, output
    assert _reissues(seen) == [{}]
    assert [r.url.path for r in seen] == [REISSUE]


@pytest.mark.parametrize('args', [['--ca-account', 'acct-2'], ['--ca-account=acct-2']])
def test_an_account_id_is_sent_as_given(args):
    result, seen, output = _run(args)

    assert result.exit_code == 0, output
    assert _reissues(seen) == [{'ca_account_id': 'acct-2'}]


@pytest.mark.parametrize('args', [['--ca-account', ''], ['--ca-account=']])
def test_an_empty_value_is_sent_as_the_cas_default_account(args):
    result, seen, output = _run(args)

    assert result.exit_code == 0, output
    assert _reissues(seen) == [{'ca_account_id': ''}]


def test_the_account_travels_with_the_sans():
    result, seen, output = _run(['--san', 'a.example.com,b.example.com', '--ca-account', 'acct-2'])

    assert result.exit_code == 0, output
    assert _reissues(seen) == [{'san_domains': ['a.example.com', 'b.example.com'],
                                'ca_account_id': 'acct-2'}]


@pytest.mark.parametrize('contract', ['2.75', '2.9', None])
@pytest.mark.parametrize('account', ['acct-2', ''])
def test_a_server_that_would_ignore_the_account_is_refused_before_anything_is_sent(contract, account):
    result, seen, output = _run(['--ca-account', account], contract=contract)

    assert result.exit_code == 1, output
    assert '2.76' in output
    assert _reissues(seen) == []


def test_the_help_says_what_each_value_means():
    result = CliRunner().invoke(app, ['cert', 'reissue', '--help'], terminal_width=200)

    assert result.exit_code == 0, result.output
    # Rich colours the help where it sees a CI (GITHUB_ACTIONS) and splits
    # '--ca-account' with escape codes, so they go first; then the box edges,
    # so a wrapped sentence reads as one.
    plain = re.sub(r'\x1b\[[0-9;]*m', '', result.output)
    text = ' '.join(plain.replace('│', ' ').split())
    assert '--ca-account' in text
    assert "CA's default account" in text
    assert 'keep' in text
