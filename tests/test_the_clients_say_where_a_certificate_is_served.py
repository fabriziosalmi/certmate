"""The SDK, the CLI and the MCP server say where a certificate is served (#854).

Every certificate answer carries `host` since API contract 2.59 (#1364): the
address of an IP certificate, the host its metadata names, the name
otherwise. The SDK reads it into a field, as it does `domain`; the CLI shows
it when it is not the certificate's name; the MCP server, which passes the
API's answer through, says in its tool description that it is there.
"""
import pathlib
import re

import pytest
from certmate import Certificate
from typer.testing import CliRunner

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.mark.parametrize('answer,host,ip_address', [
    ({'domain': 'internal.example.net', 'host': 'example.com', 'ip_address': None}, 'example.com', None),
    ({'domain': 'ip-1-1-1-1', 'host': '1.1.1.1', 'ip_address': '1.1.1.1'}, '1.1.1.1', '1.1.1.1'),
    ({'domain': 'shop.example.com'}, None, None),   # a server before 2.59
])
def test_the_sdk_reads_where_a_certificate_is_served(answer, host, ip_address):
    certificate = Certificate.from_dict(answer)
    assert (certificate.domain, certificate.host, certificate.ip_address) == (
        answer['domain'], host, ip_address)


def _info(answer):
    pytest.importorskip('certmate_cli', reason='certmate-cli not installed')
    from unittest.mock import MagicMock, patch

    from certmate_cli.main import app
    client = MagicMock()
    client.get_certificate.return_value = Certificate.from_dict(answer)
    with patch('certmate_cli.main._client', return_value=client):
        result = CliRunner().invoke(app, ['cert', 'info', answer['domain']])
    assert result.exit_code == 0, result.output
    return [line.strip() for line in result.output.splitlines()]


def test_the_cli_shows_a_host_that_is_not_the_name():
    lines = _info({'domain': 'internal.example.net', 'host': 'example.com'})
    assert [line for line in lines if line.startswith('host:')] == ['host:        example.com']


@pytest.mark.parametrize('answer', [
    {'domain': 'shop.example.com', 'host': 'shop.example.com'},
    {'domain': 'shop.example.com'},
])
def test_the_cli_shows_no_host_for_a_certificate_served_at_its_name(answer):
    assert not [line for line in _info(answer) if line.startswith('host:')]


def test_the_mcp_server_says_the_answer_carries_the_host():
    source = (REPO / 'mcp' / 'index.js').read_text(encoding='utf-8')
    tool = re.search(r'name: "certmate_get_certificate",\s*description: "([^"]+)"', source)
    assert tool, 'certmate_get_certificate not found in mcp/index.js'
    assert 'host (where the certificate is served' in tool.group(1)
