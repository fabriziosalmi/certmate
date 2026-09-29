"""The sanitised certbot stderr is what goes to the log, not just to the caller.

`sanitize_certbot_stderr` exists because certbot-dns-azure and a few other
plugins echo the offending credentials `.ini` line verbatim when they fail to
parse it. Its docstring says so. Both failure paths — create and renew — called
it and sent the result to the API client.

Both then logged the **raw** stderr, on the reasoning that the log is internal
and an operator debugging a failed issuance wants everything. The create path
said as much in a comment that began "Log the FULL stderr internally", directly
above a line that wrote the secret material the comment two lines further down
admitted was there.

A log file outlives the request, is shipped wherever logs are shipped, and ends
up in a support bundle. "Internal" was doing a great deal of work in that
sentence. The redacted copy goes to both places now.

What these tests do: they run the real create and renew paths against a
certbot that fails with that stderr (a mock shell, #666 S6 made both paths go
through one builder, `_certbot_failure`), and assert on the records a log
handler receives. They used to read the two call sites from the AST, because
neither path could be driven without certbot; pinning the source is what
blocked the next correct change, twice.
"""
import logging

import pytest

from modules.core.utils import sanitize_certbot_stderr

pytestmark = [pytest.mark.unit]

# The shape certbot-dns-azure produces when it cannot parse its credentials.
LEAKY_STDERR = (
    "Error parsing credentials configuration file:\n"
    "  dns_azure_sp_client_secret = hunter2-THE-ACTUAL-SECRET\n"
    "Please see https://certbot-dns-azure.readthedocs.io for the format.\n"
)
SECRET = 'hunter2-THE-ACTUAL-SECRET'


def test_the_sanitiser_removes_the_secret_at_all():
    """Guard the guard: if this ever stops stripping, every assertion below
    would pass for the wrong reason."""
    assert SECRET not in sanitize_certbot_stderr(LEAKY_STDERR)


def test_the_sanitiser_keeps_the_part_an_operator_needs():
    cleaned = sanitize_certbot_stderr(LEAKY_STDERR)
    assert 'Error parsing credentials configuration file' in cleaned


def _log_of(caplog):
    return '\n'.join(record.getMessage() for record in caplog.records)


def _fail(tmp_path, path, caplog):
    """Run the real *path* against a certbot that echoes a secret on stderr."""
    from modules.core import certificates as certs_module
    from tests.test_one_certbot_failure_message import (
        _create, _manager, _renew, _shell)

    caplog.set_level(logging.DEBUG, logger=certs_module.logger.name)
    mgr = _manager(tmp_path, _shell(1, stderr=LEAKY_STDERR))
    raised = _create(mgr) if path == 'create' else _renew(tmp_path, mgr)
    return raised, _log_of(caplog)


@pytest.mark.parametrize('path', ['create', 'renew'])
def test_neither_failure_path_writes_the_secret_to_the_log(tmp_path, caplog, path):
    """The redacted text is what a log handler receives."""
    _, logged = _fail(tmp_path, path, caplog)
    assert SECRET not in logged
    assert 'Error parsing credentials configuration file' in logged


@pytest.mark.parametrize('path', ['create', 'renew'])
def test_neither_failure_path_raises_the_secret(tmp_path, caplog, path):
    raised, _ = _fail(tmp_path, path, caplog)
    assert SECRET not in raised
    assert 'Error parsing credentials configuration file' in raised


def test_the_domain_cannot_forge_a_second_log_line(caplog):
    """The convention this file now follows is `%r` with logging arguments.
    repr escapes a newline to a literal backslash-n, so a domain carrying one
    cannot open a line of its own."""
    from modules.core import certificates as certs_module

    caplog.set_level(logging.DEBUG, logger=certs_module.logger.name)
    forged = 'evil.example\nERROR certmate: all certificates revoked'
    certs_module.logger.error("Certbot failed for %r: %r", forged, 'boom')

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert '\n' not in message
    assert '\\n' in message
