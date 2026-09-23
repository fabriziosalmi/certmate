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

What these tests do, precisely, because the distinction matters: one pair
emits through the module's own logger with the values the failure paths now
pass, and asserts on the records a handler receives; another reads the two
call sites from the AST and asserts which names they interpolate. Neither
constructs a CertificateManager — the create path needs certbot, a DNS
provider and a filesystem — so the second is what stops the first passing
while the code quietly goes back to the raw blob.
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


def _logged_stderr_arguments():
    """For each `logger.error` in certificates.py whose message mentions a
    certbot failure, the names it interpolates.

    Read from the AST rather than by matching the source text. An earlier
    version of this file asserted the exact f-string, which meant a genuine
    improvement — moving to `%r` and logging arguments, the convention every
    other domain-carrying line here already follows — broke the test that was
    supposed to protect the property. A test that pins the spelling instead of
    the property will block the next correct change too.
    """
    import ast
    import inspect

    from modules.core import certificates as certs_module

    tree = ast.parse(inspect.getsource(certs_module))
    found = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'error'
                and node.args):
            continue
        first = node.args[0]
        text = first.value if isinstance(first, ast.Constant) else ''
        if not isinstance(text, str):
            continue
        if 'Certbot failed' in text:
            key = 'create'
        elif 'Certificate renewal failed' in text:
            key = 'renew'
        else:
            continue
        found[key] = {ast.unparse(a) for a in node.args[1:]} | {
            ast.unparse(v) for v in getattr(first, 'values', [])}
    return found


@pytest.mark.parametrize('path', ['create', 'renew'])
def test_neither_failure_path_writes_the_secret_to_the_log(caplog, path):
    """The redacted text is what a log handler receives."""
    from modules.core import certificates as certs_module

    caplog.set_level(logging.DEBUG, logger=certs_module.logger.name)
    safe = sanitize_certbot_stderr(LEAKY_STDERR)
    if path == 'create':
        certs_module.logger.error("Certbot failed for %r: %r", 'example.com', safe)
    else:
        certs_module.logger.error("Certificate renewal failed for %r: %r",
                                  'example.com', safe)

    logged = _log_of(caplog)
    assert SECRET not in logged
    expected = ('Certbot failed' if path == 'create' else 'Certificate renewal failed')
    assert logged == f"{expected} for 'example.com': {safe!r}"


@pytest.mark.parametrize('path,clean,raw', [
    ('create', 'safe_stderr', 'result.stderr'),
    ('renew', 'safe_error', 'error_msg'),
])
def test_each_failure_path_logs_the_sanitised_name_and_not_the_raw_one(path, clean, raw):
    """The behaviour test above proves the sanitiser works on a string, not
    that the code passes it. This reads what the call actually interpolates."""
    logged = _logged_stderr_arguments()
    assert path in logged, f'no certbot failure log line found for the {path} path'
    assert clean in logged[path], (
        f'the {path} path no longer logs {clean}; it logs {logged[path]}'
    )
    assert raw not in logged[path], (
        f'{raw} is back in the {path} path log line: certbot plugins echo '
        f'credentials into it'
    )


def test_the_sanitiser_is_called_before_the_log_line_in_both_paths():
    """Ordering matters: sanitising after logging would read identically at a
    glance and fix nothing."""
    import inspect

    from modules.core import certificates as certs_module

    source = inspect.getsource(certs_module)
    for clean_call, log_marker in (
        ('safe_stderr = sanitize_certbot_stderr(result.stderr)', 'Certbot failed for'),
        ('safe_error = sanitize_certbot_stderr(error_msg) if result.stderr else error_msg',
         'Certificate renewal failed for'),
    ):
        assert source.index(clean_call) < source.index(log_marker), (
            'the stderr is logged before it is sanitised'
        )


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
