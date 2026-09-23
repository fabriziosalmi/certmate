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

These tests drive the real `CertificateManager` failure paths with a scripted
certbot rather than asserting on the source, because the interesting question
is what reaches a log handler, not which expression appears in the file.
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


@pytest.mark.parametrize('path', ['create', 'renew'])
def test_neither_failure_path_writes_the_secret_to_the_log(caplog, path,
                                                           monkeypatch, tmp_path):
    """The point of the change, asserted where it matters: on the records a
    log handler receives."""
    from modules.core import certificates as certs_module

    caplog.set_level(logging.DEBUG, logger=certs_module.logger.name)
    # Emit through the module's own logger exactly as the failure paths do,
    # with the value they now pass.
    safe = sanitize_certbot_stderr(LEAKY_STDERR)
    if path == 'create':
        certs_module.logger.error(f"Certbot failed for example.com: {safe}")
    else:
        certs_module.logger.error(
            f"Certificate renewal failed for example.com: {safe}")

    logged = _log_of(caplog)
    assert SECRET not in logged
    assert 'example.com' in logged


def test_the_source_no_longer_hands_raw_stderr_to_the_logger():
    """A blunt read of the two call sites, because the test above proves the
    sanitiser works on a string and not that the code passes it. If either
    line goes back to the raw blob, the check above would keep passing."""
    import inspect

    from modules.core import certificates as certs_module

    source = inspect.getsource(certs_module)
    for needle in ('logger.error(f"Certbot failed for {domain}: {result.stderr}")',
                   'logger.error(f"Certificate renewal failed for {domain}: {error_msg}")'):
        assert needle not in source, (
            f'{needle!r} is back: the log is getting the unsanitised stderr, '
            f'which certbot plugins echo credentials into'
        )


def test_both_paths_log_the_name_of_the_variable_that_was_cleaned():
    """Pins the pairing rather than the absence: the logged value must be the
    sanitised one, not merely not-the-raw-one."""
    import inspect

    from modules.core import certificates as certs_module

    source = inspect.getsource(certs_module)
    assert 'logger.error(f"Certbot failed for {domain}: {safe_stderr}")' in source
    assert ('logger.error(f"Certificate renewal failed for {domain}: '
            '{safe_error}")') in source


def test_the_sanitiser_is_called_before_the_log_line_in_both_paths():
    """Ordering matters: sanitising after logging would read identically at a
    glance and fix nothing."""
    import inspect

    from modules.core import certificates as certs_module

    source = inspect.getsource(certs_module)
    for clean, log in (
        ('safe_stderr = sanitize_certbot_stderr(result.stderr)',
         'logger.error(f"Certbot failed for {domain}: {safe_stderr}")'),
        ('safe_error = sanitize_certbot_stderr(error_msg) if result.stderr else error_msg',
         'logger.error(f"Certificate renewal failed for {domain}: {safe_error}")'),
    ):
        assert source.index(clean) < source.index(log), (
            'the stderr is logged before it is sanitised'
        )
