"""The command a ShellExecutor runs is logged without the credentials it carries.

certbot takes the EAB key of a CA account only as ``--eab-hmac-key <value>``,
so the value is in the command. The executor logged ``' '.join(cmd)`` at DEBUG
before every run and, at ERROR, when a run timed out (a renewal waits up to 30
minutes for a CA that has stopped answering). The error line is on at the
default log level: the HMAC key, which is the right to issue as that CA
account, reached the log in clear.
"""
import logging
import subprocess
import sys

import pytest

from modules.core.shell import ShellExecutor, redact_command

pytestmark = [pytest.mark.unit]

SECRET = 'ZZ-SECRET-HMAC-VALUE-1234567890abcdef'
KID = 'kid-1234'


def _slow(*extra):
    return [sys.executable, '-c', 'import time; time.sleep(5)', *extra]


def test_the_values_of_the_credential_flags_are_masked():
    cmd = ['certbot', 'certonly', '--eab-kid', KID, '--eab-hmac-key', SECRET,
           '--email', 'a@example.com', '-d', 'x.example.com']

    safe = redact_command(cmd)

    assert SECRET not in ' '.join(safe) and KID not in ' '.join(safe) and 'a@example.com' not in ' '.join(safe)
    assert safe[safe.index('--eab-hmac-key') + 1] == '***'
    assert safe[-2:] == ['-d', 'x.example.com']


def test_the_equals_form_is_masked_too():
    safe = redact_command(['certbot', f'--eab-hmac-key={SECRET}', '--server', 'https://ca.example/dir'])

    assert SECRET not in ' '.join(safe)
    assert safe[1] == '--eab-hmac-key=***'
    assert safe[-1] == 'https://ca.example/dir'


def test_a_command_with_nothing_to_hide_is_unchanged():
    cmd = ['certbot', 'renew', '--quiet', '--cert-name', 'x.example.com']

    assert redact_command(cmd) == cmd


def test_a_timeout_is_logged_without_the_credential(caplog):
    with caplog.at_level(logging.INFO, logger='modules.core.shell'):
        with pytest.raises(subprocess.TimeoutExpired):
            ShellExecutor().run(_slow('--eab-hmac-key', SECRET), timeout=1)

    assert 'timed out' in caplog.text
    assert SECRET not in caplog.text


def test_the_debug_line_before_a_run_is_logged_without_the_credential(caplog):
    with caplog.at_level(logging.DEBUG, logger='modules.core.shell'):
        ShellExecutor().run([sys.executable, '-c', 'pass', '--eab-hmac-key', SECRET])

    assert 'Executing command' in caplog.text
    assert SECRET not in caplog.text
