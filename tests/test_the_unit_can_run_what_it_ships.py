"""Deployment hooks could not start under the systemd unit.

`certmate.service` set:

    Environment=PATH=/opt/certmate/venv/bin

`Environment=PATH=` REPLACES systemd's default PATH rather than prepending to
it. Deployment hooks run as `['sh', '-c', command]` with `os.environ` copied
(modules/core/deployer.py), and `sh` lives in `/bin`, so the lookup raised
FileNotFoundError before the hook's command was ever parsed:

    >>> env['PATH'] = '/opt/certmate/venv/bin'
    >>> subprocess.run(['sh', '-c', 'echo ciao'], env=env)
    FileNotFoundError: [Errno 2] No such file or directory: 'sh'

Every hook on a non-container installation failed, and nothing a hook would
reasonably call — curl, openssl, systemctl, ssh — resolved either. Issuance
itself kept working, because certbot and gunicorn are inside the venv, which is
why this survived: the part under test was the part that still worked.

The venv stays first so the pinned certbot wins over any system one.
"""
import pathlib
import re
import shutil

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
UNIT = REPO / 'certmate.service'
OLD = '/opt/certmate/venv/bin'


def _unit_path():
    for line in UNIT.read_text(encoding='utf-8').splitlines():
        match = re.match(r'Environment=PATH=(.+)$', line.strip())
        if match:
            return match.group(1)
    pytest.fail('the unit no longer sets PATH — read this test before removing it')


def test_a_hook_can_find_a_shell():
    """THE regression, asked the way the deployer asks it: `sh` by name, on
    the PATH the unit actually exports."""
    assert shutil.which('sh', path=_unit_path()), (
        f'no shell on the unit PATH ({_unit_path()}): every deployment hook '
        f'fails with FileNotFoundError before its command runs'
    )


def test_the_old_value_really_was_broken():
    """CONTROL. Without this, the test above passes on any machine whose
    shutil.which falls back to something — it proves the probe can fail."""
    assert shutil.which('sh', path=OLD) is None


def test_the_pinned_tools_still_win():
    """The venv must stay FIRST: a system certbot ahead of it would be an
    unpinned ACME client doing the issuance."""
    entries = _unit_path().split(':')

    assert entries[0] == OLD, f'the venv is no longer first on PATH: {entries}'


def test_the_usual_hook_tools_are_reachable():
    """Not an exhaustive list — the point is that the system directories are
    on the PATH at all, which is what was missing."""
    entries = set(_unit_path().split(':'))

    assert {'/usr/bin', '/bin'} <= entries, (
        f'the system directories are not on the unit PATH: {sorted(entries)}'
    )


def test_the_hook_runner_still_relies_on_the_environment():
    """If hooks ever stop inheriting os.environ, or stop being run through a
    shell looked up by name, the assertions above stop describing anything.
    They are tied to the code here so they cannot quietly become decoration."""
    import inspect

    from modules.core.deployer import DeployManager

    source = inspect.getsource(DeployManager._run_hook)

    assert "['sh', '-c', command]" in source
    assert 'os.environ.copy()' in source
