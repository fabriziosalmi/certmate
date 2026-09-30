"""The bare-metal installer and the systemd unit it installs (#1025).

Verified by running deploy/install.sh on Debian 12, Ubuntu 24.04 and Rocky
Linux 9 (systemd as PID 1): install, first admin and login, a DNS-01 issuance
reaching certbot, an upgrade by re-running it, and a reboot. Each line below
is something one of those runs broke on, or something the unit got wrong
before, and could quietly come back:

* the unit's sandbox (ProtectSystem=strict) left letsencrypt/ read-only, so
  every issuance with a file-based DNS provider failed with
  "[Errno 30] Read-only file system: 'letsencrypt/config/cloudflare-….ini'";
* the unit listened on 0.0.0.0 whatever the installer announced;
* gunicorn 26 tried to create its control socket under the service user's
  home, /opt/certmate, read-only to the service;
* the first installer version chowned all of /opt/certmate to root on
  upgrade, taking the files INSIDE data/ with it: the service could no longer
  read settings.json and crash-looped;
* its health wait had no timeout and hung for half an hour on that crash loop;
* `--exclude=data` would drop any directory named data anywhere in the code;
* asking dnf for `curl` fails on RHEL-family systems that ship curl-minimal.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
INSTALL = (REPO / 'deploy' / 'install.sh').read_text()
UNIT = (REPO / 'certmate.service').read_text()


def _unit_value(key):
    return [l.split('=', 1)[1] for l in UNIT.splitlines() if l.startswith(f'{key}=')]


def test_the_sandbox_lets_the_service_write_dns_credential_files():
    paths = _unit_value('ReadWritePaths')[0].split()
    for d in ('certificates', 'data', 'backups', 'logs', 'letsencrypt'):
        assert f'/opt/certmate/{d}' in paths, d
    assert 'strict' in _unit_value('ProtectSystem')


def test_the_unit_listens_where_the_configuration_says_and_loopback_by_default():
    assert 'CERTMATE_BIND=127.0.0.1:8000' in _unit_value('Environment')
    exec_start = _unit_value('ExecStart')[0]
    assert '--bind ${CERTMATE_BIND}' in exec_start
    assert '--no-control-socket' in exec_start
    # certmate.env is read after the default, so an operator's value wins.
    assert UNIT.index('Environment=CERTMATE_BIND') < UNIT.index('EnvironmentFile=')


def test_the_installer_owns_code_and_state_separately():
    assert 'chown -R root:root "$PREFIX"' not in INSTALL
    assert 'chown -R certmate:certmate "$PREFIX/$d"' in INSTALL


def test_the_health_wait_cannot_hang():
    assert re.search(r'curl -fsS --max-time \d+ "\$probe"', INSTALL)


def test_code_excludes_are_anchored_to_the_top():
    for d in ('data', 'certificates', 'backups', 'logs', 'letsencrypt'):
        assert f'--exclude=./{d}' in INSTALL
        assert f'--exclude={d} ' not in INSTALL


def test_it_asks_only_for_missing_tools():
    assert 'command -v "$cmd"' in INSTALL
    assert 'dnf install -y -q ca-certificates $missing' in INSTALL


def test_it_refuses_a_release_whose_unit_predates_it():
    assert "grep -q 'CERTMATE_BIND' \"$src/certmate.service\"" in INSTALL


def test_it_installs_the_locked_set_the_image_uses():
    assert 'pip sync' in INSTALL and 'requirements.lock' in INSTALL
    assert 'PYTHON_VERSION="3.12"' in INSTALL


@pytest.mark.skipif(not shutil.which('shellcheck'), reason='shellcheck not installed')
def test_shellcheck_is_clean():
    result = subprocess.run(['shellcheck', '-s', 'sh', str(REPO / 'deploy' / 'install.sh')],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout
