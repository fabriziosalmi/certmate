"""The Ansible role (#1031).

Verified against a fresh Debian 13 host over SSH: the role installed Docker
itself, CertMate came up healthy (token 200, anonymous 401, loopback only,
.env mode 600), a second run reported changed=0, rotating the token recreated
the container ONCE and the new token worked, a run with no secrets stopped at
the assertion, and the instance was healthy after a reboot. Two defects that
run found, pinned below: minimal hosts have no curl for Docker's script, and a
handler recreated the container a second time after `compose up` already had.
"""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

ROLE = Path(__file__).resolve().parent.parent / 'deploy' / 'ansible' / 'roles' / 'certmate'
TASKS = yaml.safe_load((ROLE / 'tasks' / 'main.yml').read_text())


def _task(name):
    return next(t for t in TASKS if t['name'] == name)


def _modules(task):
    return [k for k in task if k.startswith('ansible.')]


def test_only_builtin_modules_are_used():
    for task in TASKS:
        for module in _modules(task):
            assert module.startswith('ansible.builtin.'), (task['name'], module)


def test_it_refuses_to_run_without_its_secrets():
    that = _task('Refuse to run without the required secrets')['ansible.builtin.assert']['that']
    assert 'certmate_api_token | length >= 32' in that
    assert 'certmate_secret_key | length >= 32' in that


def test_curl_is_there_before_dockers_script_needs_it():
    names = [t['name'] for t in TASKS]
    assert names.index("Install what Docker's install script needs") < names.index(
        'Install Docker Engine and the compose plugin')


def test_the_env_file_is_private_and_never_logged():
    task = _task('Write the environment file')
    assert task['ansible.builtin.template']['mode'] == '0600'
    assert task['no_log'] is True


def test_nothing_recreates_the_container_a_second_time():
    assert not (ROLE / 'handlers').exists()
    assert not any('notify' in t for t in TASKS)


@pytest.mark.skipif(not shutil.which('ansible-playbook'), reason='ansible not installed')
def test_the_example_playbook_parses():
    site = ROLE.parent.parent / 'site.yml'
    result = subprocess.run(['ansible-playbook', '--syntax-check', '-i', 'localhost,', str(site)],
                            capture_output=True, text=True,
                            env={'ANSIBLE_ROLES_PATH': str(ROLE.parent), 'PATH': '/usr/bin:/bin:/opt/homebrew/bin'})
    assert result.returncode == 0, result.stderr
