"""A job on the self-hosted runner installs only packages whose hashes the repository wrote down.

What a job installs runs on the machine the job runs on. On a hosted runner that machine is
thrown away after the job, with a read-only token. On the self-hosted host it is not: the UI
suite runs there on every frontend pull request, and the real-certificate E2E runs there with
the Cloudflare token in its environment. Both used to run ``pip install --upgrade pip`` and
``pip install -r requirements.txt``, so the pip and every transitive package on that host were
whatever PyPI served that minute, unreviewed. An audit (code-metrics, supply chain) found the
unhashed installs in CI.

The fix is the image's own sequence, which the typecheck job in ci.yml already used: pip from
requirements-build.lock and the locked set from requirements.lock, both with --require-hashes,
then the test requirements constrained by requirements.constraints (the lock's pins without
hashes). The floating install of requirements.txt stays in ci.yml's ``test`` job, on a hosted
runner, because that is the install path docs/installation.md documents and someone has to
notice when it breaks.
"""
import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / '.github' / 'workflows'

PIP_INSTALL = re.compile(r'\bpip\s+install\b')
HASHED = re.compile(r'\bpip\s+install\s+--require-hashes\s+-r\s+requirements[\w.-]*\.lock\b')
CONSTRAINED = re.compile(r'\bpip\s+install\s+-c\s+requirements[\w.-]*\.constraints\s+-r\s+\S+')
LOCKED_SET = re.compile(r'\bpip\s+install\s+--require-hashes\s+-r\s+requirements\.lock\b')


def _self_hosted(job):
    runs_on = job.get('runs-on')
    labels = runs_on if isinstance(runs_on, list) else [runs_on]
    return 'self-hosted' in labels


def _pip_lines(job):
    return [
        line.strip()
        for step in job.get('steps', [])
        for line in (step.get('run') or '').splitlines()
        if PIP_INSTALL.search(line) and not line.strip().startswith('#')
    ]


def self_hosted_installs():
    """Every self-hosted job that installs something, as (workflow:job, pip install lines)."""
    found = []
    for path in sorted(WORKFLOWS.glob('*.yml')):
        workflow = yaml.safe_load(path.read_text())
        for name, job in (workflow.get('jobs') or {}).items():
            if _self_hosted(job) and _pip_lines(job):
                found.append((f'{path.name}:{name}', _pip_lines(job)))
    return found


def unhashed(lines):
    """The lines of one job that would install something no hash covers."""
    wrong = [line for line in lines if not (HASHED.search(line) or CONSTRAINED.search(line))]
    # A constraints file pins versions, not files: it is only safe on top of the hashed lock.
    if any(CONSTRAINED.search(line) for line in lines) and not any(LOCKED_SET.search(line) for line in lines):
        wrong.append('-c requirements.constraints without the hashed requirements.lock before it')
    return wrong


def test_the_self_hosted_jobs_are_found():
    names = [name for name, _ in self_hosted_installs()]
    assert 'ui-tests.yml:ui' in names and 'e2e-staging.yml:e2e-staging' in names, (
        f'the self-hosted jobs moved or stopped installing: this test has lost its subject ({names})')


@pytest.mark.parametrize('where,lines', self_hosted_installs(), ids=[n for n, _ in self_hosted_installs()])
def test_a_self_hosted_job_installs_only_hashed_packages(where, lines):
    wrong = unhashed(lines)
    assert not wrong, (
        f'{where} runs on the self-hosted host and installs packages no hash covers:\n  '
        + '\n  '.join(wrong)
        + '\nInstall pip from requirements-build.lock and the set from requirements.lock with '
        '--require-hashes, then extras with -c requirements.constraints, as the typecheck job does.')


@pytest.mark.parametrize('lines', [
    ['python -m pip install --upgrade pip'],
    ['pip install -r requirements.txt'],
    ['pip install -r requirements-test.txt'],
    ['pip install -c requirements.constraints -r requirements-test.txt'],
    ['pip install --require-hashes -r requirements-build.lock', 'pip install playwright'],
])
def test_the_check_sees_an_unhashed_install(lines):
    assert unhashed(lines), lines


def test_the_check_accepts_the_typecheck_sequence():
    assert unhashed([
        'python -m pip install --require-hashes -r requirements-build.lock',
        'pip install --require-hashes -r requirements.lock',
        'pip install -c requirements.constraints -r requirements-test.txt',
    ]) == []
