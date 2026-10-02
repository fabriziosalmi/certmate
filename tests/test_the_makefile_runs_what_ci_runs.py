"""The Makefile and CONTRIBUTING.md run what CI runs, and say so only while it is true (#1091).

The Makefile called itself the "single source of truth" and `make ci` "identical to what
GitHub Actions runs". It was neither: `make lint` did not run the complexity or exception
budgets (the check that failed #1089's 3.14 leg), `make test` ran a different set of tests,
`make format` would have rewritten 641 of 642 Python files and CI never uses it,
`make docker-test` could not install its own requirements, and `make pre-commit` had no
config to run. CONTRIBUTING.md had once been corrected for the same drift ("character for
character") and nothing kept it corrected: it still left out the exception budget.

This reads what the `test` job of ci.yml runs and fails when the Makefile or the gate table
in CONTRIBUTING.md differs from it. It reads the real files, not a copy of their contents,
so adding a check to CI without adding it here is a red test, not a surprise on someone's PR.
"""
import pathlib
import re

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
MAKEFILE = (REPO / 'Makefile').read_text(encoding='utf-8')
CONTRIBUTING = (REPO / 'CONTRIBUTING.md').read_text(encoding='utf-8')
CI = yaml.safe_load((REPO / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8'))
RELEASE = (REPO / 'scripts' / 'release.sh').read_text(encoding='utf-8')
TEST_REQUIREMENTS = (REPO / 'requirements-test.txt').read_text(encoding='utf-8')


def _commands(job='test'):
    """Every non-comment command line of the job's `run:` steps, continuations joined."""
    lines = []
    for step in CI['jobs'][job]['steps']:
        script = step.get('run')
        if not script:
            continue
        joined = re.sub(r'\\\n\s*', ' ', script)
        lines.extend(line.strip() for line in joined.splitlines()
                     if line.strip() and not line.strip().startswith('#'))
    return lines


def _make_targets():
    return set(re.findall(r'^([a-z][a-z0-9-]*):', MAKEFILE, flags=re.MULTILINE))


def test_the_instrument_finds_the_job_and_its_checks():
    """CONTROL. A parse that found nothing would compare nothing with nothing."""
    commands = _commands()
    assert any(c.startswith('flake8 . --count --select=') for c in commands), commands[:6]
    assert any('scripts/check_complexity_budget.py' in c for c in commands)
    assert any(c.startswith('pytest ') and '--cov-fail-under' in c for c in commands)
    assert len(_make_targets()) >= 15, sorted(_make_targets())


def test_every_check_script_the_test_job_runs_is_in_the_makefile_and_contributing():
    scripts = sorted({m for c in _commands() for m in re.findall(r'python scripts/(check_[a-z_]+\.py)', c)})
    assert len(scripts) >= 3, scripts
    for script in scripts:
        assert f'scripts/{script}' in MAKEFILE, (
            f'ci.yml runs scripts/{script} and the Makefile does not: `make lint`/`make ci` would '
            f'pass where CI fails.')
        assert script in CONTRIBUTING, (
            f'ci.yml runs scripts/{script} and the gate table in CONTRIBUTING.md does not list it.')


def test_the_flake8_selection_is_the_one_ci_enforces():
    ci_select = next(re.search(r'--select=(\S+)', c).group(1) for c in _commands()
                     if c.startswith('flake8 .') and '--select=' in c)
    assert f'FLAKE8_SELECT := {ci_select}\n' in MAKEFILE, 'the Makefile selects different flake8 codes than CI'
    assert f'--select={ci_select}' in CONTRIBUTING, 'CONTRIBUTING.md lists different flake8 codes than CI'


def test_bandit_is_run_as_ci_runs_it_and_at_the_version_ci_pins():
    commands = _commands()
    bandit = next(c for c in commands if c.startswith('bandit '))
    assert f'$(VENV)/bin/{bandit}' in MAKEFILE, f'the Makefile does not run `{bandit}`'
    assert bandit in CONTRIBUTING
    pinned = re.search(r'pip install bandit==(\S+)', ' '.join(commands)).group(1)
    assert f'BANDIT_VERSION := {pinned}\n' in MAKEFILE, 'the Makefile installs another bandit than CI pins'


def test_flake8_is_pinned_where_the_tests_install_it_to_the_version_ci_pins():
    ci_pin = re.search(r'pip install flake8==(\S+)', ' '.join(_commands())).group(1)
    assert f'flake8=={ci_pin}' in TEST_REQUIREMENTS.split(), 'requirements-test.txt pins another flake8 than CI'


def test_test_ci_is_the_pytest_command_ci_runs():
    ci = next(c for c in _commands() if c.startswith('pytest ') and '--cov-fail-under' in c)
    arguments = ci[len('pytest '):]
    assert f'$(PYTEST) {arguments}' in MAKEFILE, (
        f'`make test-ci` is not `pytest {arguments}`, which is what ci.yml runs')
    assert 'pytest -m "not ui and not network" --cov=modules --cov-fail-under=75' in CONTRIBUTING


def test_the_real_certificate_files_are_the_ones_release_sh_runs():
    gate = re.search(r'-m e2e\s*\\\n(.*?)-p no:cacheprovider', RELEASE, flags=re.DOTALL)
    assert gate, 'release.sh no longer has the real-certificate step this test reads'
    release_files = set(re.findall(r'tests/\S+\.py', gate.group(1)))
    block = re.search(r'E2E_FILES := (.*?)\n\n', MAKEFILE, flags=re.DOTALL).group(1)
    assert set(re.findall(r'tests/\S+\.py', block)) == release_files, (
        'make test-e2e runs other files than the release gate')
    assert len(release_files) >= 5, release_files


def test_make_test_is_the_selection_release_sh_and_contributing_document():
    release = re.search(r'-m "(not ui and not e2e)" -p no:cacheprovider', RELEASE)
    assert release, 'release.sh no longer runs the suite this test reads'
    assert f'-m "{release.group(1)}"' in re.search(r'\ntest:.*?\n\n', MAKEFILE, flags=re.DOTALL).group(0)
    assert f'-m "{release.group(1)}"' in CONTRIBUTING


def test_no_document_names_a_make_target_that_does_not_exist():
    """`make format` was named by the README as one of "the same tools CI runs", and
    `make docker-test` and `make pre-commit` were targets that could not work."""
    targets = _make_targets()
    named = {}
    for path in ['README.md', 'CONTRIBUTING.md', *sorted(str(p.relative_to(REPO)) for p in (REPO / 'docs').rglob('*.md')
                                                           if 'releases' not in p.parts)]:
        text = (REPO / path).read_text(encoding='utf-8')
        for target in re.findall(r'^\s*make ([a-z][a-z0-9-]*)', text, flags=re.MULTILINE) + \
                re.findall(r'`make ([a-z][a-z0-9-]*)`', text):
            named.setdefault(target, set()).add(path)
    missing = {t: sorted(p) for t, p in named.items() if t not in targets}
    assert not missing, f'documents name make targets the Makefile does not have: {missing}'
    assert 'test' in named and 'lint' in named, 'CONTROL: the scan found the targets the docs name'
