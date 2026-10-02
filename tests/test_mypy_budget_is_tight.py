"""The mypy ratchet fails the four ways a ratchet has quietly stopped ratcheting here (#1094).

`scripts/check_mypy_budget.py` gives every file with mypy errors a count that can only go down, and
enforces every other file at zero. Its comparison is driven here with synthetic measurements, and
its measurement on a small tree built for the purpose.

What is deliberately NOT here: a check of the real tree. What mypy reports depends on the versions
of the packages it reads, and this job installs requirements.txt, whose transitive dependencies
float on purpose; a typed library's release would fail this suite for a reason that is not the
change under review. That check is the `typecheck` job in ci.yml and `make typecheck`, both on the
locked set under Python 3.12.
"""
import importlib.util
import pathlib
import re
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
CHECKER = REPO / 'scripts' / 'check_mypy_budget.py'


@pytest.fixture(scope='module')
def checker():
    spec = importlib.util.spec_from_file_location('check_mypy_budget', CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# What ties the baseline to the mypy that measured it, and to its configuration.
# --------------------------------------------------------------------------

def test_the_baseline_was_measured_with_the_mypy_that_is_pinned(checker):
    pins = [line.strip() for line in (REPO / 'requirements-test.txt').read_text().splitlines()]
    assert f'mypy=={checker.MYPY_VERSION}' in pins
    done = subprocess.run([sys.executable, '-m', 'mypy', '--version'], capture_output=True, text=True)
    assert done.stdout.split()[1] == checker.MYPY_VERSION, 'the mypy installed here is another one'


def test_the_baseline_is_not_empty_and_names_files_that_exist(checker):
    assert len(checker.BASELINE) >= 20 and sum(checker.BASELINE.values()) >= 80, checker.BASELINE
    missing = [path for path in checker.BASELINE if not (REPO / path).is_file()]
    assert not missing, f'baseline entries for files that are gone (delete them): {missing}'


def test_a_module_held_to_strict_has_no_baseline_entry(checker):
    """mypy.ini writes out `--strict` for the modules that were clean under it. An entry for one of them
    would be a ceiling above zero on a file meant to stay at zero."""
    config = (REPO / 'mypy.ini').read_text(encoding='utf-8')
    section = re.search(r'^\[mypy-(modules[^\]]*)\]\n(?:(?!\[).*\n)*?disallow_untyped_defs = True', config, flags=re.MULTILINE)
    assert section, 'mypy.ini no longer lists strict modules'
    strict = section.group(1).split(',')
    assert 'modules.api.path_validation' in strict and 'modules.core.audit_context' in strict
    for name in strict:
        for path in (f"{name.replace('.', '/')}.py", f"{name.replace('.', '/')}/__init__.py"):
            assert path not in checker.BASELINE, f'{path} is held to strict and has a baseline entry'


def test_third_party_packages_without_types_are_named_not_blanket_ignored():
    config = (REPO / 'mypy.ini').read_text(encoding='utf-8')
    assert not re.search(r'^\[mypy\]\n(?:.*\n)*?ignore_missing_imports', config.split('\n\n')[0] + '\n', flags=re.MULTILINE)
    named = re.findall(r'^\[mypy-([a-z0-9_]+)\.\*\]\nignore_missing_imports = True', config, flags=re.MULTILINE)
    assert {'flask_restx', 'boto3', 'azure'} <= set(named), named


# --------------------------------------------------------------------------
# The measurement, on a tree built for it. It needs nothing from the project's dependencies.
# --------------------------------------------------------------------------

def _tree(tmp_path, files):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (tmp_path / 'mypy.ini').write_text('[mypy]\nfiles = pkg\n')
    return tmp_path


def test_the_measurement_counts_errors_per_file(checker, tmp_path):
    tree = _tree(tmp_path, {
        'pkg/__init__.py': '',
        'pkg/a.py': 'x: int = "no"\ny: str = 1\n',
        'pkg/b.py': 'z: int = 3\n',
        'pkg/c.py': 'def f(v: int) -> str:\n    return v\n',
    })
    counts, where, unchecked = checker.measure(tree)
    assert counts == {'pkg/a.py': 2, 'pkg/c.py': 1}, counts
    assert where['pkg/a.py'] == ['pkg/a.py:1', 'pkg/a.py:2']
    assert not unchecked


def test_a_file_mypy_cannot_parse_is_a_problem_not_a_silent_pass(checker, tmp_path):
    """The counts of a tree that was not analysed are counts of less than the tree."""
    tree = _tree(tmp_path, {'pkg/__init__.py': '', 'pkg/bad.py': 'def broken(:\n'})
    counts, _where, unchecked = checker.measure(tree)
    assert unchecked and unchecked[0].startswith('pkg/bad.py:1'), (counts, unchecked)


# --------------------------------------------------------------------------
# The comparison, on synthetic measurements.
# --------------------------------------------------------------------------

BASELINE = {'modules/core/a.py': 5, 'modules/core/b.py': 2}


def test_a_tree_at_its_baseline_has_no_problems(checker):
    assert checker.evaluate({'modules/core/a.py': 5, 'modules/core/b.py': 2}, {}, BASELINE) == []


def test_a_file_the_baseline_does_not_name_is_a_new_offender(checker):
    now = {'modules/core/a.py': 5, 'modules/core/b.py': 2, 'modules/core/new.py': 1}
    problems = checker.evaluate(now, {'modules/core/new.py': ['modules/core/new.py:7']}, BASELINE)
    assert len(problems) == 1 and 'modules/core/new.py: 1 new error' in problems[0] and ':7' in problems[0]


def test_a_count_going_up_is_caught(checker):
    problems = checker.evaluate({'modules/core/a.py': 6, 'modules/core/b.py': 2}, {}, BASELINE)
    assert len(problems) == 1 and 'errors went from 5 to 6' in problems[0]


def test_a_count_going_down_asks_for_its_entry_to_come_down(checker):
    problems = checker.evaluate({'modules/core/a.py': 3, 'modules/core/b.py': 2}, {}, BASELINE)
    assert len(problems) == 1 and 'is at 3, below its entry of 5' in problems[0]


def test_an_entry_for_a_file_that_is_now_clean_is_caught(checker):
    problems = checker.evaluate({'modules/core/a.py': 5}, {}, BASELINE)
    assert len(problems) == 1 and 'modules/core/b.py: is clean' in problems[0] and 'delete it' in problems[0]


def test_another_mypy_than_the_one_that_measured_is_refused(checker):
    problems = checker.evaluate(dict(BASELINE), {}, BASELINE, installed='9.9.9', expected='2.4.0')
    assert len(problems) == 1 and 'mypy 9.9.9 is installed' in problems[0] and 're-measure' in problems[0]


def test_another_interpreter_than_the_one_that_measured_is_refused(checker):
    problems = checker.evaluate(dict(BASELINE), {}, BASELINE, python_minor=(3, 14), expected_python=(3, 12))
    assert len(problems) == 1 and 'Python 3.14' in problems[0] and 'under 3.12' in problems[0]


def test_the_printed_baseline_is_a_baseline_the_script_would_accept(checker):
    namespace = {}
    exec(checker.render({'modules/x.py': 3, 'app.py': 1}), {}, namespace)
    assert namespace['BASELINE'] == {'app.py': 1, 'modules/x.py': 3}
