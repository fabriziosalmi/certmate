"""The ruff ratchet fails the four ways a ratchet has quietly stopped ratcheting here (#1093).

`scripts/check_ruff_budget.py` gives every (area, rule) the tree violates a count that can only
go down, and enforces every other rule at zero. The comparison is driven here with synthetic
measurements, because its failure modes cannot all be produced from the real tree at once; the
real tree is checked once, and the pieces that tie the baseline to the ruff that measured it are
checked beside it.
"""
import importlib.util
import pathlib
import subprocess
import sys
import tomllib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
CHECKER = REPO / 'scripts' / 'check_ruff_budget.py'


@pytest.fixture(scope='module')
def checker():
    spec = importlib.util.spec_from_file_location('check_ruff_budget', CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ruff(*args):
    return subprocess.run([sys.executable, '-m', 'ruff', *args], cwd=REPO, capture_output=True, text=True)


# --------------------------------------------------------------------------
# The real tree, and what ties the baseline to the ruff that measured it.
# --------------------------------------------------------------------------

def test_the_tree_is_at_its_baseline():
    done = subprocess.run([sys.executable, str(CHECKER)], cwd=REPO, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_baseline_was_measured_with_the_ruff_that_is_pinned(checker):
    pins = [line.strip() for line in (REPO / 'requirements-test.txt').read_text().splitlines()]
    assert f'ruff=={checker.RUFF_VERSION}' in pins, (
        f'requirements-test.txt does not pin ruff=={checker.RUFF_VERSION}, the version the baseline '
        f'was measured with')
    assert _ruff('--version').stdout.split()[-1] == checker.RUFF_VERSION, 'the ruff installed here is another one'


def test_the_measurement_finds_what_there_is_to_find(checker):
    """CONTROL. A measurement that found nothing would compare an empty tree with an empty baseline."""
    counts, _where, unparsable = checker.measure()
    assert sum(counts.values()) >= 1500 and len({rule for _a, rule in counts}) >= 40, counts
    assert {area for area, _r in counts} >= {'modules', 'tests', 'scripts'}
    assert not unparsable


def test_there_is_no_ignore_list_to_grow():
    """The point of a ratchet over an `ignore` list: an ignored rule is free to grow."""
    config = tomllib.loads((REPO / 'ruff.toml').read_text(encoding='utf-8'))
    lint = config['lint']
    assert 'ignore' not in lint and 'extend-ignore' not in lint, (
        'ruff.toml ignores rules: put the count in BASELINE in scripts/check_ruff_budget.py instead')
    assert lint['per-file-ignores'] == {'tests/**': ['S']}, 'the only exemption is bandit\'s rules in tests'


def test_ruff_covers_what_the_flake8_gate_enforces():
    """The flake8 selection CI fails on, in ruff's codes, is clean: nothing is lost by the ratchet
    being the other gate."""
    selection = 'E9,F63,F7,F82,F811,F632,E711,E712,E713,E714,F401,F841,E722'
    done = _ruff('check', '.', '--select', selection, '--no-cache', '--output-format', 'concise')
    assert done.returncode == 0, done.stdout


# --------------------------------------------------------------------------
# The comparison, on synthetic measurements.
# --------------------------------------------------------------------------

BASELINE = {'modules': {'UP006': 10, 'B904': 4}, 'tests': {'I001': 20}}


def _counts(**by_key):
    return {tuple(key.split('__')): n for key, n in by_key.items()}


def test_a_tree_at_its_baseline_has_no_problems(checker):
    now = _counts(modules__UP006=10, modules__B904=4, tests__I001=20)
    assert checker.evaluate(now, {}, BASELINE) == []


def test_a_rule_the_baseline_does_not_name_is_a_new_offender(checker):
    now = _counts(modules__UP006=10, modules__B904=4, tests__I001=20, modules__S310=1)
    where = {('modules', 'S310'): ['modules/x.py:3']}
    problems = checker.evaluate(now, where, BASELINE)
    assert len(problems) == 1 and 'new S310' in problems[0] and 'modules/x.py:3' in problems[0]


def test_a_rule_in_an_area_the_baseline_does_not_list_is_a_new_offender(checker):
    now = _counts(modules__UP006=10, modules__B904=4, tests__I001=20, scripts__UP006=1)
    problems = checker.evaluate(now, {}, BASELINE)
    assert len(problems) == 1 and problems[0].startswith('scripts: 1 new UP006')


def test_a_count_going_up_is_caught(checker):
    now = _counts(modules__UP006=11, modules__B904=4, tests__I001=20)
    problems = checker.evaluate(now, {('modules', 'UP006'): ['modules/y.py:9']}, BASELINE)
    assert len(problems) == 1 and 'UP006 went from 10 to 11' in problems[0]


def test_a_count_going_down_asks_for_its_entry_to_come_down(checker):
    """How a ceiling stays above what the code reaches: the improvement is not recorded."""
    now = _counts(modules__UP006=7, modules__B904=4, tests__I001=20)
    problems = checker.evaluate(now, {}, BASELINE)
    assert len(problems) == 1 and 'UP006 is at 7, below its entry of 10' in problems[0]


def test_an_entry_that_matches_nothing_is_caught(checker):
    now = _counts(modules__UP006=10, tests__I001=20)
    problems = checker.evaluate(now, {}, BASELINE)
    assert len(problems) == 1 and 'B904 is at 0' in problems[0] and 'delete it' in problems[0]


def test_another_ruff_than_the_one_that_measured_is_refused(checker):
    now = _counts(modules__UP006=10, modules__B904=4, tests__I001=20)
    problems = checker.evaluate(now, {}, BASELINE, installed='9.9.9', expected='0.16.10')
    assert len(problems) == 1 and 'ruff 9.9.9 is installed' in problems[0] and 're-measure' in problems[0]


def test_a_file_ruff_cannot_parse_is_a_problem_not_a_silent_pass(checker):
    now = _counts(modules__UP006=10, modules__B904=4, tests__I001=20)
    problems = checker.evaluate(now, {}, BASELINE, unparsable=['modules/z.py:1 invalid syntax'])
    assert len(problems) == 1 and 'cannot parse modules/z.py:1' in problems[0]


def test_the_printed_baseline_is_the_one_the_script_carries(checker):
    """`--print` is how the baseline is re-measured; what it prints must be what a check accepts."""
    counts, _where, _bad = checker.measure()
    namespace = {}
    exec(checker.render(counts), {}, namespace)
    assert namespace['BASELINE'] == checker.BASELINE


def test_a_file_ruff_cannot_parse_is_reported_as_such_by_the_measurement(checker, tmp_path):
    """The real thing, not a synthetic list: ruff 0.16 labels it `invalid-syntax`, and a
    measurement that took that for a rule would budget a file it never analysed."""
    (tmp_path / 'pkg').mkdir()
    (tmp_path / 'pkg' / 'bad.py').write_text('x = 1\ndef broken(:\n')
    (tmp_path / 'pkg' / 'ok.py').write_text('import os, sys\n')
    counts, _where, unparsable = checker.measure(tmp_path)
    assert unparsable and all(item.startswith('pkg/bad.py:') for item in unparsable), unparsable
    assert not any(rule == 'invalid-syntax' for _area, rule in counts), counts
