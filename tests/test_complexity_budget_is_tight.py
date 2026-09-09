"""A ceiling set by the worst function gates nothing below the worst function.

CI ran `flake8 --select=C901 --max-complexity=559` — the number set for
`create_api_resources`, the 3.7k-line closure #667 decomposed to a complexity
of 1 — for nine months after that closure was gone. The first version of this
file removed that failure mode: it measured the tree and failed when the pin
was looser than what the tree contained, so lowering it became something the
suite asked for rather than something to remember.

That fixed the drift and left the shape. A single pin has to be set by the
worst function in the tree, which means every function below the worst is
ungated: with the pin at its honest value of 115, a contributor could add a
function at 100, or a second closure at 90, and the lint step stayed green. The
gate could only ever fail on a new record.

`scripts/check_complexity_budget.py` gives each function its own ceiling: a
general limit of 40, and an explicit entry for each of the thirteen already
above it. The tightness property this file was written for is still here — an
entry left above what the code reaches is a failure — but it now applies
thirteen times over, and there is a fourteenth thing it can catch, which is the
one the single pin never could.

The behavioural tests below drive the checker's comparison directly with
synthetic measurements, because the four failure modes cannot all be produced
from the real tree at once.
"""
import pathlib
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
CHECKER = REPO / 'scripts' / 'check_complexity_budget.py'
WORKFLOW = REPO / '.github' / 'workflows' / 'ci.yml'


def _namespace():
    """The checker's globals, without running it. `__file__` is seeded because
    the script derives the repository root from it."""
    namespace = {'__file__': str(CHECKER), '__name__': 'check_complexity_budget'}
    exec(compile(CHECKER.read_text(encoding='utf-8'), str(CHECKER), 'exec'),
         namespace)
    return namespace


CHECK = _namespace()
BUDGET = CHECK['BUDGET']
LIMIT = CHECK['GENERAL_LIMIT']


# --- against the real tree -----------------------------------------------

def test_the_budget_matches_the_tree():
    """The one that fails in the commit that earned it: every entry equals what
    flake8 measures today, and nothing outside the budget is over the limit."""
    result = subprocess.run([sys.executable, str(CHECKER)],
                            cwd=REPO, capture_output=True, text=True,
                            timeout=900)

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_measurement_finds_something_to_measure():
    """CONTROL for the instrument. A regex that stopped matching, or a flake8
    invocation reporting nothing, would make the checker pass over a tree it
    never looked at — the budget would be compared against an empty dict and
    only the stale-entry arm would notice."""
    measured = CHECK['measure'](limit=10)

    assert len(measured) > 50, (
        'flake8 reports almost nothing over a complexity of 10, which cannot '
        'be true of this codebase: the measurement is broken, not the tree')
    assert 'modules/core/settings.py::SettingsManager.load_settings' in measured


def test_every_entry_is_above_the_general_limit():
    """CONTROL on the budget itself: an entry at or below the limit describes a
    function flake8 will not report, so it can only ever fire the stale arm."""
    too_low = {key: value for key, value in BUDGET.items() if value <= LIMIT}

    assert not too_low, (
        f'these entries are at or below the general limit of {LIMIT}, so they '
        f'guard nothing and will fail as stale: {sorted(too_low)}')


# --- the four failure modes ----------------------------------------------

def test_a_clean_tree_reports_no_problems():
    """CONTROL first: a checker that complained about everything would satisfy
    every case below while blocking every build."""
    measured = dict(BUDGET)

    assert CHECK['evaluate'](measured, BUDGET, LIMIT) == []


def test_a_new_function_over_the_limit_is_caught():
    """THE reason this replaced the single pin. Under `--max-complexity=115`
    this function was invisible."""
    measured = dict(BUDGET)
    measured['modules/core/newthing.py::do_everything'] = 100

    problems = CHECK['evaluate'](measured, BUDGET, LIMIT)

    assert len(problems) == 1
    assert 'do_everything' in problems[0]
    assert 'no budget entry' in problems[0]


def test_a_budgeted_function_getting_worse_is_caught():
    """The ratchet's own direction, now per function rather than per tree."""
    key = 'modules/web/settings_routes.py::register_settings_routes'
    measured = dict(BUDGET)
    measured[key] = BUDGET[key] + 1

    problems = CHECK['evaluate'](measured, BUDGET, LIMIT)

    assert len(problems) == 1
    assert 'got worse' in problems[0]


def test_a_budgeted_function_getting_better_asks_for_its_entry():
    """The drift this file was originally written for: 559 outliving the
    function it was set for. Silent improvement is how a ceiling stops being
    a ceiling."""
    key = 'modules/core/settings.py::SettingsManager.load_settings'
    measured = dict(BUDGET)
    measured[key] = 31

    problems = CHECK['evaluate'](measured, BUDGET, LIMIT)

    assert len(problems) == 1
    assert 'got better' in problems[0]
    assert 'Lower its entry to 31' in problems[0]


def test_an_entry_that_matches_nothing_is_caught():
    """A rename or a deletion would otherwise drop a ceiling silently, and the
    check would go on passing over less code than it was written for."""
    measured = dict(BUDGET)
    measured.pop('modules/web/misc_routes.py::register_misc_routes')

    problems = CHECK['evaluate'](measured, BUDGET, LIMIT)

    assert len(problems) == 1
    assert 'reports nothing for it' in problems[0]


def test_a_function_that_drops_under_the_limit_asks_for_its_entry_to_go():
    """The same arm, from the good direction: decomposing a budgeted closure
    below 40 removes it from flake8's report entirely, and the entry left
    behind would guard a function that no longer needs guarding."""
    key = 'modules/api/resources_inventory.py::create_inventory_resources'
    measured = dict(BUDGET)
    measured.pop(key)

    problems = CHECK['evaluate'](measured, BUDGET, LIMIT)

    assert 'should be deleted' in problems[0]


# --- the gate is actually run --------------------------------------------

def test_ci_runs_the_checker():
    """A budget nothing executes is a comment."""
    workflow = WORKFLOW.read_text(encoding='utf-8')

    assert 'python scripts/check_complexity_budget.py' in workflow


def test_ci_no_longer_carries_a_single_pin():
    """Two gates disagreeing about the same property is how one of them stops
    being maintained: the bare C901 pin has to be gone, not merely superseded."""
    workflow = WORKFLOW.read_text(encoding='utf-8')

    assert '--select=C901' not in workflow, (
        'ci.yml still runs a bare C901 pin alongside the per-function budget')


def test_flake8_is_a_declared_test_dependency():
    """The checker shells out to flake8. If it were present only because the
    lint job happens to install it, this file would fail in the test job for a
    reason unrelated to complexity."""
    declared = (REPO / 'requirements-test.txt').read_text(encoding='utf-8')

    assert 'flake8' in declared
