"""#671 counted 397 broad handlers. Nothing counted them again, so they reached 425.

That is the whole argument for this checker, and it is the same one behind
`scripts/check_complexity_budget.py`: a number written into an issue is read
once, and a number in CI is read on every push.

Two of the three counts in #671 are now zero, measured with the AST rather than
grep: no bare `except:` and no broad handler whose body is only `pass`. Those
become rules rather than budgets, because zero is the only value either should
ever have. The third is pinned twice over: a total for the tree, which is the
number the issue names, and a per-file entry for each file already over the
general limit, because a total alone cannot tell one file improving from
another getting worse.

The behavioural tests drive the checker's comparison with synthetic
measurements, because the failure modes cannot all be produced from the real
tree at once.
"""
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
CHECKER = REPO / 'scripts' / 'check_exception_budget.py'
WORKFLOW = REPO / '.github' / 'workflows' / 'ci.yml'


def _namespace():
    namespace = {'__file__': str(CHECKER), '__name__': 'check_exception_budget'}
    exec(compile(CHECKER.read_text(encoding='utf-8'), str(CHECKER), 'exec'),
         namespace)
    return namespace


CHECK = _namespace()
BUDGET = CHECK['BUDGET']
LIMIT = CHECK['GENERAL_LIMIT']
TOTAL = CHECK['TOTAL_LIMIT']
UNACCOUNTED = CHECK['UNACCOUNTED_LIMIT']


def _evaluate(per_file, bare=(), silent=(), unaccounted=None):
    # `unaccounted` defaults to a list the pin's length, so a case about a
    # bare except is not also reported as the unaccounted count having moved.
    if unaccounted is None:
        unaccounted = [f'fake.py:{i}' for i in range(UNACCOUNTED)]
    return CHECK['evaluate'](per_file, list(bare), list(silent),
                             list(unaccounted), BUDGET, LIMIT,
                             sum(per_file.values()) if per_file else TOTAL,
                             UNACCOUNTED)


def _evaluate_with_total(per_file, total_limit):
    """As _evaluate, with the total pin chosen by the caller."""
    return CHECK['evaluate'](per_file, [], [],
                             [f'fake.py:{i}' for i in range(UNACCOUNTED)],
                             BUDGET, LIMIT, total_limit, UNACCOUNTED)


# --- against the real tree -----------------------------------------------

def test_the_budget_matches_the_tree():
    """The one that fails in the commit that earns it."""
    per_file, bare, silent, unaccounted = CHECK['measure']()
    problems = CHECK['evaluate'](per_file, bare, silent, unaccounted,
                                 BUDGET, LIMIT, TOTAL, UNACCOUNTED)

    assert problems == [], '\n'.join(problems)


def test_the_measurement_finds_something_to_measure():
    """CONTROL for the instrument. A walk that stopped matching would compare
    the budget against an empty dict, and only the stale-entry arm would fire."""
    per_file, _bare, _silent, _unaccounted = CHECK['measure']()

    assert len(per_file) > 40, (
        f'only {len(per_file)} files have a broad handler, which cannot be true '
        f'of this codebase: the measurement is broken, not the tree'
    )
    assert 'modules/core/storage_backends.py' in per_file


def test_the_total_pin_equals_what_the_tree_contains():
    """A pin above the tree is a comment; a pin below it fails every build."""
    per_file, _bare, _silent, _unaccounted = CHECK['measure']()

    assert sum(per_file.values()) == TOTAL, (
        f'TOTAL_LIMIT is {TOTAL} and the tree has {sum(per_file.values())}'
    )


def test_every_entry_is_above_the_general_limit():
    """CONTROL on the budget: an entry at or below the limit guards nothing."""
    too_low = {name: value for name, value in BUDGET.items() if value <= LIMIT}

    assert not too_low, (
        f'these entries are at or below the general limit of {LIMIT}, so they '
        f'can only ever fire the stale arm: {sorted(too_low)}'
    )


def test_ci_runs_it():
    """A checker nothing runs is the shape this repository keeps removing."""
    assert 'check_exception_budget.py' in WORKFLOW.read_text(encoding='utf-8')


# --- the failure modes ---------------------------------------------------

def test_a_clean_tree_reports_no_problems():
    """CONTROL first: a checker that complained about everything would satisfy
    every case below while blocking every build."""
    assert _evaluate(dict(BUDGET)) == []


def test_a_bare_except_is_caught():
    problems = _evaluate(dict(BUDGET), bare=['modules/core/thing.py:12'])

    assert len(problems) == 1
    assert 'bare' in problems[0] and 'thing.py:12' in problems[0]


def test_a_broad_handler_that_only_passes_is_caught():
    problems = _evaluate(dict(BUDGET), silent=['modules/core/thing.py:34'])

    assert len(problems) == 1
    assert 'only `pass`' in problems[0] and 'thing.py:34' in problems[0]


def test_the_total_growing_is_caught():
    """The number #671 is about."""
    measured = dict(BUDGET)
    problems = _evaluate_with_total(measured, sum(measured.values()) - 1)

    assert any('over the pinned' in problem for problem in problems)


def test_the_total_falling_asks_for_the_pin_to_come_down():
    """How the complexity pin at 559 outlived its own fix by nine months."""
    measured = dict(BUDGET)
    problems = _evaluate_with_total(measured, sum(measured.values()) + 1)

    assert any('below the pinned' in problem for problem in problems)


def test_a_new_file_over_the_limit_is_caught():
    """The case a single total could not see: one file improving by as much as
    another worsens leaves the total unchanged."""
    measured = dict(BUDGET)
    measured['modules/core/newcomer.py'] = LIMIT + 1

    problems = _evaluate(measured)

    assert any('newcomer.py' in problem and 'general limit' in problem
               for problem in problems)


def test_a_budgeted_file_getting_worse_is_caught():
    name, pinned = next(iter(sorted(BUDGET.items())))
    measured = dict(BUDGET)
    measured[name] = pinned + 1

    problems = _evaluate(measured)

    assert any(name in problem and 'over its budgeted' in problem
               for problem in problems)


def test_a_budgeted_file_getting_better_asks_for_its_entry():
    name, pinned = next(iter(sorted(BUDGET.items())))
    measured = dict(BUDGET)
    measured[name] = pinned - 1

    problems = _evaluate(measured)

    assert any(name in problem and 'Lower the entry' in problem
               for problem in problems)


def test_an_entry_that_matches_nothing_is_caught():
    """A rename or a deletion would otherwise drop a ceiling in silence."""
    measured = dict(BUDGET)
    name = next(iter(sorted(BUDGET)))
    del measured[name]

    problems = _evaluate(measured)

    assert any(name in problem and 'no longer exists' in problem
               for problem in problems)


def test_the_unaccounted_count_growing_is_caught():
    """A new handler that neither logs nor explains must not slip in."""
    measured = dict(BUDGET)
    problems = CHECK['evaluate'](
        measured, [], [], [f'fake.py:{i}' for i in range(UNACCOUNTED + 1)],
        BUDGET, LIMIT, sum(measured.values()), UNACCOUNTED)

    assert any('neither record the failure nor say why not' in p
               for p in problems)


def test_the_unaccounted_count_falling_asks_for_the_pin_to_come_down():
    """Same both-ways discipline as the total: a pin above the tree enforces
    nothing, and reads in review as though it does."""
    measured = dict(BUDGET)
    problems = CHECK['evaluate'](
        measured, [], [], [f'fake.py:{i}' for i in range(UNACCOUNTED - 1)],
        BUDGET, LIMIT, sum(measured.values()), UNACCOUNTED)

    assert any('Lower UNACCOUNTED_LIMIT' in p for p in problems)


def test_a_handler_that_logs_is_not_counted_as_unaccounted():
    """CONTROL for the instrument. If `_records` stopped recognising a log
    call, every handler in the tree would count and the pin would be meaningless
    — a gate that fails on everything gets raised until it fails on nothing.
    """
    import ast

    logging_handler = ast.parse(
        'try:\n    pass\nexcept Exception as e:\n    logger.warning(e)\n'
    ).body[0].handlers[0]
    silent_handler = ast.parse(
        'try:\n    pass\nexcept Exception:\n    value = None\n'
    ).body[0].handlers[0]

    assert CHECK['_records'](logging_handler) is True
    assert CHECK['_records'](silent_handler) is False


def test_a_comment_counts_as_an_explanation():
    """CONTROL for the other half: the rule is satisfiable by writing down the
    reason, which is the behaviour it is trying to produce."""
    import ast

    source = (
        'try:\n'
        '    pass\n'
        'except Exception:\n'
        '    # deliberate: the caller treats absence and failure the same\n'
        '    value = None\n'
    )
    handler = ast.parse(source).body[0].handlers[0]

    assert CHECK['_explained'](handler, source.split('\n')) is True
