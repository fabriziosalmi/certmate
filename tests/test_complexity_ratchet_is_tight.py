"""A ratchet that nobody lowers is a gate that permits everything.

CI runs `flake8 --select=C901 --max-complexity=N` so that no function can be
worse than the worst one already in the tree. The number was 559 — set for
`create_api_resources`, the 3.7k-line closure in `modules/api/resources.py`.
Issue #667 decomposed that function to a complexity of 1, and the number stayed
at 559: nearly five times the real worst, permitting anything a contributor
could plausibly write, while reading in review like an enforced limit.

That is the failure mode of every ratchet maintained by memory. This file
removes the memory: it measures the tree and fails when the pin is looser than
what the tree actually contains, so lowering it is not something to remember —
it is something the suite asks for, in the commit that earned it.

Deliberately one-directional. Getting *worse* is caught by CI itself (a new
function above the pin fails the lint step). Getting *better* without lowering
the pin is what this catches, and it is the direction nothing else looks at.
"""
import pathlib
import re
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = REPO / '.github' / 'workflows' / 'ci.yml'
COMPLEXITY = re.compile(r"is too complex \((\d+)\)")
PIN = re.compile(r"--select=C901\s+--max-complexity=(\d+)")


def ci_pin():
    """The number CI enforces."""
    match = PIN.search(WORKFLOW.read_text())
    assert match, (
        'the C901 ratchet is gone from ci.yml. If it was removed on purpose, '
        'remove this file too; if it was renamed, this needs renaming with it.'
    )
    return int(match.group(1))


def measured_worst():
    """The highest cyclomatic complexity in the tree, from flake8 itself.

    Run rather than reimplemented: an independent complexity calculation would
    disagree with the gate at the margins, and the number that matters is the
    one CI computes.
    """
    result = subprocess.run(
        [sys.executable, '-m', 'flake8', '.', '--select=C901',
         '--max-complexity=1', '--exit-zero'],
        cwd=REPO, capture_output=True, text=True, timeout=600)

    if 'No module named flake8' in result.stderr:
        pytest.fail(
            'flake8 is not installed, so the ratchet cannot be checked. It is '
            'in requirements-test.txt precisely so this cannot skip quietly — '
            'a check that disappears with its dependency is worse than none.')
    assert result.returncode == 0, result.stderr

    scores = [int(m.group(1)) for m in COMPLEXITY.finditer(result.stdout)]
    assert scores, (
        'flake8 reported no complexity at all against --max-complexity=1, '
        'which cannot be true of this codebase. The measurement is broken, '
        'not the tree.'
    )
    return max(scores)


def worst_function():
    """(name, path, score) of the most complex function, for the message."""
    result = subprocess.run(
        [sys.executable, '-m', 'flake8', '.', '--select=C901',
         '--max-complexity=1', '--exit-zero'],
        cwd=REPO, capture_output=True, text=True, timeout=600)
    worst, best_score = None, -1
    for line in result.stdout.splitlines():
        match = COMPLEXITY.search(line)
        if match and int(match.group(1)) > best_score:
            best_score = int(match.group(1))
            worst = line
    return worst


def test_the_pin_is_not_looser_than_the_tree():
    """The one that would have caught #667's leftover: 559 against a real
    worst of 115."""
    pin, worst = ci_pin(), measured_worst()
    assert pin <= worst, (
        f'the CI complexity ratchet is set to {pin} but nothing in the tree '
        f'is worse than {worst}, so the gate permits any function up to '
        f'{pin / worst:.1f}x the current worst and cannot fail on anything a '
        f'contributor is likely to write.\n\n'
        f'Lower --max-complexity in .github/workflows/ci.yml to {worst}. The '
        f'function that sets it:\n  {worst_function()}'
    )


def test_the_pin_is_not_tighter_than_the_tree():
    """CONTROL, and a real failure mode: a pin BELOW the worst means CI is red
    on main and every PR inherits a failure it did not cause."""
    pin, worst = ci_pin(), measured_worst()
    assert pin >= worst, (
        f'the CI complexity ratchet is {pin} but the tree contains a function '
        f'at {worst}, so the lint step fails on main:\n  {worst_function()}'
    )


def test_the_measurement_finds_something_to_measure():
    """CONTROL for the instrument. A regex that stops matching, or a flake8
    invocation that reports nothing, would make both tests above agree with
    each other about a tree they never looked at."""
    assert measured_worst() > 10, (
        'the highest complexity measured is implausibly low; the parse is '
        'probably matching nothing'
    )


def test_flake8_is_a_declared_test_dependency():
    """The check above shells out to flake8. If it were only present because
    the lint step happens to install it, this file would fail in the test job
    for a reason unrelated to complexity."""
    declared = (REPO / 'requirements-test.txt').read_text()
    assert 'flake8' in declared, (
        'flake8 is not in requirements-test.txt, so the ratchet check depends '
        'on a package the test job does not install'
    )
