"""The wiki checker must exist, and something must run it.

`scripts/check_wiki.py` compares the GitHub wiki — a separate git repository —
against the facts this one holds. It was written because the wiki has drifted
three times, each time by keeping a second copy of something already corrected
here.

A checker nothing runs is the shape this repository has spent a week removing:
`mcp/` had two test suites referenced by no workflow while Dependabot updated
its dependencies. So this asserts the wiring, not the logic — the logic is
verified by running it against a wiki with each defect reintroduced.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_wiki.py"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"

pytestmark = [pytest.mark.unit]


def test_the_checker_exists():
    assert SCRIPT.exists(), "scripts/check_wiki.py is gone"


def test_a_workflow_runs_it():
    text = CI.read_text(encoding="utf-8")
    assert "scripts/check_wiki.py" in text, (
        "no workflow runs scripts/check_wiki.py. A checker nothing executes is "
        "how mcp/ ended up with two suites that never ran."
    )
    assert ".wiki.git" in text, (
        "the workflow does not clone the wiki, so the checker would run against "
        "nothing."
    )


def test_it_reads_the_truth_from_the_repository():
    """Not from a list inside itself, which is what goes stale.

    The whole point is that the expected port, Python version and pins come
    from app.py, the Dockerfile and requirements*.txt. A checker that restated
    them would be a third copy to keep in sync.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    for reference in ('"app.py"', '"Dockerfile"', 'requirements*.txt'):
        assert reference in source, (
            f"check_wiki.py no longer reads {reference} — if the expected "
            f"values have been written into the script instead, it has become "
            f"the drift it was meant to catch."
        )
    assert re.search(r"raise SystemExit", source), (
        "check_wiki.py no longer aborts when it cannot read the repository. "
        "Printing a complaint and exiting zero is how a check goes quiet."
    )
