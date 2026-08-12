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
import importlib.util
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
    """Behaviour, not substrings.

    The point is that the expected port, Python version and pins come from the
    repository rather than from a list inside the script — a restated value is
    a third copy to keep in sync. An earlier version of this test asserted the
    literal strings `"app.py"` and `"Dockerfile"` appeared in the source, which
    would break on a harmless refactor and pass on a harmful one (Copilot,
    #555). So it calls the function and compares what it returns with what the
    repository says.
    """
    spec = importlib.util.spec_from_file_location("check_wiki", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    port, python_version, pins = module._truth()

    app = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    assert port == re.search(r"--port['\"].*?default=(\d+)", app).group(1), (
        "check_wiki.py's expected port does not come from app.py"
    )
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert python_version == re.search(r"^FROM python:(\d+\.\d+)",
                                       dockerfile, re.M).group(1), (
        "check_wiki.py's expected Python version does not come from the Dockerfile"
    )
    assert pins.get("certbot") == re.search(
        r"^certbot==([\w.]+)",
        (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8"),
        re.M).group(1), (
        "check_wiki.py's pins do not come from requirements.txt"
    )


def test_it_aborts_rather_than_reporting_success():
    """A checker that cannot read its sources must not print 'no drift'."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"raise SystemExit", source), (
        "check_wiki.py no longer aborts when it cannot read the repository. "
        "Printing a complaint and exiting zero is how a check goes quiet."
    )
