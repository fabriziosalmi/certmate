"""Rigor gate: every pytest marker that has tests must be selected by at least
one CI pytest invocation.

This is the guard that would have caught the UI-test rot: the ``ui`` tests
existed, but the only CI invocation was ``-m "not ui"``, so they ran nowhere
and two of them silently went stale. If a marker carries tests but is excluded
by *every* CI ``-m`` expression, this test fails.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WF_DIR = ROOT / ".github" / "workflows"
TESTS_DIR = ROOT / "tests"

pytestmark = [pytest.mark.unit]


def _declared_markers():
    """Marker names declared in pytest.ini's ``markers =`` block."""
    ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    out, in_block = set(), False
    for line in ini.splitlines():
        if re.match(r"^markers\s*=", line):
            in_block = True
            continue
        if in_block:
            m = re.match(r"^\s+(\w+):", line)
            if m:
                out.add(m.group(1))
            elif line and not line[0].isspace():
                break
    return out


def _markers_with_tests(declared):
    """Declared markers that actually appear on a test (explicit @pytest.mark.X
    or module-level pytestmark = pytest.mark.X)."""
    used = set()
    pat = re.compile(r"pytest\.mark\.(\w+)")
    for f in TESTS_DIR.rglob("test_*.py"):
        for name in pat.findall(f.read_text(encoding="utf-8")):
            if name in declared:
                used.add(name)
    return used


def _ci_marker_exprs(declared):
    """`-m` expressions used by pytest in CI workflows, limited to those that
    reference a declared marker (drops the `-m` of `python -m pytest`)."""
    exprs, pat = [], re.compile(r"-m\s+(\"[^\"]+\"|'[^']+'|\S+)")
    for f in WF_DIR.glob("*.yml"):
        for raw in pat.findall(f.read_text(encoding="utf-8")):
            expr = raw.strip("\"'")
            if any(re.search(rf"\b{re.escape(m)}\b", expr) for m in declared):
                exprs.append(expr)
    return exprs


def _selects(expr, marker, declared):
    """True if `expr` selects a test carrying ONLY `marker`."""
    ns = {m: (m == marker) for m in declared}
    try:
        return bool(eval(expr, {"__builtins__": {}}, ns))  # noqa: S307 - our own workflow strings
    except Exception:
        return False


def test_every_used_marker_is_run_by_ci():
    declared = _declared_markers()
    assert declared, "no markers declared in pytest.ini"
    used = _markers_with_tests(declared)
    exprs = _ci_marker_exprs(declared)
    assert exprs, "no pytest `-m` invocations referencing a declared marker found in CI workflows"

    uncovered = [m for m in sorted(used)
                 if not any(_selects(e, m, declared) for e in exprs)]
    assert not uncovered, (
        f"markers that carry tests but are excluded by EVERY CI pytest "
        f"invocation (they run nowhere -> rot risk): {uncovered}. "
        f"CI -m expressions seen: {exprs}"
    )


def _test_files():
    return sorted(f for f in TESTS_DIR.glob("test_*.py"))


def _declares_a_marker(src):
    """True when the file really declares a marker.

    Looks for an actual ``pytestmark`` assignment rather than the substring
    anywhere in the file: the word appears in comments and docstrings that
    discuss marking, and treating those as evidence would let a genuinely
    unmarked file slip past the guard.
    """
    if re.search(r"^pytestmark\s*=", src, re.M):
        return True
    return bool(re.search(
        r"@pytest\.mark\.(" + "|".join(_declared_markers()) + r")\b", src))


def test_every_test_file_declares_a_marker():
    """Gate membership must be chosen, not inherited by accident.

    ``--strict-markers`` rejects markers that are not declared; it says nothing
    about tests that carry no marker at all. Those land in whatever bucket the
    running ``-m`` expression happens not to exclude, so which gate they belong
    to is an accident of how the expression is written rather than a decision
    anyone made (#665).
    """
    unmarked = []
    for path in _test_files():
        src = path.read_text(encoding="utf-8")
        if not re.search(r"^\s*def test_", src, re.M):
            continue
        if not _declares_a_marker(src):
            unmarked.append(path.name)
    assert not unmarked, (
        "these test files declare no marker, so which CI gate runs them is "
        "incidental rather than intended: " + ", ".join(unmarked)
    )


def _markers_in_use():
    """Marker names actually applied to tests.

    Read from the sources rather than by shelling out to pytest once per
    marker: that was slower, and it judged a run by grepping stdout for a
    message pytest can also emit on stderr — a check that can miss its own
    signal is not one worth keeping.

    ``conftest.py`` counts as a source. A marker applied there by
    ``pytest_collection_modifyitems`` is applied to real tests — ``credentialed``
    is derived from the fixtures a test requests, precisely so it cannot drift
    the way a hand-written decorator does — and reading only ``test_*.py``
    would report it as a category nobody is in while ``-m credentialed``
    selects fifteen tests.
    """
    used = set()
    declared = _declared_markers()
    for path in [*_test_files(), TESTS_DIR / "conftest.py"]:
        if not path.exists():
            continue
        src = path.read_text(encoding="utf-8")
        for match in re.finditer(r"pytest\.mark\.(\w+)", src):
            if match.group(1) in declared:
                used.add(match.group(1))
    return used


def test_no_marker_is_declared_without_tests():
    """The other blind spot: a category nobody is in.

    ``integration``, ``api`` and ``dns`` were declared and carried zero tests,
    so a reader filtering by them got silence and concluded there was nothing
    to run — indistinguishable from a suite where those tests had rotted away.
    """
    empty = sorted(_declared_markers() - _markers_in_use())
    assert not empty, (
        "these markers are declared but no test carries them, so they name "
        "categories that do not exist: " + ", ".join(empty)
    )
