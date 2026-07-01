"""Rigor gate: every pytest marker that has tests must be selected by at least
one CI pytest invocation.

This is the guard that would have caught the UI-test rot: the ``ui`` tests
existed, but the only CI invocation was ``-m "not ui"``, so they ran nowhere
and two of them silently went stale. If a marker carries tests but is excluded
by *every* CI ``-m`` expression, this test fails.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
WF_DIR = ROOT / ".github" / "workflows"
TESTS_DIR = ROOT / "tests"


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
