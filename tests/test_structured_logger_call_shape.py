"""Loggers from get_certmate_logger() are StructuredLogger instances whose
level methods are ``warning(msg, **kwargs)`` — keyword-only extras, no
positional %-args. The standard-library idiom ``logger.warning("x %s", y)``
therefore raises TypeError at the call site, i.e. exactly when the code
wanted to log a problem. factory.py:415 was the one such call in the tree,
inside the "non-fatal" handler for an unwritable ACME challenge directory,
and took the boot down with it. This scan keeps it at zero.
"""
import ast
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
LEVELS = {'debug', 'info', 'warning', 'warn', 'error', 'critical', 'exception'}


def _structured_logger_names(tree):
    """Module-level names bound to get_certmate_logger(...)."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            fname = func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)
            if fname == 'get_certmate_logger':
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _offenders():
    found = []
    for path in sorted((REPO / 'modules').rglob('*.py')):
        src = path.read_text(encoding='utf-8')
        if 'get_certmate_logger' not in src:
            continue
        tree = ast.parse(src)
        names = _structured_logger_names(tree)
        if not names:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in LEVELS:
                continue
            if not (isinstance(node.func.value, ast.Name) and node.func.value.id in names):
                continue
            if len(node.args) > 1:
                found.append(f"{path.relative_to(REPO)}:{node.lineno}")
    return found


def test_structured_logger_calls_pass_one_positional_argument():
    offenders = _offenders()
    assert not offenders, (
        "StructuredLogger level methods take (msg, **kwargs); these calls pass "
        f"extra positional args and raise TypeError when reached: {offenders}")


def test_the_scan_sees_structured_loggers_at_all():
    """Guard the guard: if nothing binds get_certmate_logger at module level
    any more, the scan above passes over nothing."""
    bound = 0
    for path in (REPO / 'modules').rglob('*.py'):
        src = path.read_text(encoding='utf-8')
        if 'get_certmate_logger' in src and _structured_logger_names(ast.parse(src)):
            bound += 1
    assert bound >= 1, bound
