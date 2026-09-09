"""A client should be able to branch on a failure without matching English.

Machine-readable error codes existed for seven conditions and were absent from
161 error returns under `modules/api`, so for almost every failure the only
thing a caller could act on was the human message — which is not a contract:
it gets reworded, translated, or has a domain interpolated into it.

The plumbing was already there. `models.py` declares `code` on the error model,
and the comment beside it records that marshalling strips anything undeclared.
What was missing was the requirement.

**This is a ratchet, not a rule.** Filling in 161 codes in one change would
produce 161 identifiers chosen in a hurry, and a stable-looking identifier that
means nothing is worse than none — a client would branch on it. So each file
carries a ceiling, and the ceiling can only go down. Two files are at zero:
`resources_lifecycle.py` (create, renew, reissue, the async job endpoints) and
`resources_downloads.py`, which is what the SDK and the CLI actually call.

Adding an error return without a code fails the build in every file, because
every file's ceiling is the number it has today.
"""
import ast
import collections
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
API = REPO / 'modules' / 'api'

# Error returns still carrying no code, per file, as of this commit. Lower a
# number when you add codes; a file at 0 is done and must stay done. Never
# raise one: that is what the test is for.
UNCODED_CEILING = {
    'resources_backup.py': 31,
    'resources_certificates.py': 14,
    'resources_inventory.py': 18,
    'resources_storage.py': 18,
    'resources_settings.py': 16,
    'resources_deployment.py': 7,
    'resources_discovery.py': 5,
    'resources_ca.py': 3,
    'resources_cache.py': 2,
    'resources_health.py': 2,
    'resources_lifecycle.py': 0,
    'resources_downloads.py': 0,
}


def _error_returns(path):
    """Every `return {...}, <4xx/5xx>` in a file, with whether it has a code.

    Only literal dict returns are counted. A return of a variable cannot be
    checked here and is not the shape this is about: the 161 were all literals.
    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Return)
                and isinstance(node.value, ast.Tuple)
                and len(node.value.elts) == 2):
            continue
        body, status = node.value.elts
        if not (isinstance(status, ast.Constant)
                and isinstance(status.value, int)
                and status.value >= 400):
            continue
        if not isinstance(body, ast.Dict):
            continue
        keys = {k.value for k in body.keys if isinstance(k, ast.Constant)}
        yield node.lineno, status.value, 'code' in keys


def uncoded():
    """{filename: [(line, status)]} for every error return with no code."""
    found = collections.defaultdict(list)
    for path in sorted(API.glob('*.py')):
        for lineno, status, has_code in _error_returns(path):
            if not has_code:
                found[path.name].append((lineno, status))
    return found


# --- the ratchet ---------------------------------------------------------

def test_no_file_has_more_uncoded_errors_than_its_ceiling():
    found = uncoded()
    over = []
    for name, sites in sorted(found.items()):
        ceiling = UNCODED_CEILING.get(name)
        if ceiling is None:
            over.append(
                f'{name}: {len(sites)} uncoded error return(s), and the file '
                f'is not in UNCODED_CEILING at all')
        elif len(sites) > ceiling:
            lines = ', '.join(str(line) for line, _ in sites[:8])
            over.append(
                f'{name}: {len(sites)} uncoded, ceiling {ceiling} (lines '
                f'{lines})')
    assert not over, (
        "these files gained an error return with no machine-readable 'code', "
        "so a client can only string-match the message:\n  "
        + '\n  '.join(over)
        + "\n\nAdd a 'code' naming the condition — see the convention in "
          "resources_lifecycle.py — or, if you removed codes deliberately, "
          "raise the ceiling and say why in the commit."
    )


def test_a_ceiling_that_is_too_high_is_lowered():
    """The half that makes it a ratchet. Without it a ceiling stays at its
    original value forever and the file can regress back up to it silently
    after someone does the work."""
    found = uncoded()
    slack = {name: (ceiling, len(found.get(name, [])))
             for name, ceiling in UNCODED_CEILING.items()
             if len(found.get(name, [])) < ceiling}
    assert not slack, (
        'these files have fewer uncoded error returns than their ceiling — '
        'good, now lower it so the progress is locked in: '
        + ', '.join(f'{name}: {actual} (ceiling {ceiling})'
                    for name, (ceiling, actual) in sorted(slack.items())))


def test_the_two_finished_files_stay_finished():
    """Named separately so the failure says which surface regressed. These
    two are what the SDK and the CLI call."""
    found = uncoded()
    for name in ('resources_lifecycle.py', 'resources_downloads.py'):
        assert not found.get(name), (
            f'{name} is meant to have a code on every error return; these do '
            f'not: ' + ', '.join(str(line) for line, _ in found[name]))


def test_a_ceiling_does_not_name_a_file_that_is_gone():
    present = {path.name for path in API.glob('*.py')}
    stale = sorted(set(UNCODED_CEILING) - present)
    assert not stale, (
        'UNCODED_CEILING names files that no longer exist: ' + ', '.join(stale))


# --- controls on the census ---------------------------------------------

def test_the_census_finds_error_returns_at_all():
    """Without this, a parser that matches nothing reports every file clean
    and the ratchet becomes decoration."""
    total = sum(1 for path in API.glob('*.py')
                for _ in _error_returns(path))
    assert total > 150, (
        f'only {total} error returns found across modules/api; the AST walk '
        f'is reading the wrong thing')


def test_the_census_can_tell_a_coded_return_from_an_uncoded_one():
    """CONTROL: if `'code' in keys` were always true, every ceiling would be
    satisfiable by doing nothing."""
    coded = sum(1 for path in API.glob('*.py')
                for _, _, has_code in _error_returns(path) if has_code)
    plain = sum(1 for path in API.glob('*.py')
                for _, _, has_code in _error_returns(path) if not has_code)
    assert coded > 40, f'only {coded} coded returns seen'
    assert plain > 40, f'only {plain} uncoded returns seen'


def test_a_success_return_is_not_counted():
    """CONTROL: 200s do not carry error codes, and counting them would make
    every ceiling unreachable."""
    module = ast.parse(
        "def f():\n    return {'ok': True}, 200\n"
        "def g():\n    return {'error': 'no'}, 404\n")
    found = []
    for node in ast.walk(module):
        if (isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple)
                and len(node.value.elts) == 2):
            body, status = node.value.elts
            if (isinstance(status, ast.Constant)
                    and isinstance(status.value, int)
                    and status.value >= 400
                    and isinstance(body, ast.Dict)):
                found.append(status.value)
    assert found == [404]


# --- the codes themselves ------------------------------------------------

def test_every_code_looks_like_a_code():
    """A code is an identifier a client branches on. A sentence is not one."""
    import re
    pattern = re.compile(r'^[A-Z][A-Z0-9_]{2,48}$')
    bad = []
    for path in sorted(API.glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == 'code'
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                        and not pattern.match(value.value)):
                    bad.append(f'{path.name}:{node.lineno} {value.value!r}')
    assert not bad, 'these are not machine-readable codes: ' + ', '.join(bad)
