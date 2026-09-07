"""Every manager looked up by string key must be a manager that exists.

The extracted API groups reach the long-tail managers out of the context
mapping by name — `ctx.managers.get('storage')`, `ctx.managers.get('file_ops')`
— and answer 503 when the lookup comes back empty. That makes a wrong key a
silent, total outage of the endpoint, indistinguishable from a manager that is
genuinely unconfigured.

It is not hypothetical. Moving the backup group out of the closure rewrote the
captured names to `ctx.*` with a regex that did not respect string boundaries,
so `managers.get('file_ops')` became `managers.get('ctx.file_ops')` and
BackupDelete answered 503 to every request. Every build-only test passed,
because none of them call the method.

Rather than add a call-through test per endpoint — which only ever covers the
endpoints someone remembered — this reads the keys straight out of the source
and checks them against the mapping the application really builds. It covers
groups that do not exist yet.
"""
import ast
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

API_DIR = Path(__file__).resolve().parent.parent / 'modules' / 'api'
FACTORY = Path(__file__).resolve().parent.parent / 'modules' / 'core' / 'factory.py'


def _known_manager_keys():
    """The keys `container.managers` is actually populated with."""
    tree = ast.parse(FACTORY.read_text(encoding='utf-8'))
    keys = set()
    for node in ast.walk(tree):
        # container.managers = { 'file_ops': ..., ... }
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            targets = [ast.unparse(t) for t in node.targets]
            if not any(t.endswith('managers') for t in targets):
                continue
            for key in node.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    keys.add(key.value)
        # container.managers['x'] = ... , managers.setdefault('x', ...)
        elif isinstance(node, ast.Subscript):
            if (ast.unparse(node.value).endswith('managers')
                    and isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, str)):
                keys.add(node.slice.value)
    return keys


def _looked_up_keys():
    """Every literal key read out of a managers mapping in modules/api."""
    found = []
    pattern = re.compile(r'managers\.get\(\s*[\'"]([^\'"]+)[\'"]')
    for path in sorted(API_DIR.glob('*.py')):
        for lineno, line in enumerate(
                path.read_text(encoding='utf-8').splitlines(), 1):
            for match in pattern.finditer(line):
                found.append((path.name, lineno, match.group(1)))
    return found


def test_the_factory_key_set_was_actually_found():
    """CONTROL: the check below is vacuous if this comes back empty.

    A refactor that renames the mapping, or an AST shape this parser does not
    recognise, would leave `_known_manager_keys()` empty — and an empty
    reference set makes every lookup below look wrong, or (worse, if the
    assertion were written the other way round) makes them all look fine.
    """
    keys = _known_manager_keys()
    assert len(keys) >= 8, (
        f'only found {sorted(keys)} in factory.py; the parser has lost track '
        f'of how the manager mapping is built, so the check below means '
        f'nothing'
    )
    for expected in ('file_ops', 'settings', 'auth', 'certificates'):
        assert expected in keys, f'{expected} missing from the parsed key set'


def test_every_manager_lookup_names_a_manager_that_exists():
    lookups = _looked_up_keys()
    assert lookups, (
        'no managers.get(...) calls were found in modules/api at all; either '
        'the pattern stopped matching or the groups stopped using the '
        'mapping — either way this test is no longer watching anything'
    )

    known = _known_manager_keys()
    wrong = [(f, n, k) for f, n, k in lookups if k not in known]
    assert not wrong, (
        'these lookups name a manager the application never puts in the '
        'mapping, so the endpoint answers 503 unconditionally: '
        + '; '.join(f'{f}:{n} -> {k!r}' for f, n, k in wrong)
        + f'. Known managers: {sorted(known)}'
    )


def test_no_lookup_key_carries_a_context_prefix():
    """CONTROL: names the exact corruption this exists to catch.

    The generic check above would already catch `'ctx.file_ops'`, but only for
    as long as no manager is ever named something similar. This states the rule
    directly so the failure message points at the cause rather than at a
    missing key.
    """
    bad = [(f, n, k) for f, n, k in _looked_up_keys() if k.startswith('ctx.')]
    assert not bad, (
        'a lookup key was rewritten as if it were an identifier: '
        + '; '.join(f'{f}:{n} -> {k!r}' for f, n, k in bad)
    )
