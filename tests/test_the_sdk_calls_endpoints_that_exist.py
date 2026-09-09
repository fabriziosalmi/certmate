"""The list of endpoints the SDK uses is read from the SDK, not remembered.

`tests/test_clients_e2e.py` carried nine endpoints in a literal list, checked
against the Swagger spec of a running container. Two things were wrong with
that, and the first one had already happened.

**It was stale.** The SDK calls nineteen endpoints. The list had nine, and the
ten it did not know about include `certificates/{}/deploy`,
`settings/dns-providers`, `dns/{}/accounts`, `audit/verify` and `activity` —
so the drift check whose whole purpose is catching a renamed endpoint had
stopped covering half the client. A list maintained by memory decays exactly
where nobody is looking, which is where the drift is.

**It could not see the blueprint.** Its own comment excluded
`/api/web/test-provider` and `/api/web/backups` because they are not in the
restx schema — but the SDK calls them, so a rename there was invisible to the
one test that exists to notice. It also needed a built container, which put a
contract between two files in this repository behind the slowest tier in the
suite.

So the list is derived: walk the SDK's `_request` calls with `ast` and compare
what comes out against the application's own `url_map`. Both sides are read
from source, nothing is remembered, and it runs in the unit tier.
"""
import ast
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
SDK_CLIENT = REPO / 'clients' / 'certmate-sdk' / 'certmate' / 'client.py'

# What the SDK's transport helper is called. If it is renamed, every extraction
# below finds nothing — which is why `test_the_extraction_found_the_client`
# exists.
TRANSPORT = '_request'


def _normalise(path: str) -> str:
    """Collapse a path parameter to `{}` in either notation.

    Flask writes `<domain>` and `<path:name>`; the SDK's f-strings arrive here
    already as `{}`.
    """
    return re.sub(r'<[^>]*>', '{}', path)


def _literal_paths(node, assignments):
    """Every string a path expression can evaluate to.

    Four shapes appear in the client: a plain string, an f-string, a name
    assigned earlier in the same method, and a conditional expression — which
    is `list_dns_accounts`, whose two branches are two different endpoints and
    both have to be checked.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [''.join(str(part.value) if isinstance(part, ast.Constant)
                        else '{}' for part in node.values)]
    if isinstance(node, ast.IfExp):
        return (_literal_paths(node.body, assignments)
                + _literal_paths(node.orelse, assignments))
    if isinstance(node, ast.Name):
        return [value for assigned in assignments.get(node.id, [])
                for value in _literal_paths(assigned, assignments)]
    return []


def sdk_calls():
    """(method, path) for every request the SDK makes, from its source."""
    tree = ast.parse(SDK_CLIENT.read_text(encoding='utf-8'))
    calls, unresolved = set(), []

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        assignments = {}
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments.setdefault(target.id, []).append(node.value)

        for node in ast.walk(function):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == TRANSPORT
                    and len(node.args) >= 2):
                continue
            methods = _literal_paths(node.args[0], assignments)
            paths = _literal_paths(node.args[1], assignments)
            if not methods or not paths:
                unresolved.append(f'{function.name} (line {node.lineno})')
                continue
            for method in methods:
                for path in paths:
                    calls.add((method.lower(), _normalise(path)))

    assert not unresolved, (
        'these SDK calls build their path in a way this extraction cannot '
        'read, so they would be checked against nothing: '
        + ', '.join(unresolved))
    return calls


@pytest.fixture(scope='session')
def routes(tmp_path_factory):
    """The application's route table, keyed by normalised path.

    Built under a temporary root: `setup_directories()` creates state relative
    to `modules/core/factory.__file__`, and a test that only reads the route
    table must not write into the checkout (#702).
    """
    root = tmp_path_factory.mktemp('sdkroutes') / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n', encoding='utf-8')

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('TESTING', 'true')
        patch.setenv('FLASK_ENV', 'testing')
        from modules.core.factory import create_app
        patch.setattr('modules.core.factory.__file__', str(anchor))
        result = create_app()
    app = result[0] if isinstance(result, tuple) else result

    merged = {}
    for rule in app.url_map.iter_rules():
        verbs = {method.lower() for method in rule.methods
                 if method not in ('HEAD', 'OPTIONS')}
        # Union, never overwrite: several paths are served by more than one
        # rule, and keeping whichever iterated last reports the wrong verbs.
        merged.setdefault(_normalise(str(rule)), set()).update(verbs)
    return merged


# --- the instrument first -------------------------------------------------

def test_the_extraction_found_the_client():
    """A derivation that quietly finds nothing passes every comparison below.
    The hand-written list it replaces had nine entries; anything at or under
    that is the extraction failing, not the SDK shrinking."""
    calls = sdk_calls()

    assert len(calls) > 12, f'only {len(calls)} SDK calls found: {sorted(calls)}'
    assert ('get', '/api/certificates') in calls
    assert ('post', '/api/certificates/create') in calls


def test_the_route_table_was_built(routes):
    """CONTROL for the other side of the comparison."""
    assert len(routes) > 50
    assert '/api/certificates' in routes


def test_the_conditional_path_yields_both_endpoints():
    """`list_dns_accounts` picks its path with a conditional expression. Both
    branches are real endpoints and a reader of the source sees one."""
    calls = sdk_calls()

    assert ('get', '/api/dns/accounts') in calls
    assert ('get', '/api/dns/{}/accounts') in calls


# --- THE contract ---------------------------------------------------------

def test_every_endpoint_the_sdk_calls_exists(routes):
    """The drift check. A renamed or removed route breaks the published SDK,
    and this is the only thing that looks."""
    missing = sorted(f'{method.upper()} {path}'
                     for method, path in sdk_calls()
                     if path not in routes)

    assert not missing, (
        'the SDK calls endpoints this application does not serve:\n  '
        + '\n  '.join(missing))


def test_every_endpoint_the_sdk_calls_accepts_its_method(routes):
    """A path that exists with the wrong verb is a 405 at runtime, which reads
    to a user like the server being broken rather than the client."""
    wrong = sorted(
        f'{method.upper()} {path} (route accepts {sorted(routes[path])})'
        for method, path in sdk_calls()
        if path in routes and method not in routes[path])

    assert not wrong, (
        'the SDK uses a verb the route does not accept:\n  ' + '\n  '.join(wrong))


# --- what the hand-maintained list was missing ---------------------------

@pytest.mark.parametrize('method,path', [
    # In the old list.
    ('get', '/api/certificates'),
    ('post', '/api/certificates/create'),
    # Not in it, and not findable by it: the blueprint endpoints its own
    # comment excluded for not being in the restx schema.
    ('post', '/api/web/certificates/test-provider'),
    ('get', '/api/web/backups'),
    ('post', '/api/web/backups/create'),
    # Not in it for no stated reason at all — the drift the plan predicted.
    ('post', '/api/certificates/{}/deploy'),
    ('get', '/api/settings/dns-providers'),
    ('get', '/api/dns/{}/accounts'),
    ('get', '/api/audit/verify'),
    ('get', '/api/activity'),
    ('get', '/health'),
])
def test_the_endpoints_the_old_list_did_not_know_about(routes, method, path):
    """Named one by one, so that if the derivation ever stops finding one of
    them the failure says which."""
    assert (method, path) in sdk_calls()
    assert path in routes and method in routes[path]


def test_the_stale_literal_list_is_gone():
    """It cannot stay beside this file: two lists of the same thing means the
    one nobody updates is the one that keeps passing."""
    e2e = (REPO / 'tests' / 'test_clients_e2e.py').read_text(encoding='utf-8')

    assert '_SDK_RESTX_ENDPOINTS' not in e2e
