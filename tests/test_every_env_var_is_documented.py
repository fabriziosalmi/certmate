"""Every environment variable the code reads is documented, or is listed here.

Twenty-three of the thirty-nine variables `modules/` and `app.py` read appeared
in neither the README nor `docs/docker.md`. Several govern security behaviour:
`BEHIND_PROXY` decides whether `X-Forwarded-For` is trusted — and the login
rate limit is keyed on the address it produces; `CERTMATE_ENABLE_HSTS` and
`PREFERRED_URL_SCHEME` decide whether the session cookie is marked `Secure`;
`CERTMATE_ALLOW_INTERNAL_WEBHOOKS` and `CERTMATE_PROBE_ALLOW_PRIVATE` each
remove an SSRF guard; `CERTMATE_AUDIT_CHAIN=0` turns off the tamper-evident
log.

An undocumented knob is not a secret feature. It is a switch nobody knows is
there, including the person who has to explain the instance's behaviour a year
later — and for these, one that changes the security posture.

The repository already has this shape of test for advertised endpoints and for
the documented port. This is the same idea for the environment, and the census
is taken from the AST rather than from a grep because six of the readers take
the variable name as a *parameter* — `_int_env`, `_env_float`, `_clamp_env_int`
and friends — so a grep for `os.getenv("` misses every variable that reaches
them. The finding that prompted this counted twenty-seven variables by grep;
there are thirty-nine.

Two of those six helpers were found by this file's own control rather than by
reading, which is the argument for the control: a census that quietly stops
seeing a class of readers reports a clean result.

`NOT_OPERATOR_CONFIGURATION` is the reviewable part. Three of the names are set
*for* CertMate by something else — certbot, Kubernetes — and documenting them
as knobs would be wrong, not merely verbose.
"""
import ast
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
DOCS = [REPO / 'README.md', REPO / 'docs' / 'docker.md']

# Functions that read the environment using their first argument as the name.
# Kept explicit, and checked for completeness by a test below: a new helper
# that nobody adds here would make the census quietly incomplete, which is the
# failure mode this whole file exists to prevent.
ENV_HELPERS = {'_int_env', '_env_float', '_env_bool', '_env_int',
               '_clamp_env_int', '_load_or_create'}

# Variables the AST census cannot see, because the name never appears as a
# literal at the point of the read. Listed by hand and checked below: each must
# still exist as a string literal somewhere in the source, so a rename is
# caught rather than silently dropping the entry.
REACHED_THROUGH_A_CONSTANT = {
    'AUDIT_SIGNING_KEY_FILE':
        "reached as AuditSigner(key_file_env=KEY_FILE_ENV) and read inside "
        "_load_or_create as os.getenv(env) — a module constant passed through "
        "a parameter default, which needs interprocedural resolution the "
        "census deliberately does not attempt.",
}

# Read from the environment, but not configuration an operator sets.
NOT_OPERATOR_CONFIGURATION = {
    'CERTBOT_VALIDATION':
        'set BY certbot when it invokes the DNS hook, carrying the challenge '
        'value. Documenting it as a knob would invite someone to set it.',
    'KUBERNETES_SERVICE_HOST':
        'injected by Kubernetes into every pod. Read to detect that the '
        'process is running in-cluster, so the deploy target can use the '
        'service account instead of a kubeconfig.',
    'KUBERNETES_SERVICE_PORT':
        'injected by Kubernetes alongside the host above, and read for the '
        'same reason.',
}


def _source_files():
    return sorted(REPO.glob('modules/**/*.py')) + [REPO / 'app.py']


def _literal(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def environment_variables():
    """{name: {files}} for every variable read by the application.

    Three shapes, because the codebase uses three: `os.getenv("X")`,
    `os.environ.get("X")`, `os.environ["X"]` — plus a call to one of
    ENV_HELPERS, which forward their first argument.
    """
    found = {}
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Call) and node.args:
                called = ast.unparse(node.func)
                if (called in ('os.getenv', 'os.environ.get')
                        or called.split('.')[-1] in ENV_HELPERS):
                    name = _literal(node.args[0])
            elif (isinstance(node, ast.Subscript)
                  and ast.unparse(node.value) == 'os.environ'):
                name = _literal(node.slice)
            if name and name.isupper() and len(name) > 2:
                found.setdefault(name, set()).add(
                    str(path.relative_to(REPO)))
    return found


def documented():
    return '\n'.join(path.read_text(encoding='utf-8') for path in DOCS)


# --- the census ----------------------------------------------------------

def test_every_variable_the_code_reads_is_documented():
    text = documented()
    names = set(environment_variables()) | set(REACHED_THROUGH_A_CONSTANT)
    missing = sorted(
        name for name in names
        if name not in NOT_OPERATOR_CONFIGURATION and f'`{name}`' not in text)
    assert not missing, (
        'these environment variables change how CertMate behaves and appear '
        'in neither README.md nor docs/docker.md:\n  ' + '\n  '.join(missing)
        + '\n\nDocument them in the README environment table, or — if the '
          'variable is set FOR CertMate by something else — add it to '
          'NOT_OPERATOR_CONFIGURATION with the reason.'
    )


def test_the_exemptions_still_correspond_to_variables_that_are_read():
    """A stale exemption is a standing licence for a name that may come back
    meaning something an operator does need to know about."""
    read = set(environment_variables())
    stale = sorted(set(NOT_OPERATOR_CONFIGURATION) - read)
    assert not stale, (
        'NOT_OPERATOR_CONFIGURATION names variables nothing reads any more: '
        + ', '.join(stale))


def test_a_variable_reached_through_a_constant_still_exists():
    """The hand-maintained half of the census. A rename would otherwise drop
    the entry and take the documentation requirement with it."""
    source = '\n'.join(path.read_text(encoding='utf-8')
                       for path in _source_files())
    for name, reason in REACHED_THROUGH_A_CONSTANT.items():
        assert f"'{name}'" in source or f'"{name}"' in source, (
            f'{name} is listed as reached through a constant but no longer '
            f'appears anywhere in the source')
        assert len(reason.strip()) > 40, f'{name} has no usable reason'


def test_every_exemption_says_why():
    for name, reason in NOT_OPERATOR_CONFIGURATION.items():
        assert len(reason.strip()) > 40, (
            f'{name} is exempt with no usable reason: {reason!r}')


# --- controls on the census itself --------------------------------------

def test_the_census_finds_the_variables_that_are_obviously_there():
    """Without this, a broken parser reports an empty set and the test above
    passes on a measurement of nothing."""
    found = environment_variables()
    assert len(found) > 25, (
        f'only {len(found)} environment variables found; the AST walk is '
        f'reading the wrong thing')
    for expected in ('SECRET_KEY_FILE', 'API_BEARER_TOKEN', 'FLASK_ENV'):
        assert expected in found, f'{expected} was not found by the census'


def test_variables_read_through_a_helper_are_found():
    """The reason this is an AST walk and not a grep. Seven variables reach
    the environment through `_int_env` / `_env_float`, and a grep for
    `os.getenv("` finds none of them."""
    found = environment_variables()
    for through_helper in ('CERTMATE_LOG_MAX_BYTES',
                           'CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS',
                           'CERTMATE_AUDIT_LOG_BACKUP_COUNT'):
        assert through_helper in found, (
            f'{through_helper} is read via a helper and the census missed it')


def test_no_reader_helper_is_missing_from_the_list():
    """The census trusts ENV_HELPERS to be complete. A new helper added
    without being listed here would hide every variable that goes through it,
    silently — so find the helpers from the source instead of trusting the
    list, and compare.

    A helper is a function that takes a name parameter and passes THAT
    parameter to os.getenv / os.environ.get, rather than a literal.
    """
    helpers = set()
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for func in [n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef)]:
            params = {a.arg for a in func.args.args}
            for node in ast.walk(func):
                if (isinstance(node, ast.Call) and node.args
                        and ast.unparse(node.func) in ('os.getenv',
                                                       'os.environ.get')
                        and isinstance(node.args[0], ast.Name)
                        and node.args[0].id in params):
                    helpers.add(func.name)
    unlisted = sorted(helpers - ENV_HELPERS)
    assert not unlisted, (
        'these functions read the environment from a name they are passed, '
        'and are not in ENV_HELPERS, so every variable that reaches the '
        'environment through them is invisible to this census: '
        + ', '.join(unlisted))


def test_a_variable_absent_from_the_docs_is_actually_detected():
    """CONTROL: proves the comparison can fail. The docs contain the word
    `PORT` in prose, so a substring match would report `A_MADE_UP_SETTING` as
    documented if the pattern were loose enough."""
    text = documented()
    assert '`A_MADE_UP_SETTING`' not in text
    assert '`CERTMATE_ENABLE_HSTS`' in text, (
        'the documentation lookup is not finding entries that are there')
