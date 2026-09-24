"""The post-login `next` guard inspected two characters. Browsers strip more.

`safeNextUrl()` in templates/login.html rejected a value whose second
character was `/` or `\\`, to stop `//evil.example` and its backslash
variants. It could not see anything the URL parser removes *before* those
characters matter:

    /<TAB>/evil.example/

has `/` at [0] and a tab at [1], so neither branch fired. The browser then
stripped the tab while parsing, leaving `//evil.example/` — and
`window.location.href` went cross-origin, carrying whatever the login flow
had put in the query or fragment. Carriage return and newline behave the same
way, and the set of characters a parser strips is not ours to track.

Measured against the real WHATWG parser before the fix:

    "/\\t/evil.example/"  -> guard "/\\t/evil.example/"  -> lands on https://evil.example

The guard resolves the value and compares origins now, which is what the
server-side twin in `modules/web/oidc_routes.py` has effectively always done
(`urlparse` strips those characters before the netloc check, so the Python
side was never vulnerable — the two only disagreed because one parsed and the
other guessed).

The function is extracted from the shipped template and run under node, so
this exercises the code the browser gets rather than a Python restatement of
it.
"""
import json
import pathlib
import shutil
import subprocess

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
LOGIN = REPO / 'templates' / 'login.html'
ORIGIN = 'https://certmate.example'

# Values that must never leave this origin. The first three are what the old
# character test caught; the rest are what it did not.
HOSTILE = [
    '//evil.example/',
    '/\\evil.example/',
    '\\\\evil.example/',
    '/\t/evil.example/',
    '/\n/evil.example/',
    '/\r/evil.example/',
    '/\t\\evil.example/',
    '/\r\n//evil.example/',
    'https://evil.example/',
    'http://evil.example/',
    '//evil.example\\@certmate.example/',
]

# And values that must still work, or the guard has traded one defect for a
# product that cannot redirect anywhere.
ALLOWED = {
    '/dashboard': '/dashboard',
    '/dashboard?tab=certs': '/dashboard?tab=certs',
    '/dashboard?tab=certs#row-3': '/dashboard?tab=certs#row-3',
    '/': '/',
}


def _guard_source():
    """The shipped function, lifted out of the template verbatim."""
    html = LOGIN.read_text(encoding='utf-8')
    start = html.index('function safeNextUrl()')
    end = html.index('\n        }', start) + len('\n        }')
    source = html[start:end]
    assert 'safeNextUrl' in source and 'return' in source, (
        'the guard was not extracted — this test is reading nothing')
    return source


def _run(values):
    """Resolve each value through the real guard and report the origin."""
    script = _guard_source() + f"""
const BASE = {json.dumps(ORIGIN)};
globalThis.window = {{ location: {{ search: '', origin: BASE }} }};
const out = {{}};
for (const value of {json.dumps(values)}) {{
    window.location.search = '?next=' + encodeURIComponent(value);
    let returned, origin;
    try {{
        returned = safeNextUrl();
        origin = new URL(returned, BASE).origin;
    }} catch (e) {{ returned = null; origin = 'THREW'; }}
    out[value] = [returned, origin];
}}
console.log(JSON.stringify(out));
"""
    result = subprocess.run(['node', '-e', script],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


pytestmark.append(
    pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed'))


@pytest.mark.parametrize('value', HOSTILE)
def test_no_value_reaches_another_origin(value):
    """THE regression. Four of these passed the old guard."""
    returned, origin = _run([value])[value]

    assert origin == ORIGIN, (
        f'{value!r} came back as {returned!r} and lands on {origin}'
    )


@pytest.mark.parametrize('value,expected', sorted(ALLOWED.items()))
def test_a_legitimate_destination_still_works(value, expected):
    """CONTROL. A guard that answered '/' to everything would pass the tests
    above and make `next` useless — including the redirect the login flow
    itself depends on."""
    returned, origin = _run([value])[value]

    assert (returned, origin) == (expected, ORIGIN)


def test_the_guard_parses_rather_than_inspecting_characters():
    """The character test is what could not see a stripped tab. Asserted so
    that a future edit cannot quietly reintroduce the same shape."""
    source = _guard_source()

    assert 'new URL(' in source
    assert '.origin !== ' in source
    assert "raw[1] === '/'" not in source


def test_the_server_side_twin_agrees():
    """The two guards protect the same journey and disagreed for years. If
    the Python one ever loses its parse, this says so before a browser does."""
    from modules.web.oidc_routes import _safe_next

    for value in ('/\t/evil.example/', '//evil.example/', 'https://evil.example/'):
        assert _safe_next(value) == '/', f'{value!r} survived the server guard'
    assert _safe_next('/dashboard') == '/dashboard'
