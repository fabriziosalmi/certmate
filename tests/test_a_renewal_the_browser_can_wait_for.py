"""#942: a renewal that SUCCEEDED, reported as a network error.

The report arrived from the in-app bug reporter with its own activity log
attached, and the log said:

    2026-09-25 16:15:42 — renew / certificate / success

The renewal worked. What failed was the HTTP response getting back: status 0
with `Unexpected token '<', "<!DOCTYPE "... is not valid JSON` is a browser
that received an HTML error page, which is what a proxy — or gunicorn's own
`--timeout`, 300s in the shipped image — answers with when a request outlives
it. DNS-01 against a public CA spends minutes on propagation and ACME polling.

The server has supported async issuance since phase 3, and it works. Measured
on the private-CA bench, same certificate, same force flag:

    synchronous   http=200   3.17 s
    async:true    http=202   0.003 s   + job_id, polled to "succeeded"

Three endpoints accept the flag — create, renew and reissue. The dashboard
asked for it on **one**.

## The reason reissue was excluded stopped being true

    // Reissue stays synchronous — it edits a row that already exists, so an
    // optimistic new row would be wrong.

`buildPendingRowsHtml` skips any *issuing* job whose domain is already in the
table — a guard added for the race where SSE beats the poll, and exactly the
case a reissue or a renewal is. So the exclusion bought nothing but a request
held open for the whole round-trip.

A **failed** job is still rendered, deliberately: the row carries the reason,
beside the certificate that is still serving. Measured in a browser rather
than assumed — the first version of this paragraph said no row ever appears,
and the screen said otherwise.

That is why the rule below is derived from the two sources rather than written
as a list: the endpoints that accept the flag come from the Python, the calls
come from the dashboard, and a fourth one added later cannot quietly be left
out.
"""
import ast
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESOURCES = ROOT / 'modules/api/resources_lifecycle.py'
FACTORY = ROOT / 'modules/factory.py'
DASHBOARD = ROOT / 'static/js/dashboard.js'


def _async_capable_resources():
    """Resource classes whose POST honours the async flag, from the source."""
    tree = ast.parse(RESOURCES.read_text(encoding='utf-8'))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if (isinstance(item, ast.FunctionDef) and item.name == 'post'
                    and 'wants_async' in ast.unparse(item)):
                found.append(node.name)
    return found


def _routes_for(resource_names):
    """The URL suffix each of those resources is mounted at."""
    factory = FACTORY.read_text(encoding='utf-8')
    routes = {}
    for name in resource_names:
        match = re.search(
            r"add_resource\(api_resources\['%s'\]\s*,\s*'([^']*)'" % re.escape(name),
            factory)
        if match:
            routes[name] = match.group(1)
    return routes


def _code_only(text):
    """*text* with its comments removed.

    The fourth time in a day that a comment satisfied the assertion meant to
    catch its absence: `renewCertificate` explains the async opt-in in prose
    directly above the flag, so searching the raw scope for the word found the
    explanation whether or not the flag was there.
    """
    lines = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if in_block:
            if '*/' in stripped:
                in_block = False
            continue
        if stripped.startswith('/*'):
            in_block = '*/' not in stripped
            continue
        if stripped.startswith(('//', '*')):
            continue
        lines.append(line.split('//')[0] if '//' in line else line)
    return '\n'.join(lines)


def _function_span(source, start):
    """(start, end) of the function beginning at *start*, by brace matching."""
    depth, opened = 0, False
    for index in range(start, len(source)):
        if source[index] == '{':
            depth += 1
            opened = True
        elif source[index] == '}':
            depth -= 1
            if opened and depth == 0:
                return start, index + 1
    return start, len(source)


def _enclosing_function(source, offset):
    """The text of the nearest function whose body CONTAINS *offset*.

    Walking back to the closest preceding `function ` keyword is not the same
    thing and was the first version of this: it kept landing on inline
    callbacks that had already closed — `function () { loadCertificates(); }`
    — and judged the wrong scope. The span has to be checked.
    """
    import re as _re
    at, outermost = offset, None
    while True:
        start = source.rfind('function', 0, at)
        if start == -1:
            break
        begin, end = _function_span(source, start)
        if begin <= offset < end:
            # A NAMED function, not the innermost closure. The endpoint also
            # appears inside `.catch(function (error) {...})` as the string an
            # error report carries, and judging that scope asks the wrong
            # question: what must handle a 202 is the function performing the
            # request, of which the callbacks are part.
            if _re.match(r'function\s+\w+\s*\(', source[begin:begin + 60]):
                outermost = source[begin:end]
        at = start
    return outermost if outermost is not None else source


def _fetch_calls(source):
    """Every `fetch(...)` in the file, as (url_fragment, whole call text).

    Bracket-matched rather than regex-terminated: the body argument spans
    lines, and the question being asked is whether the async flag is inside
    the same call as the URL.
    """
    calls = []
    for match in re.finditer(r"fetch\(", source):
        depth, start = 0, match.end() - 1
        for index in range(start, len(source)):
            if source[index] == '(':
                depth += 1
            elif source[index] == ')':
                depth -= 1
                if depth == 0:
                    text = source[start:index + 1]
                    # The URL is often concatenated — '/api/certificates/' +
                    # encodeURIComponent(domain) + '/renew' — so join every
                    # literal in the call rather than taking the first.
                    literals = re.findall(r"'([^']*)'", text[:text.find('{')] or text)
                    url = ''.join(part for part in literals if part.startswith('/') or part.startswith('/api'))
                    calls.append((url, text, start))
                    break
    return calls


# --- the instrument -------------------------------------------------------

def test_the_endpoints_are_found_in_the_python():
    """CONTROL: with none found, the rule below checks nothing."""
    resources = _async_capable_resources()

    assert len(resources) >= 3, f'only {resources} honour the async flag'
    assert 'RenewCertificate' in resources
    assert 'CertificateReissue' in resources


def test_each_one_is_mounted_somewhere():
    routes = _routes_for(_async_capable_resources())

    assert len(routes) == len(_async_capable_resources()), (
        f'a resource honours the flag but is mounted nowhere: {routes}')


def test_the_dashboard_makes_calls_the_scan_can_see():
    """CONTROL for the bracket matcher: a parser that found no calls would
    make every endpoint vacuously compliant."""
    calls = _fetch_calls(DASHBOARD.read_text(encoding='utf-8'))
    with_urls = [url for url, _text, _at in calls if url]

    assert len(with_urls) > 10, f'only parsed {with_urls}; the matcher is broken'
    assert any('/renew' in url for url in with_urls)


# --- the rule -------------------------------------------------------------

@pytest.mark.parametrize('resource', sorted(_async_capable_resources()))
def test_the_dashboard_opts_into_async_where_the_server_offers_it(resource):
    """A long ACME round-trip on an open request is #942: the work completes
    and the answer never arrives, so the operator is told a successful renewal
    failed and does not know whether to retry."""
    routes = _routes_for([resource])
    suffix = routes.get(resource, '')
    # '/<string:domain>/renew' -> 'renew'; '/create' -> 'create'
    tail = [part for part in suffix.split('/') if part and '<' not in part]
    if not tail:
        pytest.skip(f'{resource} is mounted at a bare parameter path')
    needle = tail[-1]

    source = DASHBOARD.read_text(encoding='utf-8')
    # The endpoint literal, wherever it appears — a fetch argument, or a
    # ternary assigned to one, which is how /reissue is built. Looking only
    # inside `fetch(...)` skipped the very endpoint this issue is about.
    sites = [m.start() for m in re.finditer(r"'/%s'" % re.escape(needle), source)]
    sites += [m.start() for m in re.finditer(r"'/api/[a-z/]*%s'" % re.escape(needle), source)]
    if not sites:
        pytest.fail(f'the dashboard never names /{needle}, so this rule '
                    f'checks nothing for {resource}')

    for at in sites:
        scope = _enclosing_function(source, at)
        assert '202' in scope, (
            f'the dashboard POSTs to /{needle}, which the server may answer '
            f'with 202 and a job id, and the caller has no branch for it. '
            f'Blocking on the whole issuance is what #942 is: a proxy or '
            f'gunicorn --timeout answers with HTML and the browser reports '
            f'NETWORK_ERROR for work that completed.')


def test_the_reissue_exclusion_is_gone():
    """It was excluded for a reason that had stopped being true, and the
    comment saying so outlived it by longer than the defect did."""
    source = DASHBOARD.read_text(encoding='utf-8')

    assert 'Reissue stays synchronous' not in source
    assert re.search(r'^\s*requestBody\.async = true;', source, re.M), (
        'the create/reissue path no longer opts in at all')


def test_a_queued_job_is_adopted_rather_than_forgotten():
    """202 with a job id and nothing watching it is worse than the blocking
    call: the operator is told nothing at all."""
    source = DASHBOARD.read_text(encoding='utf-8')

    assert 'function adoptRenewalJob(' in source
    adopter = source[source.index('function adoptRenewalJob('):]
    adopter = adopter[:adopter.index('\n    }')]
    assert 'pollCertJob(' in adopter
    assert "kind: 'renew'" in adopter


def test_a_failed_renewal_does_not_report_itself_as_a_failed_issuance():
    """The shared poller serves three kinds of job now, and an operator who
    pressed Renew must not be told issuance failed."""
    source = DASHBOARD.read_text(encoding='utf-8')

    assert "'Certificate renewal failed for '" in source


# Callers that legitimately do not ask, with the reason.
ASKS_EXEMPT = {
    'postCreate':
        'replays a payload the submit path already built, async flag and all '
        '(it is the Retry mirror), so it has nothing of its own to ask with.',
}


@pytest.mark.parametrize('resource', sorted(_async_capable_resources()))
def test_the_caller_actually_asks_for_it(resource):
    """Handling a 202 is not the same as asking for one, and the first version
    of this file only checked the first: removing `async: true` from the renew
    body left every test green while the defect was back. A branch for an
    answer the server will never send is not a fix.
    """
    routes = _routes_for([resource])
    tail = [part for part in routes.get(resource, '').split('/')
            if part and '<' not in part]
    if not tail:
        pytest.skip(f'{resource} is mounted at a bare parameter path')
    needle = tail[-1]

    source = DASHBOARD.read_text(encoding='utf-8')
    sites = [m.start() for m in re.finditer(r"'/%s'" % re.escape(needle), source)]
    sites += [m.start() for m in re.finditer(r"'/api/[a-z/]*%s'" % re.escape(needle), source)]
    assert sites, f'the dashboard never names /{needle}'

    checked = set()
    for at in sites:
        scope = _enclosing_function(source, at)
        name = re.match(r'function\s+(\w+)', scope)
        name = name.group(1) if name else '<anonymous>'
        if name in checked or name in ASKS_EXEMPT:
            continue
        checked.add(name)
        assert re.search(r'\basync\b', _code_only(scope)), (
            f'{name} POSTs to /{needle} without asking for async. The server '
            f'supports it and answers in milliseconds; without the flag the '
            f'request stays open for the whole ACME round-trip, which is #942.')


def test_every_asks_exemption_is_still_earned():
    source = DASHBOARD.read_text(encoding='utf-8')
    missing = [name for name in ASKS_EXEMPT
               if not re.search(r'function\s+%s\s*\(' % re.escape(name), source)]

    assert not missing, (
        f'exempted callers that no longer exist: {missing}')
