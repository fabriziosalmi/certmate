"""The Content-Security-Policy allows no `eval` and no inline script, and the page needs neither.

`script-src` carried 'unsafe-eval' and 'unsafe-inline' (#314). Both are gone,
and each for a reason that has to stay true:

* **no `eval`**: Alpine is `@alpinejs/csp`, the build that parses an expression
  itself where the standard one compiles it with `new Function()`;
* **no inline script**: no markup carries an event handler (a control names an
  action, tests/test_no_markup_carries_script.py), and the <script> blocks
  written into the templates carry the nonce of the response they are in.

A policy that says so and a page that still needs what it forbids is a page
that stops working, quietly, one control at a time. So the three have to hold
together: the header, the vendored Alpine, and the nonce on every script the
templates write. That every expression can be evaluated is
scripts/check_alpine_expressions.mjs, which needs Node and runs in the
`frontend-css` job; what is checked here is that the job still runs it.

In a browser: tests/test_ui_the_policy_stops_a_script_that_is_not_the_pages.py.
"""
import json
import re
from pathlib import Path

import pytest

from tests.test_csp_img_src_airgap import _csp, client  # noqa: F401

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
VENDORED = REPO / 'static' / 'js' / 'alpine.min.js'


def test_script_src_is_the_page_itself_and_this_responses_nonce(client):  # noqa: F811
    directive = _csp(client)['script-src'].split()
    assert directive[:2] == ['script-src', "'self'"], directive
    assert len(directive) == 3 and re.fullmatch(r"'nonce-[A-Za-z0-9_-]{22,}'", directive[2]), directive


def test_nothing_else_brings_them_back(client):  # noqa: F811
    """A `default-src` or another directive could allow what `script-src` does not.
    Styles keep 'unsafe-inline': that is `style-src`, and it runs nothing."""
    policy = _csp(client)
    assert all("'unsafe-eval'" not in directive for directive in policy.values()), policy
    inline = sorted(name for name, directive in policy.items() if "'unsafe-inline'" in directive)
    assert inline == ['style-src'], inline
    assert policy['default-src'] == "default-src 'self'"
    assert 'script-src-attr' not in policy and 'script-src-elem' not in policy


def test_the_nonce_is_new_for_every_response_and_cannot_be_guessed(client):  # noqa: F811
    seen = {_csp(client)['script-src'].split()[2] for _ in range(50)}
    assert len(seen) == 50
    # 18 random bytes, base64: 144 bits.
    assert all(len(nonce) == len("'nonce-'") + 24 for nonce in seen), sorted(seen)[:3]


@pytest.fixture
def pages(tmp_path, monkeypatch):
    """The application with its templates, which `client` above is built without."""
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    from modules.factory import create_app
    application, _container = create_app()
    return application.test_client()


SCRIPT_TAG = re.compile(r'<script\b([^>]*)>', re.I)
LOADS_A_FILE = re.compile(r'(?:^|\s)src\s*=', re.I)


def _inline_scripts(markup):
    """The attributes of every <script> that carries its code, however the tag is written."""
    return [attributes for attributes in SCRIPT_TAG.findall(markup) if not LOADS_A_FILE.search(attributes)]


def test_an_inline_script_is_found_however_it_is_written():
    """CONTROL for the two tests below: what they would not see, they would pass."""
    assert _inline_scripts('<script>a()</script>') == ['']
    assert _inline_scripts('<SCRIPT type="module">a()</SCRIPT>') == [' type="module"']
    assert _inline_scripts('<script data-src="/static/js/a.js">a()</script>') == [' data-src="/static/js/a.js"']
    assert _inline_scripts('<script src="/static/js/a.js"></script><script\n  SRC = "/b.js"></script>') == []


@pytest.mark.parametrize('path', ['/login', '/redoc', '/docs/'])
def test_a_page_carries_the_nonce_its_header_names(pages, path):
    response = pages.get(path, follow_redirects=True)
    assert response.status_code == 200
    header = re.search(r"'nonce-([^']+)'", response.headers['Content-Security-Policy']).group(1)
    written = _inline_scripts(response.get_data(as_text=True))
    assert written, f'{path} has no inline script: this test has lost its subject'
    assert all(f'nonce="{header}"' in attributes for attributes in written), written


def test_every_script_a_template_writes_carries_the_nonce():
    """An inline script without it is blocked, and what it did stops happening
    with no error anyone sees. Data blocks (`type="application/json"`) run
    nothing and need none."""
    bare, counted = [], 0
    for template in sorted((REPO / 'templates').rglob('*.html')):
        for attributes in _inline_scripts(template.read_text()):
            if 'application/json' in attributes or 'application/ld+json' in attributes:
                continue
            counted += 1
            if 'nonce="{{ csp_nonce }}"' not in attributes:
                bare.append(f'{template.name}: <script{attributes}>')
    assert counted >= 15, counted                           # CONTROL: they were found
    assert bare == [], bare


def test_the_swagger_page_is_the_frameworks_with_the_nonce_and_nothing_else():
    """templates/swagger-ui.html overrides the template flask-restx ships,
    whose one inline script would be blocked. It is that template with the
    nonce added: when the framework changes its own, this fails, and the copy
    is made again from the new one."""
    import flask_restx
    theirs = (Path(flask_restx.__file__).parent / 'templates' / 'swagger-ui.html').read_text()
    ours = (REPO / 'templates' / 'swagger-ui.html').read_text()
    assert ours.count('nonce="{{ csp_nonce }}"') == 1
    assert ours.replace(' nonce="{{ csp_nonce }}"', '') == theirs


def test_the_vendored_alpine_is_the_build_that_needs_no_eval():
    pinned = json.loads((REPO / 'package.json').read_text())['devDependencies']['@alpinejs/csp']
    assert re.fullmatch(r'\d+\.\d+\.\d+', pinned), f'not an exact version: {pinned!r}'
    locked = json.loads((REPO / 'package-lock.json').read_text())['packages']['node_modules/@alpinejs/csp']
    assert locked['version'] == pinned

    source = VENDORED.read_text()
    assert f'version:"{pinned}"' in source, 'static/js/alpine.min.js is not the pinned version'
    # What tells the two builds apart in the minified file: this build's parser
    # reports its own errors, and it never compiles a string.
    assert 'CSP Parser Error' in source, 'this is the standard build of Alpine, which needs eval'
    assert 'new Function' not in source and 'new AsyncFunction' not in source


def test_the_pages_load_one_alpine_and_it_is_that_file():
    loads = []
    for template in (REPO / 'templates').rglob('*.html'):
        for src in re.findall(r'<script[^>]*\bsrc="([^"]+)"', template.read_text()):
            if 'alpine' in src.lower():
                loads.append((template.name, src))
    assert loads == [('base.html', '/static/js/alpine.min.js')], loads


def test_the_job_that_checks_every_expression_still_runs():
    """The check needs Node, so it is a step of the `frontend-css` job. A step
    that is deleted fails nothing; this fails."""
    assert (REPO / 'scripts' / 'check_alpine_expressions.mjs').exists()
    workflow = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
    job = workflow[workflow.index('\n  frontend-css:'):]
    following = re.search(r'\n  [a-z][\w-]*:\n', job[1:])
    job = job[:following.start() + 1] if following else job
    assert 'npm ci' in job
    assert 'run: node scripts/check_alpine_expressions.mjs' in job


def test_the_evidence_line_points_at_the_directive():
    """`.airgap.yml` names the file and the line of the directive. It pointed
    at the wrong line for a month once, after the file it names was
    reorganised."""
    declared = (REPO / '.airgap.yml').read_text()
    path, line = re.search(r'evidence: (\S+):(\d+)', declared).groups()
    assert 'script-src' in (REPO / path).read_text().splitlines()[int(line) - 1]
    assert 'OPEN MUST' not in declared, 'the item is closed: the declaration should not list it as open'
