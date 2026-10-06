"""The Content-Security-Policy allows no `eval`, and the page does not need it.

`script-src` carried 'unsafe-eval' because the standard build of Alpine
compiles every expression in the markup with `new Function()`. The page now
runs `@alpinejs/csp`, the build that parses an expression itself, and the token
is gone.

Three things have to stay true together, and each has failed somewhere before
in the shape "the control was there and looked at nothing":

* the header does not allow it;
* the vendored file is the build that does not need it, at the version the
  lockfile pins;
* every expression in the templates is one that build can evaluate. That is
  scripts/check_alpine_expressions.mjs, which needs Node and runs in the
  `frontend-css` job; what is checked here is that the job still runs it.

`'unsafe-inline'` is still in `script-src`, for the inline scripts and event
handlers (#314). The test below says so, so that the day it goes this file is
where someone finds out the comment in `.airgap.yml` is stale.
"""
import json
import re
from pathlib import Path

import pytest

from tests.test_csp_img_src_airgap import _csp, client  # noqa: F401

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
VENDORED = REPO / 'static' / 'js' / 'alpine.min.js'


def test_script_src_allows_no_eval(client):  # noqa: F811
    directive = _csp(client)['script-src']
    assert "'unsafe-eval'" not in directive, directive
    assert directive.split()[:2] == ['script-src', "'self'"], directive
    # Still there, and tracked: the inline scripts and handlers (#314).
    assert "'unsafe-inline'" in directive, 'gone: update .airgap.yml and this test'


def test_nothing_else_brings_eval_back(client):  # noqa: F811
    """A `default-src` or a second policy could allow what `script-src` does not."""
    policy = _csp(client)
    assert all("'unsafe-eval'" not in directive for directive in policy.values()), policy
    assert policy['default-src'] == "default-src 'self'"


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
    """`.airgap.yml` tracks the open item with a file and a line. It pointed at
    the wrong line for a month once, after the file it names was reorganised."""
    declared = (REPO / '.airgap.yml').read_text()
    path, line = re.search(r'evidence: (\S+):(\d+)', declared).groups()
    assert 'script-src' in (REPO / path).read_text().splitlines()[int(line) - 1]
