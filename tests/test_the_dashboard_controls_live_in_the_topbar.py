"""#359 moved the dashboard's header band into the global topbar.

The view toggle `[ Server | Client | New ]` and the certificate counters used
to be a row at the top of the page content, with an empty band between them
and the table. They are in the topbar now, which frees that row on the one page
where vertical space is worth the most.

That move costs something, and these tests are about the cost. The topbar is
`base.html`, shared by every page; the panels the toggle switches are in
`index.html`. Two Alpine roots, no common scope, so the view had to leave
`x-data` and become a global store — and a store has failure modes a screenshot
does not show:

* a page that **reads** `$store.certs` where nothing **registered** it. Alpine
  evaluates `$store.certs.view` against an undefined store and throws on every
  binding in the tree, which on the dashboard is the whole certificate list;
* the cluster **duplicated** to get the responsive layout. Its element ids are
  where `updateStats()`, `ccLoadStatistics()` and the command palette write, and
  `getElementById` answers with the first match — a second copy at another
  breakpoint would leave one set of counters permanently at zero. One node,
  moved by CSS, is why the layout uses `order-last` and an `xl:` variant rather
  than two copies;
* the cluster on a page that is not the dashboard. The first attempt guarded
  both halves with `request.path == '/'`, which is wrong in a way that only the
  rendered page shows: **`setup.html` is served from `/` too**. A fresh,
  unconfigured instance — the first screen an operator ever sees — got the
  toggle and an empty counter strip, and `openCertDrawer` is not defined there
  because `dashboard.js` is not loaded. So the controls are a `{% block %}` the
  page declares for itself, and the store registration lives in the same
  partial: one thing to include, rather than two conditions that have to stay
  identical by hand.

The behavioural half — that clicking the toggle in the topbar still switches
the panels below it — is `tests/test_ui_hash_navigation.py` and
`tests/test_ui.py`, which drive a real browser.

One note on how these are written. HTML comments are *served*, so a needle that
also reads as English can be satisfied by a comment explaining why the thing is
absent: the first draft of the setup-page test below searched for
`openCertDrawer`, and passed nothing, because a comment in base.html names it.
Every needle here is markup or code — an `id="..."` with its quotes, an
`aria-label`, a call with its comma — which prose does not produce by accident.
"""
import os
import re
from pathlib import Path

import pytest
from flask import Flask, render_template, request

pytestmark = [pytest.mark.unit]

_TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "templates")

# The ids the JavaScript writes into and the command palette clicks. Each one
# must resolve to exactly one element on the dashboard.
SINGLETON_IDS = ("certViewServerBtn", "certViewClientBtn", "statsCards",
                 "totalCount", "activeCount", "revokedCount")

# Markers, not words: the store registration with its argument list, and the
# toggle group's own label.
REGISTRATION = "Alpine.store('certs',"
TOGGLE_GROUP = 'aria-label="Certificate view and creation"'


@pytest.fixture
def render_at():
    """Render any template at any path.

    Both are variables on purpose. The path used to decide whether the topbar
    carried the dashboard's controls, and the bug that hid behind that is
    precisely a second template rendered at the dashboard's own path — so a
    fixture that ties one template to one path could not have found it.
    """
    app = Flask(__name__, template_folder=_TEMPLATES)

    @app.route("/", defaults={"rest": ""})
    @app.route("/<path:rest>")
    def any_path(rest):
        return render_template(request.args["template"])

    client = app.test_client()

    def render(path, template):
        response = client.get(path, query_string={"template": template})
        assert response.status_code == 200, f"{template} at {path} did not render"
        return response.get_data(as_text=True)

    return render


def _read(rel):
    return (Path(__file__).resolve().parent.parent / rel).read_text(encoding="utf-8")


# --- the controls belong to one page, not to one path ---------------------

def test_the_dashboard_registers_the_store_it_reads(render_at):
    body = render_at("/", "index.html")

    assert REGISTRATION in body
    assert "$store.certs.view" in body


def test_the_setup_page_shares_the_path_and_carries_none_of_it(render_at):
    """THE one that was wrong. `/` renders setup.html on an unconfigured
    instance, so a path-based guard put the certificate toggle on the
    create-your-first-admin screen — with `openCertDrawer` undefined, because
    that page does not load dashboard.js."""
    body = render_at("/", "setup.html")

    assert 'id="certViewServerBtn"' not in body
    assert 'id="statsCards"' not in body
    assert TOGGLE_GROUP not in body
    assert REGISTRATION not in body


def test_a_page_that_is_not_the_dashboard_neither_registers_nor_reads_it(render_at):
    """THE pairing. A store registered on every page would be harmless; a page
    reading one that was never registered throws in every Alpine binding on
    it."""
    body = render_at("/settings", "settings.html")

    assert REGISTRATION not in body
    assert "$store.certs" not in body, \
        "this page reads the dashboard's store, and nothing registered it here"


def test_the_chrome_alone_carries_no_dashboard_state(render_at):
    """CONTROL for the fixture as much as for the templates: if the controls
    were unconditional, every case above would pass for the wrong reason."""
    body = render_at("/", "base.html")

    assert REGISTRATION not in body
    assert 'id="certViewServerBtn"' not in body
    # ...while still being the topbar.
    assert 'alt="CertMate"' in body


def test_the_store_ships_with_the_markup_that_reads_it():
    """Why there is one include and not two: the registration and the only
    bindings that use it are in the same file, so a page cannot pick up half of
    it."""
    partial = _read("templates/partials/_dashboard_topbar.html")

    assert REGISTRATION in partial
    assert "$store.certs.view" in partial


# --- one node, not two ----------------------------------------------------

@pytest.mark.parametrize("element_id", SINGLETON_IDS)
def test_each_written_id_appears_once(render_at, element_id):
    """`getElementById` answers with the first match. A second copy of the
    cluster for the narrow layout would leave the other one at zero for the
    life of the page."""
    found = len(re.findall(r'id="%s"' % re.escape(element_id),
                           render_at("/", "index.html")))

    assert found == 1, f'{element_id} appears {found} times on the dashboard'


def test_the_narrow_layout_moves_the_cluster_rather_than_repeating_it():
    """What makes one node enough: below `xl` the cluster wraps onto a line of
    its own (`order-last w-full`), above it sits in the bar. Pinning the
    mechanism, because the alternative — rendering it twice with `hidden` — is
    the obvious way to do this and breaks every id above."""
    partial = _read("templates/partials/_dashboard_topbar.html")

    assert "order-last" in partial and "w-full" in partial
    assert "xl:order-none" in partial
    assert "xl:w-auto" in partial


def test_the_row_the_cluster_wraps_inside_can_wrap():
    """`w-full` only starts a second line in a `flex-wrap` container. Without
    it the three clusters share one line and squash each other, which reads as
    a styling accident rather than a missing class."""
    nav = _read("templates/base.html").split("</nav>")[0]

    assert "flex flex-wrap items-center justify-between" in nav


def test_the_built_css_carries_the_variants_the_cluster_needs():
    """Tailwind emits a utility only for classes it found while scanning. A
    partial moved out of the `content` globs — or a bundle committed without
    the rebuild — would leave these inert and the cluster stuck on its own row
    at every width, with no error anywhere to say so."""
    css = _read("static/css/tailwind.min.css")

    assert r".xl\:order-none" in css
    assert r".xl\:w-auto" in css


# --- the page no longer owns the state ------------------------------------

def test_the_dashboard_declares_no_view_of_its_own():
    """Two sources for one view is worse than either: the page's `x-data` would
    shadow the store inside its own tree, so the topbar toggle and the panels
    would disagree while both looked right in isolation."""
    index = _read("templates/index.html")

    assert "certView" not in index, \
        "the page still declares its own view state alongside the store"
