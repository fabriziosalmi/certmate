"""In-process guard on the CSP directives the air-gap property depends on.

`.airgap.yml` declares this surface conformant with `deviations: []`, and the
existing CSP tests (tests/test_static_csp.py) are marked `e2e` — they need a
running container, so the release gate never sees them. This file is the
unit-level backstop for the two directives that are load-bearing.

`img-src 'self' data:` in particular is doing more work than it looks like:
the vendored ReDoc bundle (static/js/redoc.standalone.js) still hardcodes
`https://cdn.redoc.ly/redoc/logo-mini.svg` for its sidebar logo. Nothing in
CertMate asks for that image — the CSP is what stops the browser fetching it,
and ReDoc's own onError handler then hides the element. So loosening img-src
would silently reintroduce a third-party request on every /redoc view, in a
product whose whole point is running where there is no third party to call.
"""
from pathlib import Path

import pytest

from modules.core.factory import create_app

pytestmark = [pytest.mark.unit]

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client(tmp_path, monkeypatch):
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    fake_factory_file = module_dir / "factory.py"
    fake_factory_file.write_text("# test path anchor\n")
    monkeypatch.setattr("modules.core.factory.__file__", str(fake_factory_file))
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("TESTING", "true")
    application, _ = create_app()
    return application.test_client()


def _csp(client):
    response = client.get("/health")
    csp = response.headers.get("Content-Security-Policy")
    assert csp, "no Content-Security-Policy header on the response"
    return {
        part.strip().split(" ")[0]: part.strip()
        for part in csp.split(";") if part.strip()
    }


def test_img_src_allows_no_remote_origin(client):
    """`self` and `data:` only — no scheme wildcard, no CDN host."""
    directive = _csp(client)["img-src"]
    assert directive == "img-src 'self' data:", (
        f"img-src is now {directive!r}. The vendored ReDoc bundle asks for "
        f"cdn.redoc.ly/redoc/logo-mini.svg; this directive is the only thing "
        f"stopping that request."
    )


def test_default_src_is_self(client):
    assert _csp(client)["default-src"] == "default-src 'self'"


def test_frame_ancestors_and_base_uri_are_locked(client):
    directives = _csp(client)
    assert directives["frame-ancestors"] == "frame-ancestors 'self'"
    assert directives["base-uri"] == "base-uri 'self'"
    assert directives["form-action"] == "form-action 'self'"


def test_redoc_bundle_is_served_locally():
    """The bundle must stay vendored — a CDN <script> would be a real
    deviation, not one the CSP happens to absorb."""
    redoc_html = (REPO_ROOT / "templates" / "redoc.html").read_text()
    assert "/static/js/redoc.standalone.js" in redoc_html
    assert "cdn.redoc.ly" not in redoc_html
    assert "fonts.googleapis.com" not in redoc_html


def test_help_page_does_not_hardcode_a_provider_count():
    """The help page's provider count must come from the code, not memory.

    It read "The dropdown lists 22 providers in total" while
    DNSManager.SUPPORTED_PROVIDERS had 29 — the kind of number that is only
    ever right on the day someone types it. Asserted against the template
    source rather than a rendered page: the count is the thing under test,
    and rendering /help would drag in auth and the whole template chain.
    """
    import re

    help_html = (REPO_ROOT / "templates" / "help.html").read_text()
    assert "{{ provider_count }} providers in total" in help_html
    literal = re.search(r"lists\s+(\d+)\s+providers in total", help_html)
    assert literal is None, (
        f"help.html hardcodes a provider count ({literal.group(1)}) again — "
        f"pass it from the route instead."
    )


def test_help_route_supplies_the_real_provider_count():
    """And the route must supply the count the DNS manager actually has."""
    import inspect

    from modules.core.dns_providers import DNSManager
    from modules.web import ui_routes

    source = inspect.getsource(ui_routes.register_ui_routes)
    assert "provider_count=len(DNSManager.SUPPORTED_PROVIDERS)" in source
    assert len(DNSManager.SUPPORTED_PROVIDERS) == len(
        set(DNSManager.SUPPORTED_PROVIDERS)
    ), "SUPPORTED_PROVIDERS has duplicates, so the count would overstate"
