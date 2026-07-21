"""A failed SSO load must not offer a form that can wipe the configuration.

Behavioural test for #424. When `GET /api/auth/oidc/settings` failed, the
component set `loading = false` but left `cfg` at `defaultCfg()`, and the
template rendered the full editable form plus an enabled Save under
`x-if="!loading"`. An admin opening Settings → SSO during a transient 500 saw
"SSO not configured", changed something, hit Save — and POSTed the blank
defaults over a live configuration, disabling SSO for the whole organisation.

The failure is driven by intercepting the request in the browser, which is the
only way to prove the *rendered* result rather than the source.
"""

import os

import pytest


pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"

# One handler, installed once, driven by this dict. Installing and removing a
# route per test made the outcome depend on test order: unroute did not
# reliably take effect on the module-scoped page, so the success case
# inherited the previous test's interception and failed. Declaring the intent
# per test removes the question entirely.
_intercept = {"status": None, "body": None}


@pytest.fixture(scope="module", autouse=True)
def _oidc_route(browser_page):
    def handler(route):
        if _intercept["status"] is None:
            route.continue_()
            return
        route.fulfill(status=_intercept["status"],
                      body=_intercept["body"],
                      content_type="application/json")

    browser_page.route("**/api/auth/oidc/settings", handler)
    yield
    _intercept["status"] = None


def _open_sso_tab(page):
    # reload(), not goto(): navigating to the same URL when only the fragment
    # differs does NOT reload the page — which is #425 itself, and it bit this
    # test first. Without the reload the component is never re-initialised, no
    # request is made, and the panel simply keeps the previous test's state.
    page.goto(f"{BASE_URL}/settings#oidc", wait_until="networkidle")
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(1000)
    return page.locator("#settings-panel-oidc")


def test_a_failed_load_hides_the_form_and_explains_why(browser_page):
    _intercept.update(status=500, body='{"error":"boom"}')
    panel = _open_sso_tab(browser_page)

    assert panel.locator("button:has-text('Save SSO settings')").count() == 0, \
        "the Save button is live on blank defaults — one click wipes the SSO config"
    assert panel.locator("text=Could not load the SSO configuration").count() == 1
    assert panel.locator("button:has-text('Retry')").count() == 1


def test_a_permission_error_is_reported_the_same_way(browser_page):
    """403 took the same silent path: form visible, defaults loaded."""
    _intercept.update(status=403, body='{"error":"admin required"}')
    panel = _open_sso_tab(browser_page)

    assert panel.locator("button:has-text('Save SSO settings')").count() == 0
    assert panel.locator("text=Could not load the SSO configuration").count() == 1


def test_a_successful_load_still_renders_the_form(browser_page):
    """The guard must not hide the tab when everything is fine."""
    _intercept.update(status=None, body=None)
    panel = _open_sso_tab(browser_page)

    assert panel.locator("button:has-text('Save SSO settings')").count() == 1
    assert panel.locator("text=Could not load the SSO configuration").count() == 0
