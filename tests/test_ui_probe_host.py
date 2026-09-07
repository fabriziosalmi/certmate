"""A wildcard's probe host must be settable from the UI (#635).

Reported by a user: a wildcard certificate reports "cannot be verified", and the
only way to fix it was `PATCH /api/certificates/<domain>` with a
`deployment_host`. "It would be useful to be able to set the host through the
GUI rather than the API."

Settings → Probe already existed and already wrote `deployment_port` and
`deployment_protocol` through that same PATCH — it simply had no field for the
one value a wildcard actually needs. So this adds the field rather than a new
dialog.

Three things are worth pinning beyond "the input exists", and none of them is
visible from the JS source:

* the value reaches the PATCH body, not just the DOM;
* a certificate configured with ONLY a host counts as configured, or it stays in
  the "Add" list forever and the operator sets it twice;
* clearing the field clears the stored host, so a wrong host can be undone
  without deleting and recreating the probe.
"""
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
WILDCARD = '*.example.com'


def _open_probe_tab(page, certificates):
    """Open Settings → Probe with a known certificate list.

    /api/certificates is intercepted so the tab has something to show without
    issuing anything: the probe list is built entirely from that response, and
    what matters here is the PATCH the form sends back.
    """
    page.route(
        '**/api/certificates',
        lambda route: route.fulfill(
            status=200, content_type='application/json',
            body=__import__('json').dumps(certificates)),
    )
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(f'{BASE_URL}/settings')
    page.click('#settings-tab-probe')
    page.wait_for_selector('#settings-panel-probe', state='visible')


def _capture_patches(page):
    seen = []
    page.on('request', lambda r: (
        seen.append((r.url, r.post_data)) if r.method == 'PATCH' else None))
    return seen


def test_the_add_form_has_a_host_field(browser_page):
    _open_probe_tab(browser_page, [])
    assert browser_page.locator(
        '#settings-panel-probe input[aria-label="Probe host"]').count() >= 1, (
        'Settings -> Probe still has no host field, so a wildcard can only be '
        'made verifiable through the API'
    )


def test_the_host_reaches_the_patch_body(browser_page):
    """The field existing is not the fix; the value arriving is."""
    _open_probe_tab(browser_page, [])
    patches = _capture_patches(browser_page)

    panel = browser_page.locator('#settings-panel-probe')
    panel.locator('input[x-model="addDomain"]').fill(WILDCARD)
    panel.locator('input[aria-label="Probe host"]').fill('www.example.com')
    panel.locator('button:has-text("Add Probe")').last.click()
    browser_page.wait_for_timeout(500)

    assert patches, 'no PATCH was sent at all'
    url, body = patches[-1]
    assert WILDCARD.replace('*', '%2A') in url or 'example.com' in url
    assert '"deployment_host": "www.example.com"' in (body or '').replace(
        '"deployment_host":"www.example.com"',
        '"deployment_host": "www.example.com"'), (
        f'the host did not reach the request body: {body}'
    )


def test_the_placeholder_suggests_a_covered_name_for_a_wildcard(browser_page):
    """A wildcard does not cover its apex, and that is the whole trap. The
    field suggests a name the certificate actually covers rather than leaving
    the operator to type the apex and get a mismatch."""
    _open_probe_tab(browser_page, [])
    panel = browser_page.locator('#settings-panel-probe')
    panel.locator('input[x-model="addDomain"]').fill(WILDCARD)
    browser_page.wait_for_timeout(200)

    placeholder = panel.locator(
        'input[aria-label="Probe host"]').first.get_attribute('placeholder')
    assert placeholder == 'www.example.com', (
        f'expected a covered-name suggestion, got {placeholder!r}'
    )


def test_a_probe_with_only_a_host_counts_as_configured(browser_page):
    """Otherwise the certificate stays in "Add Probe" after being configured,
    and the operator sets it a second time."""
    _open_probe_tab(browser_page, [{
        'domain': WILDCARD, 'deployment_host': 'www.example.com',
        'deployment_port': None, 'deployment_protocol': None,
    }])
    browser_page.wait_for_timeout(300)

    configured = browser_page.locator('#settings-panel-probe').inner_text()
    assert 'Configured Probes' in configured
    assert 'host www.example.com' in configured, (
        'a host-only probe is not shown as configured'
    )


def test_clearing_the_host_sends_null(browser_page):
    """A wrong host must be undoable in place. Sending nothing would leave the
    old value stored and the probe still pointed at the wrong name."""
    _open_probe_tab(browser_page, [{
        'domain': WILDCARD, 'deployment_host': 'wrong.example.com',
        'deployment_port': 443, 'deployment_protocol': 'https-tls',
    }])
    browser_page.wait_for_timeout(300)
    patches = _capture_patches(browser_page)

    panel = browser_page.locator('#settings-panel-probe')
    panel.locator('button:has-text("Edit")').first.click()
    host = panel.locator('input[aria-label="Probe host"]').first
    assert host.input_value() == 'wrong.example.com', (
        'the edit form did not load the stored host'
    )
    host.fill('')
    panel.locator('button:has-text("Save")').first.click()
    browser_page.wait_for_timeout(500)

    assert patches, 'no PATCH was sent'
    body = (patches[-1][1] or '').replace(' ', '')
    assert '"deployment_host":null' in body, (
        f'clearing the field did not clear the stored host: {patches[-1][1]}'
    )
