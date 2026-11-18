"""The API rate limit labels spell ACME, CRL, IP and OCSP as they are written.

The labels were made from the config keys by capitalising each word, so the
card that tunes security limits read "Acme", "Crl Download", "Ip Ceiling" and
"Ocsp Status", and a screen reader announced the same through the inputs'
aria-label. Known keys now have written labels; a key the page does not know
still gets the generated one, so a new bucket is never shown without a name.
"""
import json
import os
import re

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
CARD = '[x-data*=rateLimitManager]'
MANGLED = re.compile(r'\b(Acme|Crl|Ip|Ocsp)\b')


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _labels(page):
    page.goto(f'{BASE_URL}/settings#apikeys', wait_until='networkidle')
    page.wait_for_function(
        f"() => document.querySelectorAll('{CARD} label.block').length > 0")
    labels = page.eval_on_selector_all(f'{CARD} label.block', 'els => els.map(e => e.textContent.trim())')
    arias = page.eval_on_selector_all(f'{CARD} input[type=number]',
                                      'els => els.map(e => e.getAttribute("aria-label"))')
    return labels, arias


def test_the_known_limits_are_labelled_as_written(page):
    labels, arias = _labels(page)
    for written in ('ACME', 'CRL download', 'IP ceiling', 'OCSP status'):
        assert written in labels, (written, labels)
    assert not [t for t in labels + arias if MANGLED.search(t)], (labels, arias)
    assert 'OCSP status requests per minute' in arias


def test_a_key_the_page_does_not_know_still_has_a_label(page):
    """CONTROL: an unknown bucket falls back to the generated label."""
    def answer(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps({
            'enabled': True, 'defaults': {'acme': 300, 'zone_transfer': 5}, 'limits': {}}))
    page.route('**/api/settings/rate-limits', answer)
    labels, _ = _labels(page)
    assert labels == ['ACME', 'Zone Transfer']
