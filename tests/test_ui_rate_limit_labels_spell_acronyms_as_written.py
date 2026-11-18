"""The API rate limit labels spell ACME, CRL, IP and OCSP as they are written.

The labels were made from the config keys by capitalising each word, so the
card that tunes security limits read "Acme", "Crl Download", "Ip Ceiling" and
"Ocsp Status", and a screen reader announced the same through the inputs'
aria-label. Known keys now have written labels in the page's Title Case
("Key Name"), with the acronyms spelled; a key the page does not know, an
inherited name such as "constructor" included, still gets the generated one,
so a new bucket is never shown without a name.
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
    for written in ('ACME', 'CRL Download', 'IP Ceiling', 'OCSP Status',
                    'Certificate Create', 'Certificate Batch'):
        assert written in labels, (written, labels)
    assert not [t for t in labels + arias if MANGLED.search(t)], (labels, arias)
    assert 'OCSP Status requests per minute' in arias


def test_a_key_not_in_the_table_falls_back_to_the_generated_label(page):
    """No known key in the defaults: every label comes from the fallback,
    and an inherited name such as "constructor" is not looked up on the
    prototype (with a plain index lookup that row gets an empty label and
    no aria-label)."""
    def answer(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps({
            'enabled': True, 'defaults': {'zone_transfer': 5, 'constructor': 7, 'to_string': 9},
            'limits': {}}))
    page.route('**/api/settings/rate-limits', answer)
    labels, arias = _labels(page)
    assert labels == ['Zone Transfer', 'Constructor', 'To String']
    assert arias == ['Zone Transfer requests per minute', 'Constructor requests per minute',
                     'To String requests per minute']
