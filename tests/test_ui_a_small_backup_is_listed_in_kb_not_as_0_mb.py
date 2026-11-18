"""A backup of a few tens of KB is listed with its size, not as "0 MB".

The settings page rounded every size to tenths of a megabyte, so anything
under 52,429 bytes read "0 MB". A small install's backups weigh tens of KB,
so every row looked empty on the one page meant to reassure.

The first test makes a real backup on the instance and reads its row; the
second answers the listing in the browser with sizes on each side of a unit
boundary, so the choice of unit is checked without writing big archives.
"""
import json
import os
import re

import pytest
import requests

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
ROWS = '#unified-backup-list span'


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _sizes(page):
    page.goto(f'{BASE_URL}/settings#backup', wait_until='networkidle')
    page.wait_for_function(
        "() => document.querySelectorAll('#unified-backup-list .fa-file-zipper').length > 0")
    texts = page.eval_on_selector_all(ROWS, 'els => els.map(e => e.textContent.trim())')
    return [t for t in texts if re.fullmatch(r'[\d.]+ (B|KB|MB|GB)', t)]


def test_a_real_backup_of_a_few_kb_is_listed_in_kb(page, ui_session_cookie):
    s = requests.Session()
    s.cookies.set('certmate_session', ui_session_cookie)
    made = s.post(f'{BASE_URL}/api/backups/create', json={'type': 'unified', 'reason': 'manual_backup'},
                  headers={'Origin': BASE_URL}, timeout=30)
    assert made.status_code in (200, 201), made.text[:200]
    listed = s.get(f'{BASE_URL}/api/backups', timeout=10).json()['unified']
    size = listed[0]['metadata']['size']
    assert 1024 <= size < 1024 * 1024, f'the archive is {size} bytes, not in the KB range'

    sizes = _sizes(page)
    assert sizes, 'no size is shown on the backup rows'
    assert '0 MB' not in sizes
    assert sizes[0].endswith(' KB'), sizes


def test_each_size_is_shown_in_the_unit_that_reads(page):
    sizes = [512, 1943, 52262, 3670016, 5 * 1024 ** 3]
    rows = [{'filename': f'certmate_backup_2026111{i}_000000.zip', 'type': 'unified',
             'metadata': {'size': n, 'created': '2026-11-18T01:49:00Z', 'total_domains': 1,
                          'backup_reason': 'manual'}}
            for i, n in enumerate(sizes)]

    def answer(route):
        route.fulfill(status=200, content_type='application/json',
                      body=json.dumps({'unified': rows}))
    page.route('**/api/backups', answer)
    assert _sizes(page) == ['512 B', '1.9 KB', '51 KB', '3.5 MB', '5 GB']
