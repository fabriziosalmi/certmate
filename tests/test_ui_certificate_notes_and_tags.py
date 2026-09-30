"""Notes and tags, in the browser (#1043).

The API half is pinned in test_certificate_notes_and_tags.py. What only a
browser shows: that the detail panel can edit them, that a saved tag appears on
the row and in the tag bar, that choosing it filters the list, that the ⌘K
palette finds a certificate by a word an operator wrote, that a note is shown
as text and never as markup, and that a keypress on a tag chip does not also open
the row it sits in.

Two certificates are placed in the test container's certificate directory,
because an instance that has issued nothing has no rows to edit.
"""
import datetime
import json
import os

import pytest

from tests.conftest import CONTAINER_NAME, _docker, _REQUIRE_BROWSER

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
TAGGED = 'tagged.labels-ui.test'
PLAIN = 'plain.labels-ui.test'


def _seed(tmp_path, domain):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=60))
            .sign(key, hashes.SHA256()))
    d = tmp_path / domain
    d.mkdir()
    (d / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / 'privkey.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (d / 'metadata.json').write_text(json.dumps({'domain': domain, 'dns_provider': 'cloudflare'}))
    _docker('cp', str(d), f'{CONTAINER_NAME}:/app/certificates/{domain}')
    _docker('exec', '-u', 'root', CONTAINER_NAME, 'chown', '-R', '1000:1000',
            f'/app/certificates/{domain}')


@pytest.fixture(scope='module', autouse=True)
def two_certificates(docker_container, ui_session_cookie, tmp_path_factory):
    tmp = tmp_path_factory.mktemp('labels-ui')
    _seed(tmp, TAGGED)
    _seed(tmp, PLAIN)
    yield
    for domain in (TAGGED, PLAIN):
        _docker('exec', '-u', 'root', CONTAINER_NAME, 'rm', '-rf',
                f'/app/certificates/{domain}', check=False)


def _open_dashboard(page):
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(BASE_URL, wait_until='networkidle')
    page.wait_for_selector(f'tr[data-row-domain="{TAGGED}"]', timeout=15000)


def _row(page, domain):
    return page.locator(f'tr[data-row-domain="{domain}"]')


def test_01_a_note_and_tags_are_saved_from_the_detail_panel(browser_page):
    page = browser_page
    _open_dashboard(page)
    sent = []
    page.on('request', lambda r: sent.append(r.post_data)
            if r.method == 'PATCH' and TAGGED in r.url else None)

    _row(page, TAGGED).click()
    page.wait_for_selector('#certLabelsSection [data-labels-edit]')
    assert 'Nothing recorded' in page.locator('#certLabelsSection').inner_text()

    page.click('[data-labels-edit]')
    page.fill('#certLabelTags', 'Prod, Load-Balancer , prod')
    page.fill('#certLabelNotes', 'order 4711\n<img src=x onerror="window.__xss=1">')
    page.click('[data-labels-save]')
    page.wait_for_selector('#certLabelsSection [data-tag-chip="prod"]')

    assert json.loads(sent[-1]) == {
        'tags': ['Prod', 'Load-Balancer', 'prod'],
        'notes': 'order 4711\n<img src=x onerror="window.__xss=1">'}
    section = page.locator('#certLabelsSection')
    assert section.locator('[data-tag-chip]').all_inner_texts() == ['#prod', '#load-balancer']
    # The note is text: the tag in it is shown, not built.
    assert section.locator('img').count() == 0
    assert 'window.__xss=1' in section.inner_text()
    assert page.evaluate('window.__xss') is None


def test_02_the_row_and_the_tag_bar_show_what_was_saved(browser_page):
    page = browser_page
    _open_dashboard(page)
    assert _row(page, TAGGED).locator('[data-tag-chip]').all_inner_texts() == ['#prod', '#load-balancer']
    assert _row(page, PLAIN).locator('[data-tag-chip]').count() == 0
    bar = page.locator('#tagFilterBar')
    assert bar.is_visible()
    assert bar.locator('[data-tag-filter]').all_inner_texts()[0].startswith('#load-balancer')


def test_03_choosing_a_tag_filters_the_list_and_choosing_it_again_clears_it(browser_page):
    page = browser_page
    _open_dashboard(page)
    assert _row(page, PLAIN).is_visible()

    page.click('#tagFilterBar [data-tag-filter="prod"]')
    assert _row(page, TAGGED).is_visible()
    assert _row(page, PLAIN).count() == 0
    assert page.locator('#tagFilterBar [data-tag-filter="prod"]').get_attribute('aria-pressed') == 'true'

    page.click('#tagFilterBar [data-tag-filter="prod"]')
    assert _row(page, PLAIN).is_visible()


def test_04_a_tag_on_a_row_filters_without_opening_the_detail_panel(browser_page):
    page = browser_page
    _open_dashboard(page)

    _row(page, TAGGED).locator('[data-tag-chip="prod"]').click()

    assert _row(page, PLAIN).count() == 0
    assert not page.locator('#certDetailPanel').is_visible()
    page.click('#tagFilterBar [data-tag-filter="prod"]')


def test_05_a_key_on_a_tag_chip_does_not_also_open_the_row(browser_page):
    page = browser_page
    _open_dashboard(page)

    page.locator(f'tr[data-row-domain="{TAGGED}"] [data-tag-chip="load-balancer"]').focus()
    page.keyboard.press('Enter')

    assert not page.locator('#certDetailPanel').is_visible()
    page.click('#tagFilterBar [data-tag-filter="load-balancer"]')


def test_06_the_palette_finds_a_certificate_by_a_tag_or_a_word_in_its_note(browser_page):
    page = browser_page
    _open_dashboard(page)

    for query in ('load-balancer', 'order 4711'):
        page.keyboard.press('Control+k')
        page.wait_for_selector('#cmdPaletteInput', state='visible')
        page.fill('#cmdPaletteInput', query)
        page.wait_for_timeout(300)
        results = page.locator('#cmdPaletteResults').inner_text()
        assert TAGGED in results and PLAIN not in results, f'{query!r}: {results!r}'
        page.keyboard.press('Escape')


def test_07_clearing_them_removes_the_chips_and_hides_the_bar(browser_page):
    page = browser_page
    _open_dashboard(page)
    _row(page, TAGGED).click()
    page.click('[data-labels-edit]')
    page.fill('#certLabelTags', '')
    page.fill('#certLabelNotes', '')
    page.click('[data-labels-save]')
    page.wait_for_selector('#certLabelsSection:has-text("Nothing recorded")')

    page.keyboard.press('Escape')
    page.wait_for_timeout(400)
    assert _row(page, TAGGED).locator('[data-tag-chip]').count() == 0
    assert not page.locator('#tagFilterBar').is_visible()
