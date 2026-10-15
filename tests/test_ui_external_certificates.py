"""External certificates in the browser (#1159).

What only a browser shows: that the import form, set to "not by CertMate",
hides everything about a renewal and imports the certificate; that its row and
its detail panel offer the replacement where a renewal would be, and nothing
that renews it; and that a replacement is refused for an earlier expiry until
the box says it is meant, then put in place. What each request carries is
pinned in test_external_certificates_ui.py, and the API in
test_external_certificates.py.

The tests run in order on one certificate, imported by the first.
"""
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER
from tests.conftest import BASE_URL as _API_URL
from tests.test_certificate_import import make_bundle

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
DOMAIN = 'external.ui.test'
TILES = ('importCertificateFile', 'importChainFile', 'importPrivateKeyFile')


def _write(directory, bundle):
    paths = []
    for name in ('certificate', 'chain', 'private_key'):
        path = directory / f'{name}.pem'
        path.write_text(bundle[name])
        paths.append(str(path))
    return paths


@pytest.fixture(scope='module')
def bundles(tmp_path_factory):
    """The certificate imported, one that expires before it, and one after."""
    root = tmp_path_factory.mktemp('external-ui')
    made = {}
    for label, end in (('first', 120), ('earlier', 60), ('later', 200)):
        directory = root / label
        directory.mkdir()
        made[label] = _write(directory, make_bundle(names=(DOMAIN,), end=end))
    return made


@pytest.fixture(scope='module', autouse=True)
def _remove_the_certificate(docker_container, ui_session_cookie):
    yield
    import requests
    session = requests.Session()
    session.cookies.set('certmate_session', ui_session_cookie)
    session.headers['Origin'] = _API_URL
    session.delete(f'{_API_URL}/api/certificates/{DOMAIN}')


def _row(page):
    return page.locator(f'tr[data-row-domain="{DOMAIN}"]')


def _open_panel(page):
    page.goto(BASE_URL, wait_until='networkidle')
    _row(page).wait_for(timeout=15000)
    _row(page).click()
    page.wait_for_selector('#certDetailPanel [data-external-badge]', timeout=5000)


def test_01_the_form_imports_it_and_asks_nothing_about_a_renewal(browser_page, bundles):
    page = browser_page
    page.goto(BASE_URL, wait_until='networkidle')
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.check('#importExistingCertificate')
    assert page.is_visible('#ca_provider_select') and page.is_visible('#importAutoRenewOption')

    page.check('#importRenewalExternal')

    for selector in ('#ca_provider_select', '#challenge_type_select', '#dns-provider-container',
                     '#importAutoRenewOption', '#advancedOptionsToggle'):
        assert not page.is_visible(selector), f'{selector} is shown for an external import'
    for tile, path in zip(TILES, bundles['first'], strict=True):
        page.set_input_files(f'#{tile}', path)
    page.get_by_text('Ready to import.').wait_for(timeout=10000)
    page.click('#createCertForm button[type="submit"]')
    page.get_by_text(f'External certificate imported for {DOMAIN}').first.wait_for(timeout=10000)


def test_02_its_row_offers_the_replacement_and_no_renewal(browser_page):
    page = browser_page
    page.goto(BASE_URL, wait_until='networkidle')
    row = _row(page)
    row.wait_for(timeout=15000)
    assert 'External' in row.inner_text()
    assert 'Replace by' in row.inner_text()
    assert row.locator('button[data-action="replace"]').count() == 1
    assert row.locator('button[data-action="renew"]').count() == 0

    row.locator('button[data-more-domain]').click()
    menu = page.locator('[role="menu"]')
    menu.wait_for(timeout=5000)
    items = menu.inner_text()
    assert 'Replace certificate' in items
    assert 'Force renew' not in items and 'auto-renew' not in items
    page.keyboard.press('Escape')


def test_03_its_panel_says_what_it_is_and_renews_nothing(browser_page):
    page = browser_page
    _open_panel(page)
    panel = page.locator('#certDetailPanel')
    text = panel.inner_text()
    assert 'Not renewed by CertMate' in text and 'Not by CertMate: replaced by upload' in text
    for label in ('Renew certificate', 'Force renew', 'Edit & reissue'):
        assert panel.locator(f'button[aria-label="{label}"]').count() == 0, label
    assert panel.locator('button[aria-label="Auto-renew"]').count() == 0
    assert panel.locator('button[aria-label="Replace certificate"]').count() == 1
    assert not page.is_visible('#certReplaceSection')


def test_04_an_earlier_expiry_is_refused_until_the_box_says_it_is_meant(browser_page, bundles):
    page = browser_page
    _open_panel(page)
    page.click('#certDetailPanel button[aria-label="Replace certificate"]')
    page.wait_for_selector('#certReplaceSection', state='visible')
    for tile, path in zip(('replaceCertificateFile', 'replaceChainFile', 'replacePrivateKeyFile'),
                          bundles['earlier'], strict=True):
        page.set_input_files(f'#{tile}', path)
    page.get_by_text('Ready to replace.').wait_for(timeout=10000)

    page.click('#replaceCertificateSubmit')
    page.get_by_text('Tick "Accept a certificate that expires before this one"').first.wait_for(timeout=10000)
    assert page.is_visible('#certReplaceSection')

    page.check('#replaceAllowEarlierExpiry')
    page.click('#replaceCertificateSubmit')
    page.get_by_text(f'Certificate replaced for {DOMAIN}').first.wait_for(timeout=10000)


def test_05_a_replacement_is_shown_on_the_certificate(browser_page, bundles):
    page = browser_page
    _open_panel(page)
    assert 'Replaced' in page.locator('#certDetailPanel').inner_text()
    page.click('#certDetailPanel button[aria-label="Replace certificate"]')
    for tile, path in zip(('replaceCertificateFile', 'replaceChainFile', 'replacePrivateKeyFile'),
                          bundles['later'], strict=True):
        page.set_input_files(f'#{tile}', path)
    page.get_by_text('Ready to replace.').wait_for(timeout=10000)
    page.click('#replaceCertificateSubmit')
    page.get_by_text(f'Certificate replaced for {DOMAIN}').first.wait_for(timeout=10000)
