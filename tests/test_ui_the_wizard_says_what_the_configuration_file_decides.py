"""On an instance whose configuration file declares the DNS account, the
wizard's last step says the credentials typed were not saved, and by what.

Found in review of the UX perception audit fix for P19: with CERTMATE_CONFIG_FILE
declaring Cloudflare's "default" account, step 3 said "Settings saved" and
listed "DNS Provider: Cloudflare", while the token typed was never written
(settings.json held no trace of it). The save's answer names what it set that
something else decides (tests/test_a_settings_save_names_what_it_does_not_decide.py),
and step 3 says it.

Driven through the real pages in Chromium, against a fresh instance in setup
mode (the fixture of tests/test_ui_the_first_admin_can_be_given_an_email.py),
started with a configuration file.
"""
import json

import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

from tests import test_ui_the_first_admin_can_be_given_an_email as first_admin

instance = first_admin.instance
chromium = first_admin.chromium
PASSWORD = first_admin.PASSWORD

pytestmark = [pytest.mark.ui]

TYPED = 'typed-in-the-wizard-0123456789'


@pytest.fixture
def declared(tmp_path, monkeypatch):
    """Requested before `instance`, so the instance starts with the file."""
    path = tmp_path / 'declared.json'
    path.write_text(json.dumps({'version': 1, 'dns_providers': {'cloudflare': {'accounts': {'default': {
        'name': 'Declared', 'api_token_env': 'DECLARED_CF_TOKEN'}}}}}))
    monkeypatch.setenv('CERTMATE_CONFIG_FILE', str(path))
    monkeypatch.setenv('DECLARED_CF_TOKEN', 'from-the-environment')
    monkeypatch.delenv('CLOUDFLARE_TOKEN', raising=False)
    monkeypatch.delenv('LETSENCRYPT_EMAIL', raising=False)
    return path


def _step_three(page, base):
    page.goto(base + '/', wait_until='load')
    page.fill('#username', 'operator')
    page.fill('#password', PASSWORD)
    page.click('#setupBtn')
    page.wait_for_url('**/login', timeout=15000)
    page.fill('#username', 'operator')
    page.fill('#password', PASSWORD)
    page.click('#loginBtn')
    page.wait_for_selector('#wizEmail', state='visible', timeout=15000)
    page.fill('#wizEmail', 'ops@example.org')
    page.click('#wizNext1')
    page.click('[data-provider="cloudflare"]')
    page.fill('#wiz_api_token', TYPED)
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish', timeout=15000)
    return page.inner_text('#wizardBody')


def test_a_declared_account_is_said_not_saved_on_step_three(declared, instance, chromium):
    base, _ = instance
    page = chromium.new_page()
    try:
        text = _step_three(page, base)
        assert 'Settings saved, not all in effect' in text, text
        note = page.inner_text('[data-not-in-effect]')
        assert 'Cloudflare API Token: not saved' in note and 'CERTMATE_CONFIG_FILE' in note, note
        assert TYPED not in text and 'from-the-environment' not in text
    finally:
        page.close()


def test_without_a_configuration_file_step_three_says_saved_with_no_exception(instance, chromium, monkeypatch):
    """CONTROL: a plain instance has nothing out of effect."""
    base, _ = instance
    page = chromium.new_page()
    try:
        text = _step_three(page, base)
        assert 'Settings saved' in text and 'not all in effect' not in text, text
        assert page.locator('[data-not-in-effect]').count() == 0
    finally:
        page.close()
