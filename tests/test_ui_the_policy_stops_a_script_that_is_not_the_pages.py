"""The policy stops a script that is not the page's, and lets the page's own run.

`script-src` is `'self'` and a nonce made for each response. What that is for
is the case where something gets markup into a page that should not have:
with 'unsafe-inline' in the policy, as it was, the browser ran it.

So markup is put into the page here the way an injection would put it, in the
four forms inline script takes: an event-handler attribute, a <script> element,
a `javascript:` address and a string handed to `eval`. None of them may run,
and the browser must say it refused each.

The control is in the same test, because a page where nothing runs would pass
the lines above: the page's own inline script did run (it defines `setTheme`),
and the very same injected <script> does run once it carries the nonce of the
page. The nonce is what decides, and nothing else.
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

_REFUSED = """() => {
    window.__ran = [];
    window.__refused = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__refused.push(e.violatedDirective));
}"""

_INJECT = """() => {
    const box = document.createElement('div');
    box.id = 'injected';
    box.style.cssText = 'position:fixed;top:0;left:0;z-index:2147483647;background:#fff;padding:8px';
    box.innerHTML = `
        <button type="button" id="inj-handler" onclick="window.__ran.push('handler')">a handler attribute</button>
        <a id="inj-address" href="javascript:window.__ran.push('address')">a javascript address</a>
        <img id="inj-image" src="/static/does-not-exist.png" onerror="window.__ran.push('onerror')">`;
    document.body.appendChild(box);
    const script = document.createElement('script');
    script.textContent = "window.__ran.push('script')";
    document.body.appendChild(script);
    // `eval` is called here to see it refused. From a timer, not directly:
    // code a test evaluates through the debugger is exempt from the policy
    // for the length of that call, and a direct call ran on a page that
    // refuses it to everything else.
    setTimeout(() => {
        try { eval("window.__ran.push('eval')"); } catch (e) { window.__refused.push('eval: ' + e.name); }
    }, 0);
}"""


@pytest.mark.parametrize('path', ['/help', '/settings', '/'])
def test_what_is_not_the_pages_does_not_run_and_what_is_does(browser_page, path):
    page = browser_page
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); } catch (e) {}")
    page.goto(f'{BASE_URL}{path}', wait_until="networkidle")
    page.evaluate(_REFUSED)

    page.evaluate(_INJECT)
    page.click('#inj-handler')
    page.click('#inj-address')
    page.wait_for_timeout(400)                  # the image has failed to load by now

    assert page.evaluate("() => window.__ran") == []
    refused = page.evaluate("() => window.__refused")
    # The handler attributes (the button's and the image's), the address and
    # the element, each named by the directive that refused it; and eval.
    assert sum(directive.startswith('script-src-attr') for directive in refused) >= 2, refused
    assert sum(directive.startswith('script-src-elem') for directive in refused) >= 2, refused
    assert 'eval: EvalError' in refused, refused

    # CONTROL: the page's own inline script ran,
    assert page.evaluate("() => typeof setTheme") == 'function'
    assert page.evaluate("() => typeof CertMate.actions") == 'function'
    # and the same element runs once it carries the page's nonce.
    page.evaluate("""() => {
        const script = document.createElement('script');
        script.nonce = document.querySelector('script[nonce]').nonce;
        script.textContent = "window.__ran.push('with the nonce')";
        document.body.appendChild(script);
    }""")
    assert page.evaluate("() => window.__ran") == ['with the nonce']
