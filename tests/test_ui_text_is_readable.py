"""Text the UI draws in its own colour tokens reaches WCAG AA contrast (4.5:1).

Measured over 20 views before this was written:

* in dark mode the brand blue (`text-primary`, one fixed hsl(216 76% 43%) for
  buttons and text) was 2.5 to 2.7:1 on the dark surfaces: every link on the
  help page, the active settings menu item, the pressed status chip;
* in light mode the muted text token was 4.39:1 on the light grey surfaces;
* a pressed green or amber status chip was 4.1 and 4.2:1 in light mode, and its
  count was dimmed further with opacity-70 (2.6:1).

The contrast is computed the way WCAG defines it: the text colour, its alpha
and every ancestor's opacity composited over the stack of backgrounds behind
it. Text inside a dimmed section (an ancestor with opacity below 1, the
"inactive" look of a turned-off setting) is not held to it, as WCAG does not
hold inactive components to it.
"""
import pytest

from tests.conftest import _REQUIRE_BROWSER, BASE_URL

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

AA = 4.5
BRAND_BLUE = 'rgb(26, 93, 193)'

CONTRAST = r"""
window.__contrast = (function () {
  function parse(c) {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  }
  function lum(c) {
    const a = c.slice(0, 3).map(v => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * a[0] + 0.7152 * a[1] + 0.0722 * a[2];
  }
  function background(el) {
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      // A gradient or an image behind the text has no single colour to measure.
      if (getComputedStyle(n).backgroundImage !== 'none') return null;
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
    }
    let base = (layers.length && layers[layers.length - 1][3] >= 1)
      ? layers.pop().slice(0, 3)
      : parse(getComputedStyle(document.body).backgroundColor).slice(0, 3);
    for (let i = layers.length - 1; i >= 0; i--) {
      const l = layers[i];
      base = base.map((v, k) => l[k] * l[3] + v * (1 - l[3]));
    }
    return base;
  }
  function opacity(el) {
    let op = 1;
    for (let n = el; n; n = n.parentElement) op *= parseFloat(getComputedStyle(n).opacity);
    return op;
  }
  function ratio(el) {
    const fg = parse(getComputedStyle(el).color), b = background(el), op = opacity(el);
    if (!b) return null;
    const f = fg.slice(0, 3).map((v, k) => v * fg[3] * op + b[k] * (1 - fg[3] * op));
    const L1 = lum(f), L2 = lum(b);
    return (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
  }
  // The colour a class resolves to on this page, in this theme.
  function colourOf(cls) {
    const probe = document.createElement('span');
    probe.className = cls;
    document.body.appendChild(probe);
    const c = getComputedStyle(probe).color;
    probe.remove();
    return c;
  }
  // Every visible text drawn in `colour`, outside dimmed sections, below `need`.
  function below(colour, need) {
    const out = [];
    for (const el of document.querySelectorAll('body *')) {
      if (el.closest('[inert],[aria-hidden=true]')) continue;
      if (!el.checkVisibility({opacityProperty: true, visibilityProperty: true})) continue;
      if (![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
      if (getComputedStyle(el).color !== colour || opacity(el) < 1) continue;
      const r = ratio(el);
      if (r !== null && r < need) out.push([el.innerText.trim().slice(0, 30), +r.toFixed(2)]);
    }
    return out;
  }
  // Every visible text under AA (3:1 when large), outside dimmed and disabled parts.
  function texts() {
    const out = [];
    for (const el of document.querySelectorAll('body *')) {
      if (el.closest('[inert],[aria-hidden=true],[disabled],[aria-disabled=true],option')) continue;
      if (el.matches(':disabled')) continue;
      if (!el.checkVisibility({opacityProperty: true, visibilityProperty: true})) continue;
      if (![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
      if (opacity(el) < 1) continue;
      const st = getComputedStyle(el), size = parseFloat(st.fontSize), bold = parseInt(st.fontWeight) >= 700;
      const need = (size >= 24 || (bold && size >= 18.66)) ? 3 : 4.5;
      const r = ratio(el);
      if (r !== null && r < need) out.push([el.innerText.trim().slice(0, 30), +r.toFixed(2)]);
    }
    return out;
  }
  // Every visible control that is only an icon, under 3:1 (WCAG 1.4.11).
  function controls() {
    const out = [];
    for (const el of document.querySelectorAll('a[href], button, [role=button]')) {
      if (el.closest('[inert],[aria-hidden=true]') || el.matches(':disabled')) continue;
      if (!el.checkVisibility({opacityProperty: true, visibilityProperty: true})) continue;
      if ((el.innerText || '').trim() || el.querySelector('img')) continue;
      const icon = el.querySelector('i, svg');
      if (!icon || opacity(icon) < 1) continue;
      const r = ratio(icon);
      if (r !== null && r < 3) out.push([el.getAttribute('aria-label') || el.title || '(unnamed)', +r.toFixed(2)]);
    }
    return out;
  }
  return {ratio, colourOf, below, texts, controls};
})();
"""


@pytest.fixture
def open_page(browser_page, ui_session_cookie):
    browser = browser_page.context.browser
    contexts = []

    def run(path, scheme, width=1280):
        context = browser.new_context(viewport={'width': width, 'height': 900}, color_scheme=scheme)
        contexts.append(context)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        context.add_init_script(CONTRAST)
        page = context.new_page()
        page.goto(f'{BASE_URL}{path}', wait_until='networkidle')
        assert page.url.split('#')[0].endswith(path.split('#')[0]), f'{path} landed on {page.url}'
        page.wait_for_timeout(500)
        return page

    yield run
    for context in contexts:
        context.close()


@pytest.mark.parametrize('path', ['/help', '/settings#general', '/settings#dns', '/', '/inventory'])
def test_brand_blue_text_is_readable_in_dark_mode(open_page, path):
    page = open_page(path, 'dark')
    # The brand blue itself (hsl(216 76% 43%), as Chromium reports it), and
    # whatever text-primary resolves to in dark mode.
    for colour in (BRAND_BLUE, page.evaluate("() => __contrast.colourOf('text-primary')")):
        low = page.evaluate(f"() => __contrast.below({colour!r}, {AA})")
        assert low == [], f'{path}, dark: text in {colour} under {AA}:1: {low[:8]}'


@pytest.mark.parametrize('path', ['/inventory', '/inventory/crypto-report', '/settings#acme', '/settings#dns',
                                  '/settings#oidc', '/'])
def test_muted_text_is_readable_in_light_mode(open_page, path):
    page = open_page(path, 'light')
    colour = page.evaluate("() => __contrast.colourOf('text-muted')")
    low = page.evaluate(f"() => __contrast.below({colour!r}, {AA})")
    assert low == [], f'{path}, light: muted text ({colour}) under {AA}:1: {low[:8]}'


CHIPS = [('/', [f'[data-status-chip="{k}"]' for k in ('all', 'valid', 'expiring', 'expired')]),
         ('/#client', [f'[data-cc-status-chip="{k}"]' for k in ('', 'active', 'revoked')])]


@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_every_status_chip_is_readable_when_pressed(open_page, scheme):
    low = []
    for path, selectors in CHIPS:
        page = open_page(path, scheme)
        for selector in selectors:
            page.locator(selector).click()
            page.wait_for_function(
                f"() => document.querySelector('{selector}').getAttribute('aria-pressed') === 'true'")
            for target in (selector, f'{selector} span'):
                r = page.evaluate(f"() => __contrast.ratio(document.querySelector('{target}'))")
                if r < AA:
                    low.append((target, round(r, 2)))
    assert low == [], f'{scheme}: pressed chips under {AA}:1: {low}'


EVERY_VIEW = ['/', '/#client', '/#acme', '/inventory', '/inventory/crypto-report', '/activity', '/notifications',
              '/help'] + [f'/settings#{tab}' for tab in (
                  'general', 'dns', 'ca', 'storage', 'deploy', 'probe', 'acme', 'users', 'apikeys', 'oidc',
                  'notifications', 'backup')]


@pytest.mark.parametrize('scheme', ['light', 'dark'])
@pytest.mark.parametrize('path', EVERY_VIEW)
def test_every_text_and_icon_control_reaches_wcag_contrast(open_page, path, scheme):
    """On every view, every visible text reaches 4.5:1 (3:1 when large) and every
    control that is only an icon 3:1. Hard-coded text-gray-400 was 2.5:1 on white
    in about fifty places (the activity list, help, settings hints, the breadcrumb
    Home, the shortcuts button on every page, the client row actions), white on
    yellow-600 buttons 2.9:1, and muted text on dark inputs and hovered rows 4.0:1."""
    page = open_page(path, scheme)
    text = page.evaluate('() => __contrast.texts()')
    icons = page.evaluate('() => __contrast.controls()')
    assert text == [], f'{path}, {scheme}: text under AA: {text[:8]}'
    assert icons == [], f'{path}, {scheme}: icon-only controls under 3:1: {icons[:8]}'
