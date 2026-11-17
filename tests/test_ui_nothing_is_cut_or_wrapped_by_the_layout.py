"""Layout faults the UI audit of 2026-11-17 measured, each held to the fix.

* The create drawer split into two 284 px columns inside its 640 px panel from
  1024 px up (`lg:` reads the viewport, not the panel), so the Domain
  placeholder needed 405 px and got 250, and the SANs one 433 for 258.
* At 390 px the settings section badges wrapped into two-line blobs
  ("Local Authentication" 40 px tall), and the challenge card "HTTP-01" broke
  into "HTTP-" and "01".
* At 1024 px "Your Certificates" sat 4 px from the search box.
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


@pytest.fixture
def at_width(browser_page, ui_session_cookie):
    browser = browser_page.context.browser
    contexts = []

    def run(path, width):
        context = browser.new_context(viewport={'width': width, 'height': 900})
        contexts.append(context)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        page = context.new_page()
        page.goto(f'{BASE_URL}{path}', wait_until='networkidle')
        page.wait_for_timeout(300)
        return page

    yield run
    for context in contexts:
        context.close()


@pytest.mark.parametrize('width', [1024, 1280, 1440])
def test_the_create_form_s_placeholders_are_not_cut(at_width, width):
    page = at_width('/', width)
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.wait_for_timeout(400)
    cut = page.evaluate("""() => ['domain', 'san_entry'].map(id => {
        const el = document.getElementById(id);
        const style = getComputedStyle(el);
        const probe = document.createElement('span');
        probe.style.font = style.font;
        probe.style.whiteSpace = 'pre';
        probe.style.position = 'absolute';
        probe.textContent = el.placeholder;
        document.body.appendChild(probe);
        const needed = probe.getBoundingClientRect().width;
        probe.remove();
        const available = el.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        return [id, Math.round(needed), Math.round(available)];
    }).filter(([, needed, available]) => needed > available)""")
    assert cut == [], f'{width}px: placeholders cut [id, needed, available]: {cut}'


@pytest.mark.parametrize('tab', ['users', 'oidc', 'backup'])
def test_settings_section_badges_stay_on_one_line_on_a_phone(at_width, tab):
    page = at_width(f'/settings#{tab}', 390)
    wrapped = page.evaluate(f"""() => {{
        // Line boxes of the text itself: a badge is a flex item, so it is a block,
        // and a block has one client rect however many lines its text takes.
        const lines = el => {{ const r = document.createRange(); r.selectNodeContents(el);
                               return new Set([...r.getClientRects()].map(b => Math.round(b.top))).size; }};
        const panel = document.getElementById('settings-panel-{tab}');
        return [...panel.querySelectorAll('h3 + span.rounded-full')]
            .filter(el => el.offsetParent && lines(el) !== 1)
            .map(el => [el.innerText.trim(), lines(el)]);
    }}""")
    badges = page.evaluate(f"() => document.querySelectorAll('#settings-panel-{tab} h3 + span.rounded-full').length")
    assert badges, f'{tab}: no section badge found, nothing measured'
    assert wrapped == [], f'{tab} at 390px: badges on more than one line: {wrapped}'


def test_the_challenge_cards_keep_their_names_whole_and_match_on_a_phone(at_width):
    page = at_width('/settings#dns', 390)
    cards = page.evaluate("""() => {
        const lines = el => { const r = document.createRange(); r.selectNodeContents(el);
                              return new Set([...r.getClientRects()].map(b => Math.round(b.top))).size; };
        return [...document.querySelectorAll('input[name="challenge_type"] + div')].map(card => {
            const name = card.querySelector('span');
            return [name.innerText.trim(), lines(name), Math.round(card.getBoundingClientRect().width)];
        });
    }""")
    assert len(cards) == 2, cards
    assert [lines for _, lines, _ in cards] == [1, 1], f'a challenge name broke across lines: {cards}'
    assert cards[0][2] == cards[1][2], f'the two cards differ in width: {cards}'


def test_the_list_title_and_the_search_box_do_not_touch(at_width):
    page = at_width('/', 1024)
    gap = page.evaluate("""() => {
        const title = [...document.querySelectorAll('h3')].find(h => h.innerText.trim() === 'Your Certificates');
        const tools = title.nextElementSibling;
        return tools.getBoundingClientRect().left - title.getBoundingClientRect().right;
    }""")
    assert gap >= 12, f'title and search box {gap}px apart'
