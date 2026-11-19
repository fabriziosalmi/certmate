"""A filled button is drawn by the button components, a status badge by one helper (#1511, B18: P42, P68).

The browser test (tests/test_ui_one_button_one_badge_one_icon_colour.py) sees
what a page shows when it loads and in the dialogs it opens. A button that only
appears in a state (a key just created, a failed load, an inline editor) is
held here, in the source: a <button> or <a> that paints itself white on a colour
of its own (`text-white` with a `bg-*`) was how "Save Rate Limits" came to be
amber and "Test Connection" blue-600. The component classes in
static/css/input.css (.btn with .btn-primary, .btn-danger, .btn-warning,
.btn-secondary and .btn-sm) carry the colour, the height and the corners.

Out of scope, and so not scanned: the sign-in and first-admin pages
(templates/login.html, templates/setup.html), which are not app pages.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parent.parent
NOT_APP_PAGES = {'login.html', 'setup.html'}
TEMPLATES = sorted(p for p in (REPO / 'templates').rglob('*.html') if p.name not in NOT_APP_PAGES)
SCRIPTS = sorted(p for p in (REPO / 'static' / 'js').glob('*.js') if not p.name.endswith('.min.js')
                 and p.name not in ('redoc.standalone.js',))
SELF_PAINTED = re.compile(r'(?<![\w:-])text-white(?![\w-])')
OWN_FILL = re.compile(r'(?<![\w:/-])(bg-(?:primary|secondary|[a-z]+-[5-9]00)|btn-cta)(?![\w/-])')


def _self_painted(classes):
    """The classes paint a filled button of their own: white text on a fill, or the old CTA."""
    return bool(OWN_FILL.search(classes)) and (bool(SELF_PAINTED.search(classes)) or 'btn-cta' in classes)


class _Buttons(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found = []

    def handle_starttag(self, tag, attrs):
        # The settings debug console's floating toggle is a developer control,
        # hidden unless debugging is on, not an action of the product.
        if tag in ('button', 'a') and 'data-debug-control' not in dict(attrs):
            classes = dict(attrs).get('class') or ''
            if _self_painted(classes):
                self.found.append((self.getpos()[0], classes))


def _template_buttons(path):
    parser = _Buttons()
    parser.feed(path.read_text(encoding='utf-8'))
    return parser.found


# The opening tag of a <button> or <a> in a script's HTML strings, up to its
# first `>` (string concatenation in between is allowed), and the class in it.
TAG = re.compile(r'<(?:button|a)\b(?P<tag>[^>]{0,600}?)>', re.S)
CLASS = re.compile(r'class="([^"]*)"')
# A button built with document.createElement and given its classes in script.
CREATED = re.compile(r"(\w+)\s*=\s*document\.createElement\('(?:button|a)'\)")
# The class strings a script keeps for its buttons (certmate.js BTN_PRIMARY...).
CONSTANT = re.compile(r"var (BTN_\w+)\s*=\s*([^;]+);")


def _script_buttons(path):
    text = path.read_text(encoding='utf-8')
    found = []
    for m in TAG.finditer(text):
        for classes in CLASS.findall(m.group('tag')):
            if _self_painted(classes):
                found.append((text.count('\n', 0, m.start()) + 1, classes))
    for m in CONSTANT.finditer(text):
        if _self_painted(m.group(2)):
            found.append((text.count('\n', 0, m.start()) + 1, m.group(2).strip()))
    for name in set(CREATED.findall(text)):
        for m in re.finditer(re.escape(name) + r"\.className\s*=\s*([^;]+);", text):
            if _self_painted(m.group(1)):
                found.append((text.count('\n', 0, m.start()) + 1, m.group(1).strip()))
    return found


def test_the_scan_finds_a_self_painted_button(tmp_path):
    """CONTROL: the two shapes the scan reads, in a template and in a script."""
    parser = _Buttons()
    parser.feed('<div><button class="px-4 py-2 bg-yellow-700 text-white rounded-md">Save</button>'
                '<a class="btn btn-primary">Go</a><span class="bg-primary text-white">3</span></div>')
    assert [c for _, c in parser.found] == ['px-4 py-2 bg-yellow-700 text-white rounded-md']
    assert _self_painted('btn-cta px-4') and not _self_painted('btn btn-primary btn-sm')
    sample = tmp_path / 'sample.js'
    sample.write_text("x = '<button type=\"button\"' + f() + 'class=\"bg-blue-600 text-white\">A</button>';\n"
                      "var b = document.createElement('button');\nb.className = 'bg-green-600 text-white';\n",
                      encoding='utf-8')
    assert len(_script_buttons(sample)) == 2


def test_no_app_button_paints_its_own_fill():
    found = []
    for path in TEMPLATES:
        found += [(str(path.relative_to(REPO)), line, c) for line, c in _template_buttons(path)]
    for path in SCRIPTS:
        found += [(str(path.relative_to(REPO)), line, c) for line, c in _script_buttons(path)]
    assert found == [], '\n'.join(f'{p}:{line}: {c}' for p, line, c in found)


def test_amber_is_only_the_risky_button_variant():
    """bg-yellow-700 white text was a plain save; amber now exists once, as .btn-warning."""
    css = (REPO / 'static' / 'css' / 'input.css').read_text(encoding='utf-8')
    assert re.search(r'\.btn-warning\s*\{[^}]*bg-yellow-700', css), 'no .btn-warning in input.css'
    users = []
    for path in TEMPLATES + SCRIPTS:
        for i, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if re.search(r'(?<![\w-])btn-warning(?![\w-])', line):
                users.append((path.name, i))
    # Migrate Certificates and the Start Migration of its dialog: copying every
    # certificate into another backend, over what is there.
    assert sorted(n for n, _ in users) == ['settings.js', 'settings_storage.html'], users


def _helper_users(path):
    return len(re.findall(r'CertMate\.statusBadge\(', (REPO / 'static' / 'js' / path).read_text(encoding='utf-8')))


def test_the_three_status_lists_draw_their_badge_with_one_helper():
    certmate = (REPO / 'static' / 'js' / 'certmate.js').read_text(encoding='utf-8')
    assert 'CM.statusBadge = function' in certmate
    assert _helper_users('dashboard.js') >= 1
    assert _helper_users('client-certs.js') >= 1
    assert _helper_users('inventory.js') >= 1
    # The client status was a square chip, the shape of the usage tag beside it.
    client = (REPO / 'static' / 'js' / 'client-certs.js').read_text(encoding='utf-8')
    assert 'rounded text-xs font-medium">Active' not in client


# A Cancel or Close beside a 36 px primary was its old 28 to 32 px self, with
# other corners: the row read as two buttons from two systems.
BESIDE_A_PRIMARY = [
    ('static/js/dashboard.js', "CertMate.does('click', 'closeReplaceCertificate', [])"),
    ('templates/partials/settings_probe.html', '@click="cancelEdit()" data-discards'),
    ('static/js/report-issue.js', 'data-action="close"'),
]


@pytest.mark.parametrize('path, marker', BESIDE_A_PRIMARY)
def test_the_cancel_beside_a_primary_is_a_secondary_button(path, marker):
    text = (REPO / path).read_text(encoding='utf-8')
    at = text.index(marker)
    tag = text[at:at + 400]
    classes = CLASS.search(tag).group(1)
    assert classes.split()[:2] == ['btn', 'btn-secondary'], (path, classes)
