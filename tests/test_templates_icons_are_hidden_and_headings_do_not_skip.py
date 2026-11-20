"""Icons say nothing to a screen reader, and headings do not skip a level (#1511, P63).

The UI draws its icons with Font Awesome: an empty ``<i class="fas fa-...">``
whose glyph is a character in the Unicode private use area. An icon without
``aria-hidden`` put that character into the accessible name of the heading,
button or field it sat in (" Save Settings", " Create New Certificate"),
and screen readers voiced it, or a "private use" placeholder, before every
label. Of the 600 icons in the templates and scripts on main (69b9d67), 163
had ``aria-hidden``. And the headings skipped levels: the dashboard went
from its h1 to h3, General from h1 to h3 and h4, Storage from h3 to h5.

The rules, checked with html.parser on every template (with its inline
scripts) and on the HTML the scripts in static/js build:

* An ``<i>`` with a class (``class``, ``:class`` or ``x-bind:class``) is an
  icon. It carries ``aria-hidden="true"``, or ``role="img"`` with a
  non-empty ``aria-label`` when it is meant to be named itself. No icon in
  the tree is named today: the info icons whose tooltip was their only text
  are hidden, and the field they explain points at the same sentence with
  ``aria-describedby``.
* An ``<i>`` with no class is an icon too unless it holds text (an italic
  word, written or computed in a script): an empty one carries
  ``aria-hidden="true"``.
* A button or a link has text written inside it, or a name of its own
  (``aria-label``, ``aria-labelledby`` or ``title``, Alpine's bound forms
  included). Written text is a text node in a template; ``x-text``,
  ``x-html``, ``sr-only`` text or an image with an ``alt`` inside it count
  too. In a script, it is text inside a string literal: an expression alone
  (a variable, a call, ``${...}``) may be empty, so a control whose only
  content is an expression fails, unless that expression in that function
  is listed in EXPRESSIONS_THAT_NAME with the reason it always gives text
  (each entry must excuse exactly one control). The quotes,
  plus signs and whitespace between string pieces are neither.
* Inside one template, a heading is at most one level below the heading
  before it. A template is read in source order; across templates (a page,
  the partials it includes, the base it extends) and in what the scripts
  build, the order is the page's, so the browser checks it:
  tests/test_ui_headings_never_skip_a_level.py.

A script builds its markup from string pieces, so html.parser can lose its
place in a script (``i<n`` reads as a tag, and ``'<i\\nclass=...'`` as a tag
whose name is not ``i``). The check counts the ``<i`` tags it parsed against
the ``<i`` written in the file followed by whitespace, ``>``, ``/`` or a
JavaScript escape of whitespace, and fails when they differ, rather than
passing on what it did not see. In a script, what is inside a string
literal is told from what is outside by counting quotes: a quote inside a
literal of the other kind ("don't" in a double-quoted string) would mislead
it.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / 'templates'
SCRIPTS = ROOT / 'static' / 'js'
# Third-party bundles, not this project's markup.
VENDORED = {'alpine.min.js', 'redoc.standalone.js'}
JINJA = re.compile(r'\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\}', re.S)
# An <i> tag as written: whitespace, '>' or '/' after it, or a JS escape
# (\n, \t...) that a string turns into whitespace.
WRITTEN_I = re.compile(r'<i(?=[\s>/]|\\[ntrfv])')
HEADINGS = {'h1': 1, 'h2': 2, 'h3': 3, 'h4': 4, 'h5': 5, 'h6': 6}
CLASS_ATTRIBUTES = ('class', ':class', 'x-bind:class')
NAME_ATTRIBUTES = ('aria-label', ':aria-label', 'x-bind:aria-label', 'aria-labelledby', ':aria-labelledby',
                   'title', ':title', 'x-bind:title')
CONTROLS = ('a', 'button')


# In a script, the text between two string pieces ("' +\n '") is not text
# on the page: quotes, plus signs, escapes and whitespace say nothing.
JOINS = re.compile(r"\\[ntr]|[\s'\"`+]")
QUOTE = re.compile(r"(?<!\\)['\"`]")
INTERPOLATION = re.compile(r'\$\{[^}]*\}')
ESCAPE = re.compile(r'\\[ntrfv]')


def _literal_text(data):
    """In a script, the run of source between two tags starts inside the
    string that holds the tags: what is inside quotes there is text written
    into the page, what is outside is an expression. The literal part, with
    ${...} and whitespace escapes taken out."""
    literal = ''.join(QUOTE.split(data)[0::2])
    return ESCAPE.sub('', INTERPOLATION.sub('', literal)).strip()


class _Markup(HTMLParser):
    def __init__(self, script=False):
        super().__init__(convert_charrefs=True)
        self.script = script
        self.tags_i = 0
        self.icons = []      # (line, attributes): an <i> with a class
        self.bare = []       # line of an <i> with no class, no text and no aria-hidden
        self.headings = []   # (line, level)
        self.controls = []   # (line, tag, attributes, has_name_inside, expressions)
        self.open = []       # [line, tag, attributes, has_name_inside, expressions]
        self.open_i = []     # [line, attributes, has_content]

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        line = self.getpos()[0]
        if tag == 'i':
            self.tags_i += 1
            if any(name in attributes for name in CLASS_ATTRIBUTES):
                self.icons.append((line, attributes))
            else:
                self.open_i.append([line, attributes, False])
        if tag in HEADINGS:
            self.headings.append((line, HEADINGS[tag]))
        if tag in CONTROLS:
            self.open.append([line, tag, attributes, False, ''])
        if ('x-text' in attributes or 'x-html' in attributes or 'sr-only' in (attributes.get('class') or '').split()
                or (tag == 'img' and (attributes.get('alt') or '').strip())):
            self._name_open_controls()

    def _name_open_controls(self):
        for control in self.open:
            control[3] = True

    def handle_data(self, data):
        if self.cdata_elem == 'script':
            # A page's own script builds markup too: its icons and controls are
            # read the same way. Its headings are fragments placed elsewhere,
            # so they are not in this file's order (the browser test has them).
            inner = _Markup(script=True)
            inner.feed(data)
            inner.close()
            offset = self.getpos()[0] - 1
            self.tags_i += inner.tags_i
            self.icons += [(line + offset, attributes) for line, attributes in inner.icons]
            self.bare += [line + offset for line in inner.bare]
            self.controls += [(line + offset, *rest) for line, *rest in inner.controls]
            return
        # An italic <i> holds text, written or computed.
        if JOINS.sub('', data) if self.script else data.strip():
            for element in self.open_i:
                element[2] = True
        # A control's name is text written into the page: in a script, an
        # expression alone (a variable, a call) may be empty, so it is not one.
        if _literal_text(data) if self.script else data.strip():
            self._name_open_controls()
        if self.script:
            expression = ' '.join(''.join(QUOTE.split(data)[1::2]).replace('+', ' ').split())
            for control in self.open:
                control[4] = (control[4] + ' ' + expression).strip()

    def _close_i(self, element):
        line, attributes, has_content = element
        if not has_content and attributes.get('aria-hidden') != 'true':
            self.bare.append(line)

    def handle_endtag(self, tag):
        if tag == 'i' and self.open_i:
            self._close_i(self.open_i.pop())
        if tag not in CONTROLS:
            return
        for index in range(len(self.open) - 1, -1, -1):
            if self.open[index][1] == tag:
                self.controls.append(tuple(self.open.pop(index)))
                return

    def close(self):
        super().close()
        while self.open_i:
            self._close_i(self.open_i.pop())


def _parse(source, script=False):
    parser = _Markup(script)
    # Jinja is blanked out, newlines kept, so the line numbers are the file's;
    # an expression ({{ ... }}) prints something, so it stays as a letter.
    parser.feed(JINJA.sub(lambda match: ('x' if match.group(0).startswith('{{') else '')
                          + '\n' * match.group(0).count('\n'), source))
    parser.close()
    return parser


def _icon_is_named(attributes):
    return attributes.get('role') == 'img' and bool((attributes.get('aria-label') or '').strip())


def loud_icons(source, script=False):
    """The icons in ``source`` a screen reader would read, and the empty <i> with no class and no
    aria-hidden, as line numbers."""
    parsed = _parse(source, script)
    return sorted([line for line, attributes in parsed.icons
                   if attributes.get('aria-hidden') != 'true' and not _icon_is_named(attributes)] + parsed.bare)


def skipped_levels(source):
    """Each heading more than one level below the one before it, as (line, from, to)."""
    found, before = [], None
    for line, level in _parse(source).headings:
        if before is not None and level > before + 1:
            found.append((line, before, level))
        before = level
    return found


FUNCTION = re.compile(r'function\s+(\w+)\s*\(|(\w+)\s*[:=]\s*function\s*\(')


def _enclosing_function(lines, line):
    """The name of the nearest function declared on or above ``line`` (1-based), or ''."""
    for index in range(line - 1, -1, -1):
        match = FUNCTION.search(lines[index])
        if match:
            return match.group(1) or match.group(2)
    return ''


def unnamed_controls(source, script=False, allowed=(), used=None):
    """Buttons and links with no text written inside them (only hidden icons, or in a script only an
    expression) and no name of their own, as (line, tag). ``allowed`` holds the (function, expression)
    pairs known to give text; each one excused is counted in ``used``."""
    lines = source.split('\n')
    found = []
    for line, tag, attributes, has_name, expressions in _parse(source, script).controls:
        if has_name or any(name in attributes for name in NAME_ATTRIBUTES):
            continue
        site = (_enclosing_function(lines, line), expressions)
        if expressions and site in allowed:
            if used is not None:
                used[site] = used.get(site, 0) + 1
            continue
        found.append((line, tag))
    return found


def lost_tags(source):
    """(written, parsed) when html.parser did not see every <i> tag the source holds, else None."""
    written, parsed = len(WRITTEN_I.findall(source)), _parse(source).tags_i
    return (written, parsed) if written != parsed else None


# Controls a script builds whose only text is an expression, each checked to
# give text: (file) -> {the expression: why it is never empty}.
EXPRESSIONS_THAT_NAME = {
    'static/js/certmate.js': {
        ('toast', 'CM.escapeHtml(link.text || link.href)'):
            'a toast link is only built when link.href is a non-empty string, and its text falls back to that href',
    },
    'static/js/dashboard.js': {
        ('_menuItem', 'label'): 'every caller passes a written label ("Force renew", "Delete certificate"...)',
        ('settingsLink', 'label'): 'every caller passes a written label ("Settings, CA", "Settings, DNS")',
        ('updateCAProviderInfo', 'escapeHtml(reason.slice(cut 2))'):
            'the text after the last ": " of caNotUsableReason(), which is shown only when it is not empty and '
            'then ends ": add it in Settings > CA" (or "them")',
    },
    'static/js/setup-wizard.js': {
        ('challengeButton', 'label detail'): 'both callers pass a written label and detail ("DNS-01", "HTTP-01")',
    },
}


def _templates():
    found = sorted(TEMPLATES.rglob('*.html'))
    assert len(found) > 20, 'the templates moved: this test has lost its subject'
    return found


def _scripts():
    found = sorted(p for p in SCRIPTS.glob('*.js') if p.name not in VENDORED)
    assert len(found) > 15, 'the scripts moved: this test has lost its subject'
    return found


def _loud_and_lost(paths):
    loud, lost = [], []
    for path in paths:
        source = path.read_text()
        counts = lost_tags(source)
        if counts:
            lost.append(f'{path.relative_to(ROOT)}: {counts[0]} written, {counts[1]} parsed')
        loud += [f'{path.relative_to(ROOT)}:{line}' for line in loud_icons(source, path.suffix == '.js')]
    return loud, lost


def test_every_icon_in_the_templates_is_hidden_from_screen_readers():
    loud, lost = _loud_and_lost(_templates())
    assert not lost, f'the parser lost its place, so these files were not fully checked: {lost}'
    assert not loud, (f'{len(loud)} icons without aria-hidden="true" (or role="img" and an aria-label, for an '
                      f'icon that is the name): {loud}')


def test_every_icon_the_scripts_build_is_hidden_from_screen_readers():
    loud, lost = _loud_and_lost(_scripts())
    assert not lost, f'the parser lost its place, so these files were not fully checked: {lost}'
    assert not loud, f'{len(loud)} icons without aria-hidden="true" in the scripts: {loud}'


def test_no_template_skips_a_heading_level():
    skips = [f'{path.relative_to(ROOT)}:{line} h{before} to h{level}'
             for path in _templates() for line, before, level in skipped_levels(path.read_text())]
    assert not skips, f'headings more than one level below the one before them: {skips}'


def test_a_button_or_link_that_is_only_an_icon_has_a_name():
    bare, used = [], {}
    for path in _templates() + _scripts():
        relative = str(path.relative_to(ROOT))
        allowed = EXPRESSIONS_THAT_NAME.get(relative, {})
        counts = {}
        bare += [f'{relative}:{line} <{tag}>' for line, tag in unnamed_controls(
            path.read_text(), script=path.suffix == '.js', allowed=allowed, used=counts)]
        used.update({(relative, *site): count for site, count in counts.items()})
    assert not bare, (f'buttons and links with no written text inside (only hidden icons, or an expression) '
                      f'and no aria-label, aria-labelledby or title: {bare}')
    # Each excused expression is one place: a second copy of it is not excused.
    listed = {(relative, *site) for relative, sites in EXPRESSIONS_THAT_NAME.items() for site in sites}
    wrong = {site: used.get(site, 0) for site in listed if used.get(site, 0) != 1}
    assert not wrong, f'allowed expressions that do not match exactly one control (site: count): {wrong}'


@pytest.mark.parametrize('markup, loud', [
    ('<button><i class="fas fa-save mr-2"></i>Save</button>', [1]),
    ('<button><i class="fas fa-save mr-2" aria-hidden="true"></i>Save</button>', []),
    ('<i class="fas fa-check" aria-hidden="false"></i>', [1]),
    ('<i class="fas fa-check" role="img" aria-label="Valid"></i>', []),
    ('<i class="fas fa-check" role="img"></i>', [1]),
    ('<i :class="open ? \'fa-chevron-up\' : \'fa-chevron-down\'"></i>', [1]),
    ("html += '<i class=\"fas fa-x\"></i>' + label;", [1]),
    ('// the leading glyph (direct child <i>)', []),
])
def test_the_icon_check_tells_a_loud_icon_from_a_hidden_one(markup, loud):
    assert loud_icons(markup) == loud


@pytest.mark.parametrize('markup, lost', [
    ('<i class="fas fa-x" aria-hidden="true"></i>', None),
    ('<i\n class="fas fa-x" aria-hidden="true"></i>', None),
    ("'<i\\nclass=\"fas fa-x\"></i>'", (1, 0)),
    ("for (i = 0; i<n && x; i++) { html += '<i class=\"fas\"></i>'; }", (1, 0)),
])
def test_the_count_check_sees_a_tag_the_parser_misread(markup, lost):
    assert lost_tags(markup) == lost


@pytest.mark.parametrize('markup, skips', [
    ('<h2>Card</h2><h3>Section</h3><h4>Part</h4><h2>Next card</h2>', []),
    ('<h3>Title</h3><h4>Section</h4>', []),
    ('<h1>Page</h1><h3>Card</h3>', [(1, 1, 3)]),
    ('<h2>Card</h2>\n<h5>Part</h5>', [(2, 2, 5)]),
    ('{% if a %}<h2>A</h2>{% else %}<h2>B</h2>{% endif %}<h3>Section</h3>', []),
])
def test_the_heading_check_finds_a_skip(markup, skips):
    assert skipped_levels(markup) == skips


@pytest.mark.parametrize('markup, bare', [
    ('<a href="/"><i class="fas fa-home" aria-hidden="true"></i></a>', [(1, 'a')]),
    ('<a href="/" aria-label="Home"><i class="fas fa-home" aria-hidden="true"></i></a>', []),
    ('<a href="/"><i class="fas fa-home" aria-hidden="true"></i> Home</a>', []),
    ('<a href="/"><i class="fas fa-home" aria-hidden="true"></i><span class="sr-only">Home</span></a>', []),
    ("'<button type=\"button\" id=\"x\"><i aria-hidden=\"true\" class=\"fas fa-times\"></i></button>'",
     [(1, 'button')]),
    ('<button type="button" :title="label"><i aria-hidden="true" class="fas fa-times"></i></button>', []),
    ('<button type="button"><span x-text="label"></span></button>', []),
])
def test_the_name_check_finds_a_control_with_no_name(markup, bare):
    assert unnamed_controls(markup) == bare


@pytest.mark.parametrize('markup, bare', [
    ("'<button type=\"button\" id=\"x\">' +\n    '<i aria-hidden=\"true\" class=\"fas fa-times\"></i>' +\n    '</button>'",
     [(1, 'button')]),
    ("'<button type=\"button\">' + label + '</button>'", [(1, 'button')]),
    ("'<a href=\"#\">' + CM.escapeHtml(name) + '</a>'", [(1, 'a')]),
    ("'<button type=\"button\">Save ' + count + '</button>'", []),
    ("`<button type=\"button\">${label}</button>`", [(1, 'button')]),
    ("`<button type=\"button\">Open ${label}</button>`", []),
])
def test_in_a_script_only_written_text_is_a_name(markup, bare):
    assert unnamed_controls(markup, script=True) == bare


@pytest.mark.parametrize('markup, script, loud', [
    ('<i></i>', False, [1]),
    ('<i id="glyph"></i>', False, [1]),
    ('<i id="glyph" aria-hidden="true"></i>', False, []),
    ('<p>An <i>italic</i> word</p>', False, []),
    ("'<i id=\"glyph\">' + '</i>'", True, [1]),
    ("'<i>' + word + '</i>'", True, []),
    ('// Only the leading glyph (direct child <i>) — never the nested', True, []),
])
def test_an_i_with_no_class_is_hidden_unless_it_holds_text(markup, script, loud):
    assert loud_icons(markup, script) == loud
