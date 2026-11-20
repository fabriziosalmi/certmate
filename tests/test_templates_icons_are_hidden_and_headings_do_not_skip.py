"""Icons say nothing to a screen reader, and headings do not skip a level (#1511, P63).

The UI draws its icons with Font Awesome: an empty ``<i class="fas fa-...">``
whose glyph is a character in the Unicode private use area. An icon without
``aria-hidden`` put that character into the accessible name of the heading,
button or field it sat in (" Save Settings", " Create New Certificate"),
and screen readers voiced it, or a "private use" placeholder, before every
label. Of the 601 icons in the templates and scripts on main (69b9d67), 163
had ``aria-hidden``. And the headings skipped levels: the dashboard went
from its h1 to h3, General from h1 to h3 and h4, Storage from h3 to h5.

The rules, checked with html.parser on every template (with its inline
scripts) and on the HTML the scripts in static/js build:

* An icon (an ``<i>`` element) carries ``aria-hidden="true"``: it is
  decorative, its meaning is in the text or the ``aria-label`` beside it.
  The one exception is an icon whose meaning is nowhere else, which is then
  the accessible name of what it shows: it says so with ``role="img"`` and
  an ``aria-label`` (the two info icons of the private CA form, whose
  tooltip was their only text).
  An icon that was the only label of a control leaves the name to the
  control: ``aria-label``, ``title`` or ``sr-only`` text on it (checked for
  buttons by tests/test_every_form_control_has_an_accessible_name.py, and for
  links here).
* Inside one template, a heading is at most one level below the heading
  before it. A template is read in source order; across templates (a page,
  the partials it includes, the base it extends) and in what the scripts
  build, the order is the page's, so the browser checks it:
  tests/test_ui_headings_never_skip_a_level.py.

A script builds its markup from string pieces, so html.parser can lose its
place in a script (``i<n`` reads as a tag). The check counts the ``<i``
tags it parsed against the ``<i `` and ``<i>`` texts in the file and fails
when they differ, rather than passing on what it did not see.
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
HEADINGS = {'h1': 1, 'h2': 2, 'h3': 3, 'h4': 4, 'h5': 5, 'h6': 6}
NAME_ATTRIBUTES = ('aria-label', ':aria-label', 'x-bind:aria-label', 'aria-labelledby', 'title', ':title',
                   'x-bind:title')


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.icons = []      # (line, attributes)
        self.headings = []   # (line, level)
        self.links = []      # (line, attributes, has_name_text)
        self.open = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        line = self.getpos()[0]
        if tag == 'i':
            self.icons.append((line, attributes))
        if tag in HEADINGS:
            self.headings.append((line, HEADINGS[tag]))
        if ('x-text' in attributes or 'x-html' in attributes or 'sr-only' in (attributes.get('class') or '').split()
                or (tag == 'img' and (attributes.get('alt') or '').strip())):
            self._name_open_links()
        if tag == 'a':
            self.open.append([line, attributes, False])

    def _name_open_links(self):
        for link in self.open:
            link[2] = True

    def handle_data(self, data):
        if self.cdata_elem == 'script':
            # A page's own script builds markup too: its icons and links are
            # read the same way. Its headings are fragments placed elsewhere,
            # so they are not in this file's order (the browser test has them).
            inner = _Markup()
            inner.feed(data)
            inner.close()
            offset = self.getpos()[0] - 1
            self.icons += [(line + offset, attributes) for line, attributes in inner.icons]
            self.links += [(line + offset, attributes, named) for line, attributes, named in inner.links]
            return
        if data.strip():
            self._name_open_links()

    def handle_endtag(self, tag):
        if tag == 'a' and self.open:
            self.links.append(tuple(self.open.pop()))


def _parse(source):
    parser = _Markup()
    # Jinja is blanked out, newlines kept, so the line numbers are the file's;
    # an expression ({{ ... }}) prints something, so it stays as a letter.
    parser.feed(JINJA.sub(lambda match: ('x' if match.group(0).startswith('{{') else '')
                          + '\n' * match.group(0).count('\n'), source))
    parser.close()
    return parser


def _icon_is_named(attributes):
    return attributes.get('role') == 'img' and bool((attributes.get('aria-label') or '').strip())


def loud_icons(source):
    """The icons in ``source`` a screen reader would read, as line numbers."""
    return [line for line, attributes in _parse(source).icons
            if attributes.get('aria-hidden') != 'true' and not _icon_is_named(attributes)]


def skipped_levels(source):
    """Each heading more than one level below the one before it, as (line, from, to)."""
    found, before = [], None
    for line, level in _parse(source).headings:
        if before is not None and level > before + 1:
            found.append((line, before, level))
        before = level
    return found


def unnamed_links(source):
    """Links whose only content is hidden icons and that carry no name of their own."""
    return [line for line, attributes, has_text in _parse(source).links
            if not has_text and not any(name in attributes for name in NAME_ATTRIBUTES)]


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
        written = source.count('<i ') + source.count('<i>')
        parsed = len(_parse(source).icons)
        if parsed != written:
            lost.append(f'{path.relative_to(ROOT)}: {written} written, {parsed} parsed')
        loud += [f'{path.relative_to(ROOT)}:{line}' for line in loud_icons(source)]
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


def test_a_link_that_is_only_an_icon_has_a_name():
    bare = [f'{path.relative_to(ROOT)}:{line}' for path in _templates() + _scripts()
            for line in unnamed_links(path.read_text())]
    assert not bare, f'links with only an icon and no aria-label or title: {bare}'


@pytest.mark.parametrize('markup, loud', [
    ('<button><i class="fas fa-save mr-2"></i>Save</button>', [1]),
    ('<button><i class="fas fa-save mr-2" aria-hidden="true"></i>Save</button>', []),
    ('<i class="fas fa-check" aria-hidden="false"></i>', [1]),
    ('<i class="fas fa-check" role="img" aria-label="Valid"></i>', []),
    ('<i class="fas fa-check" role="img"></i>', [1]),
    ("html += '<i class=\"fas fa-x\"></i>' + label;", [1]),
])
def test_the_icon_check_tells_a_loud_icon_from_a_hidden_one(markup, loud):
    assert loud_icons(markup) == loud


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
    ('<a href="/"><i class="fas fa-home" aria-hidden="true"></i></a>', [1]),
    ('<a href="/" aria-label="Home"><i class="fas fa-home" aria-hidden="true"></i></a>', []),
    ('<a href="/"><i class="fas fa-home" aria-hidden="true"></i> Home</a>', []),
    ('<a href="/"><i class="fas fa-home" aria-hidden="true"></i><span class="sr-only">Home</span></a>', []),
])
def test_the_link_check_finds_a_link_with_no_name(markup, bare):
    assert unnamed_links(markup) == bare
