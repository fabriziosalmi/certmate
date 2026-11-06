"""Every form control and every button in the templates has a name a screen reader can say.

A label that sits above a field but is not bound to it (no ``for``, no wrapping)
is text on the page and nothing more: a screen reader announces the field as
"edit text", and clicking the label does not focus it. A button that holds only
an icon is announced as "button". lgit found one of each in the settings; a scan
of every template found 69, in nine files, so the rule is checked here for all of
them rather than fixed where it was noticed.

A control has a name when it is inside a ``<label>``, is the target of a
``<label for>``, or carries ``aria-label``, ``aria-labelledby`` or ``title``
(Alpine's ``:aria-label`` and ``:title`` included). A button also has one when it
holds text, when Alpine fills its text (``x-text``, on it or on an element in
it), or when it holds an ``sr-only`` span. Controls repeated by ``x-for`` cannot share an id, so they take ``aria-label``.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

TEMPLATES = Path(__file__).resolve().parent.parent / 'templates'

NAME_ATTRIBUTES = ('aria-label', ':aria-label', 'x-bind:aria-label', 'aria-labelledby', 'title', ':title', 'x-bind:title')
UNNAMED_INPUT_TYPES = ('hidden', 'submit', 'button', 'reset', 'image')
VOID = {'input', 'img', 'br', 'hr', 'meta', 'link', 'source', 'area', 'base', 'col', 'embed', 'param', 'track', 'wbr'}
JINJA = re.compile(r'\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\}', re.S)


class _Controls(HTMLParser):
    """Collect the controls and the buttons of one template, and the ids its labels name."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.open = []            # [tag, attributes, has_text, line]
        self.label_targets = set()
        self.controls = []        # (line, tag, attributes, inside_a_label)
        self.buttons = []         # (line, attributes, has_text)

    def _give_text_to_open_buttons(self):
        for element in self.open:
            if element[0] == 'button':
                element[2] = True

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        line = self.getpos()[0]
        if tag == 'label' and attributes.get('for'):
            self.label_targets.add(attributes['for'])
        if tag in ('input', 'select', 'textarea') and attributes.get('type') not in UNNAMED_INPUT_TYPES:
            inside_a_label = any(element[0] == 'label' for element in self.open)
            self.controls.append((line, tag, attributes, inside_a_label))
        if 'x-text' in attributes or 'x-html' in attributes or 'sr-only' in (attributes.get('class') or '').split():
            self._give_text_to_open_buttons()
        if tag not in VOID:
            self.open.append([tag, attributes, False, line])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.open and self.open[-1][0] == tag:
            self.open.pop()

    def handle_data(self, data):
        if data.strip():
            self._give_text_to_open_buttons()

    def handle_endtag(self, tag):
        for index in range(len(self.open) - 1, -1, -1):
            if self.open[index][0] == tag:
                element = self.open[index]
                del self.open[index:]
                if tag == 'button':
                    self.buttons.append((element[3], element[1], element[2]))
                return


def _named(attributes):
    return any(name in attributes for name in NAME_ATTRIBUTES)


def unnamed(source):
    """The controls and buttons in ``source`` that have no accessible name, as (line, description)."""
    # Jinja is blanked out, newlines kept, so the line numbers are the file's.
    parser = _Controls()
    parser.feed(JINJA.sub(lambda match: '\n' * match.group(0).count('\n'), source))
    parser.close()
    found = []
    for line, tag, attributes, inside_a_label in parser.controls:
        if inside_a_label or _named(attributes) or attributes.get('id') in parser.label_targets:
            continue
        found.append((line, f'<{tag}> {attributes.get("x-model") or attributes.get("id") or attributes.get("name") or ""}'))
    for line, attributes, has_text in parser.buttons:
        if not (has_text or _named(attributes) or 'x-text' in attributes or 'x-html' in attributes):
            found.append((line, '<button> with only an icon'))
    return found


def test_every_control_in_the_templates_has_a_name():
    templates = sorted(TEMPLATES.rglob('*.html'))
    assert len(templates) > 20, 'the templates moved: this test has lost its subject'
    missing = [
        f'{path.relative_to(TEMPLATES.parent)}:{line} {what}'
        for path in templates
        for line, what in unnamed(path.read_text())
    ]
    assert not missing, (
        'these have no accessible name; bind the visible label with for= and an id, '
        'or give a repeated or label-less control aria-label:\n' + '\n'.join(missing))


@pytest.mark.parametrize('markup', [
    '<label class="x">Name</label><input type="text" x-model="name">',
    '<button type="button" @click="add()"><i class="fas fa-plus"></i></button>',
    '<select x-model="kind"><option>a</option></select>',
])
def test_the_check_sees_an_unnamed_control(markup):
    assert unnamed(markup), markup


@pytest.mark.parametrize('markup', [
    '<label for="n">Name</label><input id="n" type="text">',
    '<label><input type="checkbox"> Enabled</label>',
    '<input type="text" aria-label="Header name">',
    '<input type="text" :aria-label="\'Header \' + key">',
    '<button type="button" aria-label="Add header"><i class="fas fa-plus"></i></button>',
    '<button type="button"><span x-text="opt"></span></button>',
    '<button type="button" x-text="c.label"></button>',
    '<button type="button"><i class="fas fa-trash"></i><span class="sr-only">Remove</span></button>',
    '<button type="button"><i class="fas fa-play"></i>Test</button>',
    '<input type="hidden" name="csrf">',
])
def test_the_check_accepts_a_named_control(markup):
    assert unnamed(markup) == [], markup
