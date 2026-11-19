"""Every username field takes what is typed: no capital letter, correction or
spelling mark from a phone keyboard (UX perception audit 2026-11-18, P31).

Usernames are case-sensitive, and stay so: a phone that typed "Admin" for
"admin" got "Invalid credentials" with nothing saying why. The fields that
name a user (login, first-run setup, Settings > Users) now say
autocapitalize="none", autocorrect="off" and spellcheck="false".

The setup page is only served before the first admin exists, so this reads
the templates; tests/test_ui_the_login_page_announces_what_went_wrong.py
checks the login and Users fields in a browser.
"""
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

TEMPLATES = Path(__file__).resolve().parent.parent / 'templates'
FIELDS = [
    ('login.html', 'username'),
    ('setup.html', 'username'),
    ('partials/settings_users.html', 'newUserUsername'),
]


class _Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.by_id = {}

    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            attrs = dict(attrs)
            if attrs.get('id'):
                self.by_id[attrs['id']] = attrs


@pytest.mark.parametrize('template,field_id', FIELDS)
def test_a_username_field_is_not_capitalised_corrected_or_spellchecked(template, field_id):
    parser = _Inputs()
    parser.feed((TEMPLATES / template).read_text(encoding='utf-8'))
    attrs = parser.by_id.get(field_id)
    assert attrs is not None, f'{template} has no input#{field_id}'
    assert attrs.get('autocapitalize') == 'none', attrs
    assert attrs.get('autocorrect') == 'off', attrs
    assert attrs.get('spellcheck') == 'false', attrs
