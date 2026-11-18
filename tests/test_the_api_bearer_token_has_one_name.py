"""The full-admin token has one name, and Settings > General says what it can do.

Found by the UX perception audit of 2026-11-18 (P59). The token set by
API_BEARER_TOKEN was "API Bearer Token" on General, "the legacy API token" on
API Keys, "an API bearer token" on SSO and "the legacy global bearer token" in
docs/api.md. General described it only as "Token used for API authentication",
so nothing next to the field said it opens everything, or how to change it
(P04: it cannot be changed from the page).
"""
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
PARTIALS = REPO / 'templates' / 'partials'
NAME = 'API Bearer Token'
OTHER_NAMES = ('legacy API token', 'API bearer token', 'global bearer token',
               'legacy bearer token', 'legacy token')


class _Field(HTMLParser):
    """Text and links of the block that holds the token field: the div whose
    label is the one for #api_bearer_token."""

    def __init__(self):
        super().__init__()
        self.depth = 0
        self.inside = 0
        self.text = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'div':
            self.depth += 1
        if tag == 'label' and attrs.get('for') == 'api_bearer_token' and not self.inside:
            self.inside = self.depth
        if self.inside and tag == 'a':
            self.links.append(attrs.get('href'))

    def handle_endtag(self, tag):
        if tag == 'div':
            if self.inside == self.depth:
                self.inside = 0
            self.depth -= 1

    def handle_data(self, data):
        if self.inside:
            self.text.append(data)


def _token_block():
    parser = _Field()
    parser.feed((PARTIALS / 'settings_general.html').read_text(encoding='utf-8'))
    return ' '.join(' '.join(parser.text).split()), parser.links


def test_the_general_tab_says_the_token_has_full_admin_access_and_how_to_rotate_it():
    text, links = _token_block()
    assert NAME in text, text
    assert 'full admin access' in text, text
    assert 'API_BEARER_TOKEN' in text and 'API_BEARER_TOKEN_FILE' in text, text
    assert 'restart' in text, text
    assert '#apikeys' in links, links


@pytest.mark.parametrize('path', [
    'templates/partials/settings_general.html',
    'templates/partials/settings_apikeys.html',
    'templates/partials/settings_oidc.html',
    'templates/partials/settings_deploy.html',
    'templates/setup.html',
    'templates/help.html',
    'docs/api.md',
    'docs/mcp.md',
])
def test_the_token_goes_by_one_name(path):
    text = ' '.join((REPO / path).read_text(encoding='utf-8').split())
    for other in OTHER_NAMES:
        assert other not in text, f'{path} calls the {NAME} "{other}"'


@pytest.mark.parametrize('path', [
    'templates/partials/settings_apikeys.html',
    'templates/partials/settings_oidc.html',
    'docs/api.md',
])
def test_the_places_that_mention_the_token_use_its_name(path):
    assert NAME in (REPO / path).read_text(encoding='utf-8'), path
