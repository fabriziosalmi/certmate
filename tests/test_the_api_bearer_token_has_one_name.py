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
OTHER_NAMES = ('legacy API token', 'API bearer token', 'API Bearer token', 'global bearer token',
               'legacy bearer token', 'legacy token', 'Bearer token for API', 'API auth token',
               'containing the bearer token', 'for the API token')


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
    assert 'wins when both are set' in text, text
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
    'templates/index.html',
    'docs/configuration.md',
    'docs/docker.md',
    'mcp/README.md',
    'clients/certmate-cli/certmate_cli/main.py',
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


def test_the_setup_page_says_which_token_it_wants_after_a_rotation():
    """It sent someone who rotated API_BEARER_TOKEN to
    scripts/reset_admin_password.py, which does nothing with the token; since
    #401 a restart puts the rotated token in force, the file first
    (auth.reconcile_bearer_token_from_env)."""
    setup = (REPO / 'templates' / 'setup.html').read_text(encoding='utf-8')
    auth = (REPO / 'modules' / 'core' / 'auth.py').read_text(encoding='utf-8')
    assert 'def reconcile_bearer_token_from_env' in auth
    flat = ' '.join(setup.split())
    start = flat.index('The pasted API Bearer Token was not accepted.')
    message = flat[start:flat.index(');', start)]
    assert 'reset_admin_password' not in message, message
    assert "API_BEARER_TOKEN_FILE ' + 'if it is set (the file wins)" in message, message
    assert 'after a restart' in message, message


def test_the_download_note_names_the_credentials_that_can_download_keys():
    """The dashboard's download command fetches private keys: a viewer key is
    refused (403, operator role required), so the note names an operator or
    admin key, or the API Bearer Token."""
    index = ' '.join((REPO / 'templates' / 'index.html').read_text(encoding='utf-8').split())
    assert 'operator or admin API key' in index
    assert 'or the API Bearer Token' in index


def test_the_log_does_not_send_anyone_to_rotate_the_token_where_it_cannot_be():
    """modules/core/settings.py logged 'rotate it via the API Keys UI', where
    the API Bearer Token cannot be rotated; it is set by API_BEARER_TOKEN(_FILE)
    and a restart."""
    settings = (REPO / 'modules' / 'core' / 'settings.py').read_text(encoding='utf-8')
    assert 'API Keys UI' not in settings
    assert 'to rotate it, set API_BEARER_TOKEN' in settings


@pytest.mark.parametrize('lang', ['de', 'es', 'fr', 'it'])
def test_each_translation_of_the_docker_page_names_the_token_as_often_as_the_english(lang):
    """A translation that kept its own word for the token ("das API-Token",
    "le jeton API") next to an English page that says API Bearer Token is
    the same split name in another language."""
    english = (REPO / 'docs' / 'docker.md').read_text(encoding='utf-8').count(NAME)
    translated = (REPO / 'docs' / lang / 'docker.md').read_text(encoding='utf-8').count(NAME)
    assert english and translated == english, (lang, english, translated)


# Each translation's own former words for this token in docs/<lang>/docker.md
# (DNS providers' "API token" lives elsewhere, not on this page).
OLD_WORDS = {
    'de': ('das API-Token', 'API-Authentifizierungs-Token', 'API-Bearer-Token'),
    'es': ('el token de la API', 'Token de autenticación de la API', 'bearer token de la API'),
    'fr': ('le jeton API', "Token d'authentification de l'API", 'token bearer'),
    'it': ('il token API', 'Token di autenticazione API', 'token bearer API'),
}


@pytest.mark.parametrize('lang', sorted(OLD_WORDS))
def test_no_translation_of_the_docker_page_keeps_its_old_word_for_the_token(lang):
    text = (REPO / 'docs' / lang / 'docker.md').read_text(encoding='utf-8')
    kept = [word for word in OLD_WORDS[lang] if word in text]
    assert kept == [], (lang, kept)

