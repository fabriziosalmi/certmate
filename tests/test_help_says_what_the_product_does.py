"""The Help page says what the product does, and covers what it can do.

UX perception audit of v2.58.0, P47 and P46. Help was written for an older
product and had drifted from it, and from itself:

- Quick Start said CertMate "ships with auth off" and told the operator to
  enable local authentication, while the setup page creates the first admin and
  turns sign-in on in the same request.
- It sent people to Settings → General for the API token (and its Generate
  button, which saves nothing), while the API section of the same page sent
  them to Settings → API Keys.
- Every "Settings → DNS" or "Settings → CA" link opened Settings → General.
- It named a DNS "Test Connection" button that does not exist, a backup button
  by a label the page does not use, a retention of "last 10, configurable"
  (the code keeps 50 and none older than 30 days, with no setting), and blamed
  a broken UI on an "Alpine CDN" when Alpine is served by CertMate itself.
- It said nothing about client certificates, the ACME server, Inventory or the
  crypto readiness report.

These checks read the template against the code that decides each fact, so a
change to either side that makes them disagree fails here. The browser half,
that each link lands on the tab it names and that the search finds the new
sections, is tests/test_ui_help_links_and_search_reach_what_they_name.py.
"""
import pathlib
import re
from html.parser import HTMLParser

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
HELP = (REPO / 'templates' / 'help.html').read_text(encoding='utf-8')


class _VisibleText(HTMLParser):
    """The text a reader sees: no script or style, no comments, no tags."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self._hidden = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._hidden += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._hidden:
            self._hidden -= 1

    def handle_data(self, data):
        if not self._hidden:
            self.parts.append(data)


def _text(fragment):
    """Visible text of a piece of markup, whitespace collapsed."""
    parser = _VisibleText()
    parser.feed(fragment)
    parser.close()
    return re.sub(r'\s+', ' ', ' '.join(parser.parts)).strip()


def _section(section_id):
    match = re.search(rf'<section id="{re.escape(section_id)}"[^>]*>(.*?)</section>', HELP, re.S)
    assert match, f'templates/help.html has no <section id="{section_id}">'
    return match.group(1)


def _settings_tabs():
    """{fragment: label} for the Settings side menu, from where it is defined."""
    source = (REPO / 'static' / 'js' / 'settings-tabs.js').read_text(encoding='utf-8')
    tabs = dict(re.findall(r"\{ id: '(\w+)', icon: '[^']*', label: '([^']+)' \}", source))
    assert len(tabs) >= 10, f'read {len(tabs)} tabs out of settings-tabs.js; the format changed'
    return tabs


def _ui_sources():
    """Every template and script of the product except Help itself and vendored bundles."""
    files = [p for p in (REPO / 'templates').rglob('*.html') if p.name != 'help.html']
    files += [p for p in (REPO / 'static' / 'js').glob('*.js')
              if not p.name.endswith('.min.js') and p.name != 'redoc.standalone.js']
    return '\n'.join(p.read_text(encoding='utf-8') for p in files)


# ---------------------------------------------------------------------------
# P47: no instruction that contradicts the product or the rest of the page
# ---------------------------------------------------------------------------

SETTINGS_LINK = re.compile(r'<a href="(/settings[^"]*)"[^>]*>Settings → ([^<]+)</a>')


def test_help_links_to_settings_by_tab():
    links = SETTINGS_LINK.findall(HELP)
    assert len(links) >= 8, f'found {len(links)} "Settings → X" links; the markup changed'


@pytest.mark.parametrize('href,label', SETTINGS_LINK.findall(HELP))
def test_every_settings_link_in_help_names_the_tab_it_opens(href, label):
    tabs = _settings_tabs()
    fragment = href.partition('#')[2]
    assert fragment, (
        f'"Settings → {label}" links to {href}, which opens Settings → General: '
        f'the tab comes from the URL fragment (settings-tabs.js)')
    assert fragment in tabs, f'{href}: Settings has no tab "{fragment}"'
    assert tabs[fragment] == label.split(' → ')[0].strip(), (
        f'"Settings → {label}" opens the tab labelled "{tabs[fragment]}"')


def test_quick_start_says_setup_turns_sign_in_on():
    """The setup page creates the admin and enables local login in one request
    (templates/setup.html reads `local_auth_enabled` from the answer); Help told
    people to go and enable it afterwards."""
    setup = (REPO / 'templates' / 'setup.html').read_text(encoding='utf-8')
    assert 'local_auth_enabled === true' in setup
    quick = _text(_section('quick-start'))
    assert 'turns sign-in on' in quick, quick
    assert 'Enable Local Authentication' not in quick, quick


def test_help_names_one_place_to_get_an_api_token():
    """API Keys is where tokens come from. The General tab's token is named once,
    by its on-screen name, as full admin access, never as the place to go."""
    general = (REPO / 'templates' / 'partials' / 'settings_general.html').read_text(encoding='utf-8')
    assert 'API Bearer Token' in general, 'the General tab renamed its token field; follow it here'
    text = _text(HELP)
    assert text.count('API Bearer Token') == 1, (
        f'Help names the General token {text.count("API Bearer Token")} times; once, as legacy')
    sentence = re.search(r'[^.]*API Bearer Token[^.]*\.', text).group(0)
    assert 'full admin access' in sentence and 'API Keys' in sentence, sentence
    api = _section('api-usage')
    assert '/settings#apikeys' in api and '/settings#general' not in _section('quick-start')
    # The Generate button beside that field does not save a token (P04).
    assert not re.search(r'\bGenerate\b(?! private key)', text), 'Help sends people to Generate'


def test_help_names_the_alpine_file_the_pages_load():
    base = (REPO / 'templates' / 'base.html').read_text(encoding='utf-8')
    src = re.search(r'<script defer src="([^"]*alpine[^"]*)"', base).group(1)
    text = _text(_section('troubleshooting'))
    assert src in text, f'the troubleshooting entry does not name {src}'
    assert 'CDN' not in text, 'Alpine is served by CertMate, not by a CDN'


def test_help_describes_the_backup_the_code_keeps():
    from modules.core.file_operations import BACKUP_RETENTION_DAYS, MAX_BACKUPS_PER_TYPE
    settings = (REPO / 'templates' / 'settings.html').read_text(encoding='utf-8')
    backup = _text(_section('backup-recovery'))
    assert 'Create Unified Backup' in settings and 'Create Unified Backup' in backup, backup
    assert f'at most {MAX_BACKUPS_PER_TYPE} backups' in backup, backup
    assert f'{BACKUP_RETENTION_DAYS} days' in backup, backup
    assert 'configurable' not in backup, 'retention is two constants, with no setting'
    # Without a passphrase a backup holds no credentials and no private keys.
    assert 'CERTMATE_BACKUP_PASSPHRASE' in backup, backup


def test_help_offers_both_challenges_the_product_offers():
    index = (REPO / 'templates' / 'index.html').read_text(encoding='utf-8')
    assert 'value="http-01"' in index and 'value="dns-01"' in index
    section = _text(_section('dns-providers'))
    assert 'DNS-01' in section and 'HTTP-01' in section, section


@pytest.mark.parametrize('claim,why', [
    ('ships with auth off', 'the setup page creates the admin and turns sign-in on'),
    ('Alpine CDN', 'Alpine is /static/js/alpine.min.js, served by CertMate'),
    ('Test Connection', 'Settings → DNS has no connection test (only Storage has one)'),
    ('Last 10 by default', 'the code keeps 50 backups and none older than 30 days'),
    ('to roll a new one', "the General token's Generate button saves nothing (P04)"),
    ('use the eye toggle to reveal it', 'the stored token is never sent back to the page'),
    ('verify reachability and EAB', 'Check configuration only reaches a Private CA'),
    ('CertMate uses the DNS-01 challenge', 'HTTP-01 is offered by the wizard and the form'),
    ('certmate#dns-providers', 'the README has no such heading; docs/dns-providers.md does'),
])
def test_help_no_longer_makes_a_claim_the_product_contradicts(claim, why):
    assert claim not in HELP, f'Help still says "{claim}": {why}'


def test_the_dns_tab_still_has_no_connection_test():
    """The fact the line above relies on. If Settings → DNS gains a test
    button, Help may name it again."""
    dns = (REPO / 'templates' / 'partials' / 'settings_dns.html').read_text(encoding='utf-8')
    assert 'Test Connection' not in dns


def test_every_control_help_names_is_in_the_product():
    """A label Help tells you to click is marked `data-ui-label`; each one is
    looked up in the templates and scripts that draw the product."""
    labels = [_text(m) for m in re.findall(r'<span[^>]*data-ui-label[^>]*>(.*?)</span>', HELP, re.S)]
    assert len(labels) >= 20, f'{len(labels)} labels marked in Help; the markup changed'
    ui = _ui_sources()
    missing = [label for label in labels if label not in ui]
    assert not missing, f'Help names controls the product does not have: {missing}'


# ---------------------------------------------------------------------------
# P46: client certificates, the ACME server, Inventory, crypto readiness
# ---------------------------------------------------------------------------

NEW_SECTIONS = ['client-certificates', 'acme-server', 'inventory', 'crypto-readiness']


@pytest.mark.parametrize('section_id', NEW_SECTIONS)
def test_help_has_a_section_for_the_feature(section_id):
    """In the chip bar, and a search target (the search filters [data-help-section])."""
    assert re.search(rf'<section id="{section_id}" data-help-section', HELP), section_id
    nav = re.search(r'<nav [^>]*aria-label="Help sections">(.*?)</nav>', HELP, re.S).group(1)
    assert f'href="#{section_id}"' in nav, f'the chip bar has no link to #{section_id}'


def test_the_client_certificate_section_matches_the_form():
    form = (REPO / 'templates' / 'partials' / '_client_create.html').read_text(encoding='utf-8')
    low, high = re.search(r'id="daysValid"[^>]*min="(\d+)" max="(\d+)"', form).groups()
    columns = re.search(r'columns: ([^<]+)\n', form).group(1)
    section = _text(_section('client-certificates'))
    assert f'{low} to {high} days' in section, section
    for column in re.findall(r'(\w+)(?: \(optional\))?(?:,|$)', columns.strip()):
        assert column in section, f'the CSV column {column} is not named in Help'
    # The PEM CRL is always there; the DER one answers 404 until the first revocation.
    assert '/api/crl/download/pem' in section and '/api/crl/download/der' not in section
    assert '/api/client-certs/ca' in section


def _bulk_columns():
    """The columns the bulk importer reads, and the one it refuses a file
    without (modules/api/client_certificates.py)."""
    api = (REPO / 'modules' / 'api' / 'client_certificates.py').read_text(encoding='utf-8')
    read = set(re.findall(r"""cert_data\.get\(['"](\w+)['"]""", api))
    required = set(re.findall(r"'(\w+)' not in headers", api))
    limit = int(re.search(r'max_batch = (\d+)', api).group(1))
    return read, required, limit


def test_the_bulk_csv_hint_and_help_name_every_column_the_importer_reads():
    """Help and the form's hint listed email and organization as if required,
    and left out organizational_unit and days_valid."""
    read, required, limit = _bulk_columns()
    assert required == {'common_name'} and {'common_name', 'email', 'days_valid'} <= read, (read, required)
    form = (REPO / 'templates' / 'partials' / '_client_create.html').read_text(encoding='utf-8')
    hint = re.search(r'columns: ([^<]+)\n', form).group(1)
    named = dict(re.findall(r'(\w+)( \(optional\))?(?:,|$)', hint.strip()))
    assert set(named) == read, (sorted(named), sorted(read))
    assert {c for c, optional in named.items() if not optional} == required, hint
    assert f'at most {limit} rows' in form
    section = _text(_section('client-certificates'))
    for column in read:
        assert column in section, f'Help does not name the CSV column {column}'
    assert 'common_name column, the only one required' in section, section
    assert f'up to {limit} rows' in section, section


def test_the_csv_downloads_and_the_json_opens_as_help_says(app_client):
    """Help said CSV and JSON both download; only the CSV is an attachment,
    and the JSON link opens in a tab (templates/inventory.html)."""
    csv = app_client.get('/api/inventory/crypto-report?format=csv')
    assert csv.status_code == 200 and 'attachment' in csv.headers.get('Content-Disposition', '')
    js = app_client.get('/api/inventory/crypto-report')
    assert js.status_code == 200 and 'attachment' not in js.headers.get('Content-Disposition', '')
    inventory = (REPO / 'templates' / 'inventory.html').read_text(encoding='utf-8')
    json_link = re.search(r'<a href="/api/inventory/crypto-report"([^>]*)>', inventory).group(1)
    assert 'target="_blank"' in json_link
    text = _text(HELP)
    assert 'CSV downloads the table of certificates' in text and 'JSON opens the whole report in a new tab' in text
    assert 'JSON download' not in text


def test_quick_start_says_what_setup_mode_allows_and_what_ends_it():
    """Help said the instance is never left open, then that a visitor can
    read it. Setup mode serves every caller as admin until sign-in is on with
    a user, an operator token is set or single sign-on is configured
    (auth.setup_mode_for); it refuses every write but the first admin and the
    reads that carry private keys or backups away (_SETUP_READS_REFUSED)."""
    auth = (REPO / 'modules' / 'core' / 'auth.py').read_text(encoding='utf-8')
    predicate = auth[auth.index('def setup_mode_for'):auth.index('def would_open_setup_mode')]
    assert 'has_operator_bearer_token' in predicate and "oidc.get('client_id')" in predicate
    assert "local_auth_enabled" in predicate and 'len(users) > 0' in predicate
    refused = auth[auth.index('_SETUP_READS_REFUSED ='):auth.index('_READ_METHODS =')]
    assert '/download' in refused and 'backups/download' in refused
    quick = _text(_section('quick-start'))
    assert 'never left open' not in quick, quick
    for fact in ('sign-in is on with a first user', 'API_BEARER_TOKEN', 'single sign-on',
                 'everything but private keys and backups', 'create the first admin'):
        assert fact in quick, (fact, quick)


def test_the_acme_section_matches_the_server():
    from modules.core import acme_ca
    from modules.core.acme_server import DEFAULTS
    section = _text(_section('acme-server'))
    assert '/acme/directory' in section and 'Settings → ACME' in section
    assert f'{acme_ca.DEFAULT_VALIDITY_DAYS} days' in section, section
    assert f'{acme_ca.MIN_VALIDITY_DAYS} to {acme_ca.MAX_VALIDITY_DAYS}' in section, section
    assert DEFAULTS['enabled'] is False and 'off until' in section, section
    assert DEFAULTS['eab_required'] is True and 'Require an EAB key' in section, section
    assert 'HTTPS' in section and 'BEHIND_PROXY' in section, section


def test_the_crypto_section_matches_the_classifier():
    from modules.core import crypto_report
    section = _text(_section('crypto-readiness'))
    assert f'RSA under {crypto_report._RSA_MIN}' in section, section
    for year in ('2030', '2035'):
        assert year in crypto_report.DEPRECATION_NOTES[crypto_report.CLASS_ACCEPTABLE]
        assert year in section, section
    assert 'NIST IR 8547' in section, section
    assert '/inventory/crypto-report' in _section('crypto-readiness')


# ---------------------------------------------------------------------------
# What Help says about scope, checked against a running application
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def app_client(tmp_path_factory):
    """The real application on temporary data dirs, signed in as an admin."""
    import secrets

    from modules.factory import create_app
    tmp = tmp_path_factory.mktemp('help')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        token = secrets.token_urlsafe(32)
        patch.setenv('API_BEARER_TOKEN', token)
        application, _container = create_app()
        client = application.test_client()
        client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
        yield client


def test_client_certificates_are_not_in_the_inventory_as_help_says(app_client):
    created = app_client.post('/api/client-certs/create', json={
        'common_name': 'help-check@example.com', 'cert_usage': 'api-mtls', 'days_valid': 30})
    assert created.status_code == 201, created.get_data(as_text=True)
    listed = app_client.get('/api/inventory').get_json()
    names = [r.get('subject_cn') for r in listed.get('certificates', [])]
    assert 'help-check@example.com' not in names, (
        'client certificates are in the inventory now; Help says they are not')
    assert 'Client certificates are not in it' in _text(_section('inventory'))
    assert 'Client certificates are not in it' in _text(_section('crypto-readiness'))


def test_the_client_ca_and_its_crl_are_served_as_help_says(app_client):
    """Help gives these two as what a verifying server installs; no sign-in.
    A second client of the same application carries no Bearer token."""
    plain = app_client.application.test_client()
    ca = plain.get('/api/client-certs/ca')
    crl = plain.get('/api/crl/download/pem')
    assert ca.status_code == 200 and b'BEGIN CERTIFICATE' in ca.data
    assert crl.status_code == 200 and b'BEGIN X509 CRL' in crl.data
    assert 'without signing in' in _text(_section('client-certificates'))


def test_the_acme_server_answers_404_while_it_is_off_as_help_says(app_client):
    assert app_client.get('/acme/directory').status_code == 404
    assert 'answers 404' in _text(_section('acme-server'))
