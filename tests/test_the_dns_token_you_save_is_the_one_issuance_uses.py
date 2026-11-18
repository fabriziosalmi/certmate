"""The DNS token you save is the one issuance uses (UX perception audit P05).

A fresh instance's first-run settings carried sixteen providers in the
single-account shape with every credential empty, and the load-time migration
wrapped each one in an account "default", described as "Migrated from
single-account configuration", with nothing in it. The settings page then
showed that empty account and, under it, the single "API Token" field. Saving
that field wrote a flat `api_token` beside `accounts`, where nothing reads it:
the lookup issuance goes through reads `accounts` only. The save said
"Settings saved successfully", the card still said "No credentials", and the
first certificate failed with "account 'default' not configured".

Now:

* no empty placeholder account is made, and the ones earlier versions made are
  removed when they hold nothing;
* a flat credential left beside `accounts` by the old settings page is moved
  into the "default" account once, with a log line, unless that account has
  credentials of its own, which are never overwritten;
* the settings page writes the single field into `accounts.default`
  (tests/test_ui_the_dns_token_you_save_is_the_one_issuance_uses.py and the
  node test below).
"""
import json
import logging
import subprocess
from pathlib import Path

import pytest

from modules.core.dns_providers import DNSManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

PLACEHOLDER = 'Migrated from single-account configuration'
TOKEN = 'T' * 40
OTHER = 'A' * 40
LOGGER = 'modules.core.settings'


def _manager(tmp_path, on_disk=None):
    dirs = [tmp_path / name for name in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir(exist_ok=True)
    settings_file = dirs[1] / 'settings.json'
    if on_disk is not None:
        settings_file.write_text(json.dumps(on_disk))
    return SettingsManager(file_ops=FileOperations(*dirs), settings_file=settings_file), settings_file


def _upgraded(dns_providers, default_accounts=None):
    """A settings.json as an earlier version left it, setup finished."""
    return {
        'email': 'ops@example.com', 'domains': [], 'setup_completed': True,
        'api_bearer_token': 'Zq8vK2mN4pR7sT1wX5yA9bC3dE6fG0hJ7kL2mN5pQ8rS1tU4', 'dns_provider': 'cloudflare',
        'challenge_type': 'dns-01', 'dns_providers': dns_providers,
        'default_accounts': default_accounts if default_accounts is not None else {},
    }


def _placeholder(provider, **values):
    return {'name': f'Default {provider.title()} Account', 'description': PLACEHOLDER, **values}


def _second_load_changes_nothing(manager, settings_file, caplog):
    before = settings_file.read_bytes()
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        manager.load_settings()
    assert settings_file.read_bytes() == before
    dns_lines = [r.getMessage() for r in caplog.records if 'DNS' in r.getMessage()]
    assert dns_lines == [], dns_lines


def test_a_fresh_instance_has_no_placeholder_dns_accounts(tmp_path):
    manager, _ = _manager(tmp_path)
    manager.load_settings()            # first boot writes the first-run settings
    settings = manager.load_settings()  # the next load runs the migrations
    accounts = DNSManager(manager).list_accounts(settings=settings)
    assert [a for a in accounts if a.get('description') == PLACEHOLDER] == []
    assert accounts == []
    assert DNSManager(manager).get_dns_provider_account_config('cloudflare') == (None, None)


def test_the_empty_accounts_an_earlier_version_made_are_removed_once(tmp_path, caplog):
    on_disk = _upgraded(
        {'cloudflare': {'accounts': {'default': _placeholder('cloudflare', api_token='')}},
         'route53': {'accounts': {'default': _placeholder(
             'route53', access_key_id='', secret_access_key='', region='us-east-1')}}},
        {'cloudflare': 'default', 'route53': 'default'})
    manager, settings_file = _manager(tmp_path, on_disk)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        settings = manager.load_settings()
    assert settings['dns_providers'] == {}
    assert settings['default_accounts'] == {}
    assert any('empty' in r.getMessage() and 'DNS' in r.getMessage() for r in caplog.records)
    assert json.loads(settings_file.read_text())['dns_providers'] == {}
    _second_load_changes_nothing(manager, settings_file, caplog)


def test_an_earlier_first_run_file_not_yet_migrated_ends_with_no_account(tmp_path, caplog):
    """The first-run settings of an earlier version, flat and empty, as a file
    that was never loaded again before the upgrade."""
    on_disk = _upgraded({'cloudflare': {'api_token': ''},
                         'route53': {'access_key_id': '', 'secret_access_key': '', 'region': 'us-east-1'}})
    manager, settings_file = _manager(tmp_path, on_disk)
    settings = manager.load_settings()
    assert settings['dns_providers'] == {}
    assert settings['default_accounts'] == {}
    _second_load_changes_nothing(manager, settings_file, caplog)


def test_a_change_inside_an_account_alone_is_written_to_the_file(tmp_path):
    """The load compares a deep copy: a change made only inside an account
    (here its name) went unnoticed by the shallow copy and was not saved,
    so it was made again at every load."""
    manager, settings_file = _manager(tmp_path)
    manager.load_settings()
    manager.load_settings()            # nothing left for any other migration
    document = json.loads(settings_file.read_text())
    document['dns_providers'] = {'cloudflare': {'accounts': {'default': {'api_token': TOKEN}}}}
    document['default_accounts'] = {'cloudflare': 'default'}
    settings_file.write_text(json.dumps(document))
    manager.load_settings(use_cache=False)
    on_file = json.loads(settings_file.read_text())
    assert on_file['dns_providers']['cloudflare']['accounts']['default']['name'] == 'Default Cloudflare Account'


def test_an_empty_account_someone_added_is_not_the_migration_s_to_remove(tmp_path):
    """Only the placeholder the migration made, by its description, goes."""
    on_disk = _upgraded({'cloudflare': {'accounts': {'staging': {'name': 'Staging', 'api_token': ''}}}})
    manager, _ = _manager(tmp_path, on_disk)
    settings = manager.load_settings()
    assert settings['dns_providers']['cloudflare']['accounts'] == {'staging': {'name': 'Staging', 'api_token': ''}}


def test_a_flat_token_beside_the_accounts_is_moved_into_default_once(tmp_path, caplog):
    on_disk = _upgraded(
        {'cloudflare': {'accounts': {'default': _placeholder('cloudflare', api_token='')}, 'api_token': TOKEN}},
        {'cloudflare': 'default'})
    manager, settings_file = _manager(tmp_path, on_disk)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        settings = manager.load_settings()
    cloudflare = settings['dns_providers']['cloudflare']
    assert 'api_token' not in cloudflare
    assert cloudflare['accounts']['default']['api_token'] == TOKEN
    assert cloudflare['accounts']['default']['name'] == 'Default Cloudflare Account'
    assert any('cloudflare' in r.getMessage() and 'default' in r.getMessage() for r in caplog.records
               if r.levelno >= logging.INFO and 'DNS' in r.getMessage())
    config, account_id = DNSManager(manager).get_dns_provider_account_config('cloudflare')
    assert (account_id, config['api_token']) == ('default', TOKEN)
    on_file = json.loads(settings_file.read_text())['dns_providers']['cloudflare']
    assert on_file == cloudflare
    _second_load_changes_nothing(manager, settings_file, caplog)


def test_a_flat_token_with_no_default_account_gets_one(tmp_path, caplog):
    on_disk = _upgraded(
        {'cloudflare': {'accounts': {'prod': {'name': 'Prod', 'api_token': OTHER}}, 'api_token': TOKEN}},
        {'cloudflare': 'prod'})
    manager, settings_file = _manager(tmp_path, on_disk)
    settings = manager.load_settings()
    accounts = settings['dns_providers']['cloudflare']['accounts']
    assert accounts['prod'] == {'name': 'Prod', 'api_token': OTHER}
    assert accounts['default']['api_token'] == TOKEN
    assert settings['default_accounts']['cloudflare'] == 'prod'
    _second_load_changes_nothing(manager, settings_file, caplog)


def test_an_existing_default_account_is_never_overwritten(tmp_path, caplog):
    """The account's own credential wins, and the flat one is kept, not lost."""
    own = {'name': 'Production', 'api_token': OTHER}
    on_disk = _upgraded({'cloudflare': {'accounts': {'default': dict(own)}, 'api_token': TOKEN}},
                        {'cloudflare': 'default'})
    manager, settings_file = _manager(tmp_path, on_disk)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        settings = manager.load_settings()
    cloudflare = settings['dns_providers']['cloudflare']
    assert cloudflare['accounts']['default'] == own
    assert cloudflare['api_token'] == TOKEN
    assert DNSManager(manager).get_dns_provider_account_config('cloudflare')[0]['api_token'] == OTHER
    _second_load_changes_nothing(manager, settings_file, caplog)


def test_a_flat_settings_write_reaches_the_account_issuance_uses(tmp_path):
    """A client that still writes the flat shape (an API script, a settings
    tab opened before the upgrade) rotates the default account's token. It
    used to land beside the accounts, answered as saved, and was never read."""
    on_disk = _upgraded({'cloudflare': {'accounts': {'default': {'name': 'Production', 'api_token': OTHER}}}},
                        {'cloudflare': 'default'})
    manager, _ = _manager(tmp_path, on_disk)
    assert manager.atomic_update({'dns_providers': {'cloudflare': {'api_token': TOKEN}}})
    cloudflare = manager.load_settings(use_cache=False)['dns_providers']['cloudflare']
    assert 'api_token' not in cloudflare
    assert cloudflare['accounts']['default'] == {'name': 'Production', 'api_token': TOKEN}
    assert DNSManager(manager).get_dns_provider_account_config('cloudflare')[0]['api_token'] == TOKEN


def test_a_single_account_config_with_a_credential_still_becomes_default(tmp_path):
    """CONTROL: the original migration is unchanged for a real credential."""
    on_disk = _upgraded({'cloudflare': {'api_token': TOKEN}})
    manager, _ = _manager(tmp_path, on_disk)
    settings = manager.load_settings()
    assert settings['dns_providers']['cloudflare']['accounts']['default']['api_token'] == TOKEN
    assert settings['default_accounts']['cloudflare'] == 'default'


def test_an_account_written_without_a_name_is_named_and_made_the_default(tmp_path, caplog):
    """The setup wizard writes `accounts.default` with the credential only.
    The placeholder used to supply its name and the default slot."""
    on_disk = _upgraded({'cloudflare': {'accounts': {'default': {'api_token': TOKEN}}}})
    manager, settings_file = _manager(tmp_path, on_disk)
    settings = manager.load_settings()
    assert settings['dns_providers']['cloudflare']['accounts']['default'] == {
        'name': 'Default Cloudflare Account', 'api_token': TOKEN}
    assert settings['default_accounts'] == {'cloudflare': 'default'}
    _second_load_changes_nothing(manager, settings_file, caplog)


def test_the_single_token_field_is_saved_into_the_default_account(node):
    settings_js = Path(__file__).resolve().parent.parent / 'static/js/settings.js'
    script = r"""
const fs = require('fs');
global.window = global;
global.CertMate = {globalActions() {}, actions() {}, escapeHtml: s => String(s), formatTime: () => '12:00'};
const values = {default_ca: 'letsencrypt', dns_provider: 'cloudflare', challenge_type: 'dns-01',
    cloudflare_api_token: 'T'.repeat(40)};
global.FormData = class {get(key) { return values[key] || ''; }};
const legacy = {style: {display: 'block'}};
const elements = {
    'cloudflare-legacy-config': legacy,
    'storage-backend': {value: 'local_filesystem'},
    'storage-cert-dir': {value: 'certificates'},
    pfx_password: {value: ''},
    settingsDebugOutput: {appendChild() {}, scrollHeight: 0}
};
global.document = {getElementById(id) { return elements[id] || null; },
    querySelectorAll() { return []; }, addEventListener() {}, createElement() { return {}; }};
const code = fs.readFileSync(process.argv[1], 'utf8').replace(/\}\)\(\);\s*$/,
    'window.__test = (settings) => { isLoading = false; currentSettings = settings; form = {}; }; ' +
    'window.__save = saveSettings; })();');
eval(code);
const settings = {setup_completed: true, api_bearer_token_hash: 'stored',
    email: 'ops@example.com', ca_providers: {letsencrypt: {email: 'ops@example.com'}}, dns_providers: {}};
let sent;
global.fetch = (url, options) => {sent = JSON.parse(options.body); return new Promise(() => {});};
window.__test(settings);
window.__save();
const cloudflare = sent.dns_providers && sent.dns_providers.cloudflare;
if (!cloudflare || 'api_token' in cloudflare || !cloudflare.accounts ||
    cloudflare.accounts.default.api_token !== 'T'.repeat(40))
    throw Error('The token went beside the accounts: ' + JSON.stringify(cloudflare));
legacy.style.display = 'none'; sent = null; window.__test(settings); window.__save();
if (sent.dns_providers) throw Error('A hidden single-account field was saved: ' + JSON.stringify(sent.dns_providers));
"""
    result = subprocess.run([node, '-e', script, str(settings_js)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
