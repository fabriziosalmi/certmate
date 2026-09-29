"""Akamai Edge DNS waits long enough for its own nameservers (#974).

CertMate passed `--edgedns-propagation-seconds 90`, from its settings default
and its strategy default alike. The Akamai plugin's own default is 180 and its
documentation suggests 240: Edge DNS takes minutes to push a new record to all
of its authoritative nameservers, which is where Let's Encrypt looks, from
several vantage points. A reporter on Akamai saw nearly every order fail with
"Some challenges have failed" while the record appeared seconds later.

The default is now 180. Every install that ever saved its settings has the old
default written into settings.json, so a stored 90 for edgedns is read as the
retired default and moved to 180; any other value is the operator's and stays.
The per-provider value is also returned by GET /api/settings, and the settings
page shows and edits it (it was reachable only by hand-editing settings.json).
"""
import json

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def sm(tmp_path):
    dirs = {name: tmp_path / name for name in ('certificates', 'data', 'backups', 'logs')}
    for d in dirs.values():
        d.mkdir()
    file_ops = FileOperations(cert_dir=dirs['certificates'], data_dir=dirs['data'],
                              backup_dir=dirs['backups'], logs_dir=dirs['logs'])
    return SettingsManager(file_ops=file_ops, settings_file=dirs['data'] / 'settings.json')


def _stored(sm):
    return json.loads(sm.settings_file.read_text())['dns_propagation_seconds']


def test_a_fresh_install_waits_180_for_akamai(sm):
    assert sm.atomic_update({'email': 'ops@example.com'})
    assert sm.load_settings()['dns_propagation_seconds']['edgedns'] == 180


def test_the_retired_default_is_moved_and_written_back(sm):
    assert sm.atomic_update({'email': 'ops@example.com'})
    data = json.loads(sm.settings_file.read_text())
    data['dns_propagation_seconds']['edgedns'] = 90
    data['dns_propagation_seconds']['cloudflare'] = 45
    data['certmate_version'] = '2.39.0'
    sm.settings_file.write_text(json.dumps(data))

    loaded = sm.load_settings(use_cache=False)
    assert loaded['dns_propagation_seconds']['edgedns'] == 180
    assert loaded['dns_propagation_seconds']['cloudflare'] == 45
    assert _stored(sm)['edgedns'] == 180, 'the migration must persist, not only read'


@pytest.mark.parametrize('chosen', [60, 240, 600])
def test_a_value_the_operator_chose_is_left_alone(sm, chosen):
    assert sm.atomic_update({'email': 'ops@example.com'})
    assert sm.atomic_update({'dns_propagation_seconds': {'edgedns': chosen}})
    assert sm.load_settings(use_cache=False)['dns_propagation_seconds']['edgedns'] == chosen


def test_the_command_certbot_receives():
    import tests.test_issuance_command_is_a_contract as contract
    creds = {'client_token': 'a', 'client_secret': 'b', 'access_token': 'c',
             'host': 'akab-x.luna.akamaiapis.net'}
    argv = contract._build_command({'dns_provider': 'edgedns'}, {}, creds)
    assert argv[argv.index('--edgedns-propagation-seconds') + 1] == '180'


def test_get_api_settings_returns_the_values():
    from flask import Flask
    from flask_restx import Api, marshal

    from modules.api.models import create_api_models

    with Flask(__name__).app_context():
        models = create_api_models(Api())
        out = marshal({'dns_propagation_seconds': {'edgedns': 240, 'cloudflare': 60}},
                      models['settings_model'])
    assert out['dns_propagation_seconds'] == {'edgedns': 240, 'cloudflare': 60}


@pytest.mark.parametrize('written_by', ['2.40.1', '2.41.0', '3.0.0'])
def test_a_90_saved_by_a_newer_version_is_the_operator_s_choice(sm, written_by):
    """The migration runs once: once a version that knows the new default has
    written the file, a 90 there was chosen, and is not moved again."""
    assert sm.atomic_update({'email': 'ops@example.com'})
    data = json.loads(sm.settings_file.read_text())
    data['dns_propagation_seconds']['edgedns'] = 90
    data['certmate_version'] = written_by
    sm.settings_file.write_text(json.dumps(data))
    assert sm.load_settings(use_cache=False)['dns_propagation_seconds']['edgedns'] == 90


@pytest.mark.parametrize('written_by', [None, '', 'dev', '2.21.3', '2.40.0'])
def test_a_file_from_before_the_change_is_migrated(sm, written_by):
    assert sm.atomic_update({'email': 'ops@example.com'})
    data = json.loads(sm.settings_file.read_text())
    data['dns_propagation_seconds']['edgedns'] = 90
    if written_by is None:
        data.pop('certmate_version', None)
    else:
        data['certmate_version'] = written_by
    sm.settings_file.write_text(json.dumps(data))
    assert sm.load_settings(use_cache=False)['dns_propagation_seconds']['edgedns'] == 180
