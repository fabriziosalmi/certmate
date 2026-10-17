"""Cloudflare waits 20 seconds for its record, not 60.

CertMate passed `--dns-cloudflare-propagation-seconds 60`, from its settings
default and its strategy default alike, while the plugin's own default is 10.
On a fresh install that wait was 60 of the 98 seconds to a first certificate.
Measured on Let's Encrypt staging from a fresh instance, 33 issuances on new
names all succeeded: 13 of 13 at 10 seconds, 10 of 10 at 20 and at 30. The
default is now 20, twice the shortest wait that never failed.

As with Akamai (#974), every install that ever saved its settings has the old
default written into settings.json, so a stored 60 for cloudflare in a file
last written by 2.50.2 or earlier is read as the retired default and moved to
20; any other value, or a 60 saved by a later version, is the operator's and
stays. Certificates issued before keep the wait certbot stored in their
renewal configuration until they are issued again (see
tests/test_propagation_seconds_has_one_home.py).
"""
import json

import pytest

from modules.core.dns_strategies import CloudflareStrategy
from modules.core.file_operations import FileOperations
from modules.core.settings import DEFAULT_CLOUDFLARE_PROPAGATION_SECONDS, SettingsManager

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


def _rewrite(sm, cloudflare, written_by):
    data = json.loads(sm.settings_file.read_text())
    data['dns_propagation_seconds']['cloudflare'] = cloudflare
    if written_by is None:
        data.pop('certmate_version', None)
    else:
        data['certmate_version'] = written_by
    sm.settings_file.write_text(json.dumps(data))


def test_the_default_is_20_in_both_places():
    assert DEFAULT_CLOUDFLARE_PROPAGATION_SECONDS == 20
    assert CloudflareStrategy().default_propagation_seconds == 20


def test_a_fresh_install_waits_20_for_cloudflare(sm):
    assert sm.atomic_update({'email': 'ops@example.com'})
    assert sm.load_settings()['dns_propagation_seconds']['cloudflare'] == 20


def test_the_retired_default_is_moved_and_written_back(sm):
    assert sm.atomic_update({'email': 'ops@example.com'})
    data = json.loads(sm.settings_file.read_text())
    data['dns_propagation_seconds']['route53'] = 45
    sm.settings_file.write_text(json.dumps(data))
    _rewrite(sm, 60, '2.50.2')

    loaded = sm.load_settings(use_cache=False)
    assert loaded['dns_propagation_seconds']['cloudflare'] == 20
    assert loaded['dns_propagation_seconds']['route53'] == 45
    assert _stored(sm)['cloudflare'] == 20, 'the migration must persist, not only read'


@pytest.mark.parametrize('chosen', [10, 30, 45, 90, 120])
def test_a_value_the_operator_chose_is_left_alone(sm, chosen):
    assert sm.atomic_update({'email': 'ops@example.com'})
    _rewrite(sm, chosen, '2.50.2')
    assert sm.load_settings(use_cache=False)['dns_propagation_seconds']['cloudflare'] == chosen


@pytest.mark.parametrize('written_by', ['2.50.3', '2.51.0', '3.0.0'])
def test_a_60_saved_by_a_newer_version_is_the_operator_s_choice(sm, written_by):
    """The migration runs once: once a version that knows the new default has
    written the file, a 60 there was chosen, and is not moved again."""
    assert sm.atomic_update({'email': 'ops@example.com'})
    _rewrite(sm, 60, written_by)
    assert sm.load_settings(use_cache=False)['dns_propagation_seconds']['cloudflare'] == 60


@pytest.mark.parametrize('written_by', [None, '', 'dev', '2.21.3', '2.50.1', '2.50.2'])
def test_a_file_from_before_the_change_is_migrated(sm, written_by):
    assert sm.atomic_update({'email': 'ops@example.com'})
    _rewrite(sm, 60, written_by)
    assert sm.load_settings(use_cache=False)['dns_propagation_seconds']['cloudflare'] == 20


def test_the_command_certbot_receives():
    """With nothing configured for Cloudflare, the strategy default reaches certbot."""
    import tests.test_issuance_command_is_a_contract as contract
    argv = contract._build_command({'dns_provider': 'cloudflare'},
                                   {'dns_propagation_seconds': {}}, {'api_token': 'cf-token'})
    assert argv[argv.index('--dns-cloudflare-propagation-seconds') + 1] == '20'
