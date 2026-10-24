"""An IP-address certificate is known by its derived name everywhere a name is asked about (#1130).

An IP certificate lives under the name ``ip-<dashed>`` (utils.cert_name_for_ip),
because an address cannot be a lineage name. Every check that asks "is this a
certificate name" was written for domains: the per-certificate routes
(``validate_domain_path``), the settings save (which drops an entry it refuses
and still answers True) and the lineage repairs after a backup restore. Each
refused ``ip-1-1-1-1``, measured on main: ten routes answered 400, the settings
entry vanished on save, and a restored lineage was never repaired.

These tests pin the one rule (``ip_for_cert_name``) and each place it is asked.
"""
import os

import pytest

from modules.core.certificates import ip_certificate_refusal
from modules.core.domain_paths import DOMAIN_RE, validate_domain_path
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager
from modules.core.utils import (
    cert_name_for_ip,
    ip_for_cert_name,
    repair_certbot_lineage_symlinks,
    repair_certbot_renewal_paths,
    validate_certificate_name,
    validate_domain,
)

pytestmark = [pytest.mark.unit]


# --- the name and the address ------------------------------------------------

@pytest.mark.parametrize('address', ['1.1.1.1', '9.9.9.9', '185.187.170.216', '8.8.4.4'])
def test_the_name_reads_back_as_the_address_it_was_made_from(address):
    assert ip_for_cert_name(cert_name_for_ip(address)) == address


@pytest.mark.parametrize('name', [
    'ip-1-1-1',             # three octets
    'ip-1-1-1-1-1',         # five
    'ip-01-1-1-1',          # not the canonical spelling: a second name for 1.1.1.1
    'ip-256-1-1-1',         # not an address
    'IP-1-1-1-1',           # names on disk are lower case
    'ip-1-1-1-1\n',         # the newline DOMAIN_RE's \\Z exists for
    'ip-1-1-1-1.example.com',
    '1.1.1.1',              # an address is not a name
    'example.com',
    '',
    None,
    1111,
])
def test_anything_else_is_not_an_ip_certificate_name(name):
    assert ip_for_cert_name(name) is None


def test_no_domain_can_take_the_name_of_an_ip_certificate():
    """The two namespaces cannot collide: a domain needs a dot and an
    alphabetic TLD, and the derived name has neither."""
    name = cert_name_for_ip('1.1.1.1')
    assert not DOMAIN_RE.match(name)
    assert validate_domain(name)[0] is False


def test_a_certificate_name_is_a_domain_or_the_name_of_an_ip_certificate():
    assert validate_certificate_name('ip-1-1-1-1') == (True, 'ip-1-1-1-1')
    assert validate_certificate_name('WWW.Example.com') == (True, 'www.example.com')
    assert validate_certificate_name('1.1.1.1')[0] is False
    assert validate_certificate_name('printer')[0] is False
    assert validate_certificate_name('ip-01-1-1-1')[0] is False


# --- the routes: validate_domain_path -----------------------------------------

def test_a_route_reaches_an_ip_certificate_by_its_name(tmp_path):
    path, error = validate_domain_path('ip-1-1-1-1', tmp_path)
    assert error is None
    assert path == tmp_path / 'ip-1-1-1-1'


@pytest.mark.parametrize('name', ['ip-01-1-1-1', 'ip-1-1-1-1\n', '1.1.1.1', 'ip-1-1-1'])
def test_a_route_still_refuses_what_is_not_a_name(tmp_path, name):
    path, error = validate_domain_path(name, tmp_path)
    assert path is None and error


# --- the settings save ---------------------------------------------------------

@pytest.fixture
def settings_manager(tmp_path):
    for name in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / name).mkdir()
    file_ops = FileOperations(cert_dir=tmp_path / 'certificates', data_dir=tmp_path / 'data',
                              backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')
    return SettingsManager(file_ops, tmp_path / 'data' / 'settings.json')


def test_the_settings_keep_an_ip_certificate_and_still_drop_a_bad_name(settings_manager):
    """The save dropped the entry and answered True, so the renewal sweep
    never saw the certificate as registered."""
    def _add(settings):
        settings['domains'] = [{'domain': 'ip-1-1-1-1', 'auto_renew': True},
                               {'domain': 'ip-01-1-1-1', 'auto_renew': True},
                               {'domain': 'example.com', 'auto_renew': True}]
    assert settings_manager.update(_add, reason='test')
    names = [entry['domain'] for entry in settings_manager.load_settings()['domains']]
    assert names == ['ip-1-1-1-1', 'example.com']


# --- the lineage repairs after a restore ----------------------------------------

def _flattened_lineage(domain_dir, name, old_dir):
    """What a backup restored elsewhere leaves: live/ holds plain files (a ZIP
    dereferences the symlinks), and the conf names the install it came from."""
    archive = domain_dir / 'archive' / name
    live = domain_dir / 'live' / name
    archive.mkdir(parents=True)
    live.mkdir(parents=True)
    for stem in ('cert', 'chain', 'fullchain', 'privkey'):
        (archive / f'{stem}1.pem').write_text(stem)
        (live / f'{stem}.pem').write_text(stem)
    (domain_dir / 'renewal').mkdir()
    (domain_dir / 'renewal' / f'{name}.conf').write_text(
        f'archive_dir = {old_dir}/archive/{name}\n'
        f'cert = {old_dir}/live/{name}/cert.pem\n'
        '[renewalparams]\npreferred_profile = shortlived\n', encoding='utf-8')


def test_a_restored_ip_lineage_is_repaired_before_it_is_renewed(tmp_path):
    """Without the repair certbot parsefails on the flattened lineage and skips
    it, so every renewal of a restored IP certificate failed (#410, #966)."""
    name = 'ip-1-1-1-1'
    domain_dir = tmp_path / 'certificates' / name
    old_dir = f'/elsewhere/certificates/{name}'
    _flattened_lineage(domain_dir, name, old_dir)

    assert repair_certbot_renewal_paths(domain_dir, name) is True
    conf = (domain_dir / 'renewal' / f'{name}.conf').read_text(encoding='utf-8')
    assert old_dir not in conf
    assert f'archive_dir = {domain_dir}/archive/{name}' in conf

    assert repair_certbot_lineage_symlinks(domain_dir, name) is True
    live_cert = domain_dir / 'live' / name / 'cert.pem'
    assert live_cert.is_symlink()
    assert os.readlink(live_cert) == f'../../archive/{name}/cert1.pem'


# --- the request an IP certificate can be issued from ------------------------------

_ASKED = {'ca_provider': 'letsencrypt', 'challenge_type': None, 'san_domains': [],
          'domain_alias': None, 'alias_dns_provider': None, 'acme_profile': None}


@pytest.mark.parametrize('changes', [
    {}, {'ca_provider': 'letsencrypt_staging'}, {'challenge_type': 'http-01'},
    {'acme_profile': 'shortlived'}, {'acme_profile': ''},
])
def test_a_request_let_s_encrypt_can_issue_is_not_refused(changes):
    assert ip_certificate_refusal(**{**_ASKED, **changes}) is None


@pytest.mark.parametrize('changes, reason', [
    ({'ca_provider': 'zerossl'}, "Let's Encrypt only"),
    ({'ca_provider': 'private_ca'}, "Let's Encrypt only"),
    ({'challenge_type': 'dns-01'}, 'HTTP-01 only'),
    ({'san_domains': ['example.com']}, 'single address'),
    ({'domain_alias': 'validation.example.org'}, 'DNS alias'),
    ({'alias_dns_provider': 'cloudflare'}, 'DNS alias'),
    ({'acme_profile': 'classic'}, "'shortlived' profile only"),
])
def test_a_request_it_cannot_issue_is_refused_with_the_reason(changes, reason):
    assert reason in ip_certificate_refusal(**{**_ASKED, **changes})

