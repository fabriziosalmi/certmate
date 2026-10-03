"""ACME profiles (#395): required at issuance, preferred at renewal, and never a silent change.

modules/core/acme_profiles.py says why each half is the way it is. These hold the pieces: the
name check, what a CA's directory offers, the renewal configuration certbot writes softened from
required to preferred, the profile a certificate is issued, reissued and renewed with, and the
renewal that finds its CA no longer offers it.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from modules.core import acme_profiles
from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'profile.example.com'


# --- the pieces -----------------------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    ('tlsserver', (True, 'tlsserver')),
    (' ShortLived ', (True, 'shortlived')),
    (None, (True, None)),
    ('', (True, None)),
])
def test_a_profile_name_is_normalized(value, expected):
    assert acme_profiles.validate_profile(value) == expected


@pytest.mark.parametrize('value', ['--server', 'a b', 'tls/server', 'x' * 65, 42, ['classic'], '\n'])
def test_anything_that_is_not_a_profile_name_is_refused(value):
    """It reaches a certbot argument list and a configuration file."""
    ok, _reason = acme_profiles.validate_profile(value)
    assert ok is False


def test_what_a_directory_offers():
    directory = {'meta': {'profiles': {'classic': 'u', 'tlsserver': 'u', 'shortlived': 'u'}}}
    assert acme_profiles.profiles_offered(directory) == ['classic', 'shortlived', 'tlsserver']
    assert acme_profiles.profile_offered(directory, 'tlsserver') is True
    assert acme_profiles.profile_offered(directory, 'tlsclient') is False
    assert acme_profiles.profile_offered({'meta': {}}, 'tlsserver') is False   # a CA with none
    assert acme_profiles.profile_offered(None, 'tlsserver') is None             # not read


CONF = """version = 5.8.0
archive_dir = /certs/profile.example.com/archive/profile.example.com
[renewalparams]
account = 0123456789abcdef
server = https://acme-staging-v02.api.letsencrypt.org/directory
authenticator = dns-cloudflare
key_type = ecdsa
required_profile = tlsserver
"""


def test_the_renewal_configuration_is_softened_to_preferred(tmp_path):
    conf = tmp_path / 'profile.example.com.conf'
    conf.write_text(CONF)

    assert acme_profiles.soften_renewal_conf(conf) == 'tlsserver'
    text = conf.read_text()
    assert 'required_profile' not in text
    assert 'preferred_profile = tlsserver\n' in text
    assert text.replace('preferred_profile', 'required_profile') == CONF, 'only that line changed'
    assert acme_profiles.soften_renewal_conf(conf) is None, 'a second pass changes nothing'
    assert not list(tmp_path.glob('*.profile-tmp'))


def test_an_older_preferred_line_does_not_survive_beside_the_new_one(tmp_path):
    conf = tmp_path / 'x.conf'
    conf.write_text(CONF.replace('key_type = ecdsa\n', 'key_type = ecdsa\npreferred_profile = classic\n'))
    acme_profiles.soften_renewal_conf(conf)
    text = conf.read_text()
    assert text.count('preferred_profile') == 1 and 'preferred_profile = tlsserver' in text


def test_the_lines_around_it_are_left_alone(tmp_path):
    """The first version matched `\\s*$` and took the line break, and a blank line after it."""
    conf = tmp_path / 'x.conf'
    text = CONF.replace('required_profile = tlsserver\n', 'required_profile = tlsserver\n\n[[webroot_map]]\n')
    conf.write_text(text)
    acme_profiles.soften_renewal_conf(conf)
    assert conf.read_text() == text.replace('required_profile', 'preferred_profile')


def test_a_missing_configuration_is_nothing_to_soften(tmp_path):
    assert acme_profiles.soften_renewal_conf(tmp_path / 'absent.conf') is None


# --- issuance -------------------------------------------------------------------------------

def _manager(tmp_path, metadata=None):
    settings = MagicMock()
    settings.load_settings.return_value = {'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
                                           'dns_propagation_seconds': {'cloudflare': 1}}
    settings.get_domain_dns_provider.return_value = 'cloudflare'
    dns = MagicMock()
    dns.get_dns_provider_account_config.return_value = ({'api_token': 'cf'}, 'default')
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings, dns_manager=dns,
                                 storage_manager=None, ca_manager=None, shell_executor=shell)
    if metadata is not None:
        (tmp_path / DOMAIN).mkdir(exist_ok=True)
        (tmp_path / DOMAIN / 'metadata.json').write_text(json.dumps(metadata))
    return manager, shell


def _argv(shell):
    return shell.commands_executed[-1].split()


def _the_profile_flag(argv):
    for flag in ('--required-profile', '--preferred-profile'):
        if flag in argv:
            return flag, argv[argv.index(flag) + 1]
    return None


def test_an_issuance_records_the_profile_and_softens_what_certbot_wrote(tmp_path):
    manager, shell = _manager(tmp_path)
    renewal = tmp_path / DOMAIN / 'renewal'
    renewal.mkdir(parents=True)
    (renewal / f'{DOMAIN}.conf').write_text(CONF)        # what certbot writes during the run

    manager.create_certificate(DOMAIN, 'a@b.com', 'cloudflare', acme_profile='tlsserver')

    assert _the_profile_flag(_argv(shell)) == ('--required-profile', 'tlsserver')
    assert manager._load_metadata(DOMAIN)['acme_profile'] == 'tlsserver'
    assert 'preferred_profile = tlsserver' in (renewal / f'{DOMAIN}.conf').read_text()


def test_no_profile_sends_no_flag_and_records_none(tmp_path):
    manager, shell = _manager(tmp_path)
    manager.create_certificate(DOMAIN, 'a@b.com', 'cloudflare')
    assert _the_profile_flag(_argv(shell)) is None
    assert 'acme_profile' not in manager._load_metadata(DOMAIN)


def test_a_reissue_keeps_the_profile_it_was_issued_with(tmp_path):
    """Editing a SAN must not quietly change what kind of certificate it is."""
    manager, shell = _manager(tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare',
                                         'acme_profile': 'shortlived'})
    manager.create_certificate(DOMAIN, 'a@b.com', 'cloudflare', replace=True)
    assert _the_profile_flag(_argv(shell)) == ('--required-profile', 'shortlived')
    assert manager._load_metadata(DOMAIN)['acme_profile'] == 'shortlived'


def test_a_reissue_that_asks_for_the_ca_default_clears_it(tmp_path):
    manager, shell = _manager(tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare',
                                         'acme_profile': 'shortlived',
                                         'acme_profile_withdrawn_at': '2026-09-30T03:00:00'})
    manager.create_certificate(DOMAIN, 'a@b.com', 'cloudflare', replace=True, acme_profile='')
    assert _the_profile_flag(_argv(shell)) is None
    kept = manager._load_metadata(DOMAIN)
    assert 'acme_profile' not in kept and 'acme_profile_withdrawn_at' not in kept


@pytest.mark.parametrize('requested, replace, recorded, account, expected', [
    (None, False, None, {'acme_profile': 'tlsserver'}, 'tlsserver'),    # the account's default
    (None, False, 'shortlived', {}, None),                                # a new one ignores disk
    (None, True, 'shortlived', {'acme_profile': 'tlsserver'}, 'shortlived'),
    ('classic', True, 'shortlived', {'acme_profile': 'tlsserver'}, 'classic'),
    ('', False, None, {'acme_profile': 'tlsserver'}, None),               # explicitly the CA's
])
def test_which_profile_an_issuance_asks_for(tmp_path, requested, replace, recorded, account, expected):
    manager, _shell = _manager(tmp_path, {'acme_profile': recorded} if recorded else None)
    assert manager._resolve_acme_profile(DOMAIN, replace, requested, account) == expected


def test_a_malformed_account_default_is_refused_at_issuance(tmp_path):
    manager, _shell = _manager(tmp_path)
    with pytest.raises(ValueError):
        manager._resolve_acme_profile(DOMAIN, False, None, {'acme_profile': '--server x'})


def test_a_csr_renewal_asks_for_its_profile_as_preferred(tmp_path):
    """A CSR certificate renews by re-running issuance (replace + renewal)."""
    manager, shell = _manager(tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare',
                                         'acme_profile': 'tlsserver'})
    manager.create_certificate(DOMAIN, 'a@b.com', 'cloudflare', replace=True, renewal=True)
    assert _the_profile_flag(_argv(shell)) == ('--preferred-profile', 'tlsserver')


# --- renewal --------------------------------------------------------------------------------

def _renew(tmp_path, metadata, directory):
    manager, shell = _manager(tmp_path, metadata)
    (tmp_path / DOMAIN / 'cert.pem').write_text('certificate')
    renewal = tmp_path / DOMAIN / 'renewal'
    renewal.mkdir(exist_ok=True)
    (renewal / f'{DOMAIN}.conf').write_text(CONF)        # an older lineage: still required
    manager._acme_directory_url = lambda info: 'https://ca.example.test/directory'
    manager._ari_client = MagicMock(directory=MagicMock(return_value=directory))
    published = {}
    with patch.object(CertificateManager, '_renewal_happened', return_value=True), \
            patch.object(CertificateManager, '_publish_renewed_certificate',
                         side_effect=lambda d, _dir, md: published.update(md)):
        manager.renew_certificate(DOMAIN, force=True)
    return _argv(shell), published, (renewal / f'{DOMAIN}.conf').read_text()


OFFERS = {'meta': {'profiles': {'classic': 'u', 'tlsserver': 'u'}}}
WITHDRAWN = {'meta': {'profiles': {'classic': 'u'}}}


def test_a_renewal_asks_for_its_profile_as_preferred(tmp_path):
    argv, published, conf = _renew(tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare',
                                              'acme_profile': 'tlsserver'}, OFFERS)
    assert _the_profile_flag(argv) == ('--preferred-profile', 'tlsserver')
    assert 'required_profile' not in conf, 'certbot would restore it and require the profile'
    assert 'acme_profile_withdrawn_at' not in published


def test_a_withdrawn_profile_is_said_and_recorded(tmp_path, caplog):
    with caplog.at_level('WARNING', logger='modules.core.certificates'):
        argv, published, _conf = _renew(
            tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare', 'acme_profile': 'tlsserver'},
            WITHDRAWN)
    assert _the_profile_flag(argv) == ('--preferred-profile', 'tlsserver')
    assert published.get('acme_profile_withdrawn_at')
    assert any('no longer offers' in record.getMessage() for record in caplog.records)


def test_a_profile_offered_again_clears_the_record(tmp_path):
    published = _renew(
        tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare', 'acme_profile': 'tlsserver',
                   'acme_profile_withdrawn_at': '2026-09-30T03:00:00'}, OFFERS)[1]
    assert 'acme_profile_withdrawn_at' not in published


def test_a_directory_that_cannot_be_read_changes_nothing_recorded(tmp_path):
    """Not evidence either way: the record stays as it was."""
    published = _renew(
        tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare', 'acme_profile': 'tlsserver',
                   'acme_profile_withdrawn_at': '2026-09-30T03:00:00'}, None)[1]
    assert published.get('acme_profile_withdrawn_at') == '2026-09-30T03:00:00'


def test_a_renewal_without_a_profile_sends_none(tmp_path):
    argv, _published, _conf = _renew(tmp_path, {'domain': DOMAIN, 'dns_provider': 'cloudflare'}, OFFERS)
    assert _the_profile_flag(argv) is None


# --- where a profile is chosen ------------------------------------------------------------

def _ca_account_client(settings):
    from flask import Flask

    from modules.web.settings_routes import register_settings_routes

    app = Flask(__name__)
    store = MagicMock()
    store.load_settings.side_effect = lambda: settings
    store.update.side_effect = lambda mutate, reason: (mutate(settings) or True)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda fn: fn
    register_settings_routes(app, {}, None, auth, store, MagicMock())
    return app.test_client()


def test_a_ca_account_names_a_default_profile_and_can_clear_it():
    settings = {'default_ca': 'letsencrypt', 'domains': []}
    client = _ca_account_client(settings)
    url = '/api/web/settings/ca-providers/letsencrypt/accounts/short'

    assert client.post(url, json={'email': 'a@b.com', 'acme_profile': 'ShortLived'}).status_code == 200
    account = settings['ca_providers']['letsencrypt']['accounts']['short']
    assert account['acme_profile'] == 'shortlived'

    assert client.post(url, json={'email': 'a@b.com', 'acme_profile': '--server evil'}).status_code == 400
    assert account['acme_profile'] == 'shortlived', 'a refused value changes nothing'

    assert client.post(url, json={'email': 'a@b.com', 'acme_profile': ''}).status_code == 200
    assert 'acme_profile' not in settings['ca_providers']['letsencrypt']['accounts']['short']


def test_a_malformed_profile_in_a_create_request_is_a_400_before_anything_runs():
    from modules.core.cert_service import _checked_profile

    assert _checked_profile(None) is None and _checked_profile('') == ''
    assert _checked_profile('TLSServer') == 'tlsserver'
    with pytest.raises(ValueError):
        _checked_profile('tls server')
