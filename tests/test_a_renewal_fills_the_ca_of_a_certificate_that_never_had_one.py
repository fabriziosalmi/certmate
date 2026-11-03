"""A certificate issued before `ca_provider` existed gets it from its renewal (#1383).

The scheduled renewal runs `certbot renew` on the existing lineage and only
stamped `renewed_at` on the metadata it found, so a certificate created before
the field existed kept it empty however often it renewed, and the inventory kept
saying it was issued before CertMate stored it. The CA that renews it is the
`server` in its own renewal configuration; it is recorded when that server is a
directory the registry pins, and never guessed from the default CA.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.ca_manager import CAManager
from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'old.example.com'
LE = 'https://acme-v02.api.letsencrypt.org/directory'
LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
GOOGLE = 'https://dv.acme-v02.api.pki.goog/directory'
GOOGLE_STAGING = 'https://dv.acme-v02.test-api.pki.goog/directory'


def _manager(tmp_path):
    settings = MagicMock()
    # The default CA is deliberately not the one the lineage names: a fill
    # taken from it would be wrong here, and the tests would show it.
    settings.load_settings.return_value = {'default_ca': 'zerossl'}
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=settings, dns_manager=MagicMock(),
        storage_manager=None, ca_manager=None, shell_executor=MockShellExecutor())


def _renew(manager, tmp_path, metadata, server):
    domain_dir = tmp_path / DOMAIN
    (domain_dir / 'renewal').mkdir(parents=True)
    if server is not None:
        (domain_dir / 'renewal' / f'{DOMAIN}.conf').write_text(
            f'version = 4.0.0\n[renewalparams]\nauthenticator = dns-cloudflare\nserver = {server}\n')
    saved = {}

    def commit(domain, cert_files, meta, **kwargs):
        saved.update(meta)

    with patch.object(CertificateManager, '_publish_flat_files', return_value={}), \
            patch.object(CertificateManager, '_commit_certificate', side_effect=commit):
        manager._publish_renewed_certificate(DOMAIN, domain_dir, metadata)
    return saved


def test_a_certificate_without_a_ca_gets_the_one_its_lineage_renews_at(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path, {'domain': DOMAIN}, LE)

    assert saved['ca_provider'] == 'letsencrypt'
    assert 'renewed_at' in saved


def test_the_staging_directory_names_the_staging_provider(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path, {'domain': DOMAIN}, LE_STAGING)

    assert saved['ca_provider'] == 'letsencrypt_staging'


def test_a_provider_whose_staging_directory_is_its_own_is_named_and_flagged_staging(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path, {'domain': DOMAIN}, GOOGLE_STAGING)

    assert saved['ca_provider'] == 'google'
    assert saved['staging'] is True


def test_a_production_directory_does_not_flag_staging(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path, {'domain': DOMAIN}, GOOGLE)

    assert saved['ca_provider'] == 'google'
    assert 'staging' not in saved


def test_a_directory_the_registry_does_not_pin_is_left_unnamed(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path, {'domain': DOMAIN},
                   'https://ca.internal.example/acme/directory')

    assert 'ca_provider' not in saved


def test_a_lineage_without_a_server_is_left_unnamed_not_given_the_default_ca(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path, {'domain': DOMAIN}, None)

    assert 'ca_provider' not in saved


def test_a_ca_already_recorded_is_not_overwritten(tmp_path):
    saved = _renew(_manager(tmp_path), tmp_path,
                   {'domain': DOMAIN, 'ca_provider': 'zerossl'}, LE)

    assert saved['ca_provider'] == 'zerossl'


def test_only_a_pinned_directory_names_a_provider():
    manager = CAManager(MagicMock())

    assert manager.provider_for_directory(LE + '/') == 'letsencrypt'
    assert manager.provider_for_directory('') is None
    assert manager.provider_for_directory('custom') is None
    # DigiCert's directory is regional, an account may override it: not matched.
    assert manager.provider_for_directory(
        manager.ca_providers['digicert']['production_url']) is None
