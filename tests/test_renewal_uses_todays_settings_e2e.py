"""A renewal answers its challenge with today's settings, not issue day's (#666, D6).

certbot writes the plugin options of the run that issued a certificate into
`renewal/<domain>.conf` and, at `certbot renew`, replays them unless the
command line says otherwise. CertMate's renew command said nothing about the
wait, so the propagation time chosen on the day of issue applied to every
renewal after it. Raising a provider's wait in Settings — the documented fix
for "the TXT record was not visible yet", and what v2.40.0's Akamai migration
does for #974 — changed new certificates only; the ones already failing kept
failing with the old value.

Real certbot, real Let's Encrypt staging, real Cloudflare DNS, in-process as
in test_ari_staging_e2e.py. Requires CLOUDFLARE_API_TOKEN and
CERTMATE_TEST_DOMAIN.
"""
import os
import re
import secrets
import uuid

import pytest

from tests.e2e_support import TEST_EMAIL, assert_staging_issuer

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get('CERTMATE_TEST_DOMAIN', 'gpfree.org')
TEST_DOMAIN = f'wait-e2e-{uuid.uuid4().hex[:8]}.{BASE_DOMAIN}'
ACCOUNT_ID = 'wait-e2e'
ISSUE_DAY_WAIT = 40
TODAYS_WAIT = 47
# Long enough for Cloudflare: at 11 s staging once found no TXT record yet.
# Only the issuance pays it; staging reuses the authorization at renewal.


@pytest.fixture(scope='module')
def instance(tmp_path_factory, cloudflare_token):
    """A real CertMate, in this process, pinned to Let's Encrypt staging."""
    tmp = tmp_path_factory.mktemp('wait-e2e')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
        from modules.factory import create_app
        _, container = create_app()
        managers = container.managers
        settings_manager = managers['settings']
        settings = settings_manager.load_settings()
        settings.update({
            'email': TEST_EMAIL,
            'default_ca': 'letsencrypt_staging',
            # Non-empty on purpose: an EMPTY staging entry aliases back to
            # production in ca_manager.get_ca_config (see e2e_support).
            'ca_providers': {
                'letsencrypt': {'email': TEST_EMAIL},
                'letsencrypt_staging': {'email': TEST_EMAIL},
            },
            'dns_provider': 'cloudflare',
            'dns_propagation_seconds': {'cloudflare': ISSUE_DAY_WAIT},
            'domains': [{'domain': TEST_DOMAIN, 'dns_provider': 'cloudflare',
                         'account_id': ACCOUNT_ID, 'auto_renew': True}],
        })
        assert settings_manager.save_settings(settings, 'wait-e2e') is not False
        managers['dns'].add_account(
            ACCOUNT_ID, 'cloudflare', {'api_token': cloudflare_token})
        yield managers


def _run_wait(manager):
    """The wait the latest certbot run was configured with.

    Read from certbot's own configuration dump, not from its "Waiting N
    seconds" notice: staging reuses a valid authorization for a renewal, so
    no challenge runs and nothing is announced. The configured value is what
    the renewal would have waited, and what it writes back for the next one.
    """
    log = manager.cert_dir / TEST_DOMAIN / 'logs' / 'letsencrypt.log'
    found = re.findall(r'Var dns_cloudflare_propagation_seconds=(\d+)',
                       log.read_text())
    return int(found[-1]) if found else None


def _replayed_wait(manager):
    conf = manager.cert_dir / TEST_DOMAIN / 'renewal' / f'{TEST_DOMAIN}.conf'
    found = re.search(r'^dns_cloudflare_propagation_seconds = (\d+)$',
                      conf.read_text(), re.M)
    return int(found.group(1)) if found else None


def test_01_issue_with_the_issue_day_wait(instance):
    manager = instance['certificates']
    result = manager.create_certificate(
        TEST_DOMAIN, TEST_EMAIL, 'cloudflare', account_id=ACCOUNT_ID,
        ca_provider='letsencrypt_staging')
    assert result, result
    pem = (manager.cert_dir / TEST_DOMAIN / 'cert.pem').read_text()
    print('issuer:', assert_staging_issuer(pem))
    assert _run_wait(manager) == ISSUE_DAY_WAIT
    assert _replayed_wait(manager) == ISSUE_DAY_WAIT


def test_02_a_renewal_waits_what_settings_say_today(instance):
    settings_manager = instance['settings']
    settings = settings_manager.load_settings()
    settings['dns_propagation_seconds'] = {'cloudflare': TODAYS_WAIT}
    assert settings_manager.save_settings(settings, 'wait-e2e') is not False

    manager = instance['certificates']
    manager.renew_certificate(TEST_DOMAIN, force=True)

    assert _run_wait(manager) == TODAYS_WAIT, (
        f'the renewal ran with {_run_wait(manager)} s, the value baked in on '
        f'issue day, not the {TODAYS_WAIT} s Settings say today')
    # And certbot records today's value for the renewal after this one.
    assert _replayed_wait(manager) == TODAYS_WAIT
