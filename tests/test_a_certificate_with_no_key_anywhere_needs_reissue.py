"""A certificate with no private key anywhere says "reissue required" (#966).

Restoring a share-safe backup brings certificates back without any private
key: not the served privkey.pem, not live/, not archive/privkeyN.pem. Measured
on Let's Encrypt staging (#966): certbot cannot even read such a lineage, so
every renewal attempt was a generic "1 parse failure" every night, and the only
repair is a reissue. The decision recorded on #966: no automatic reissue by
default, but a precise state instead of a generic failure. The renewal path
now stops before certbot and says what to do, with its own code for the API
and its own counter in the sweep.

Scenarios A (only the served copy missing) and C (served copy from another
issuance) are NOT this: certbot still holds the key in live/ or archive/, and
the ordinary renewal path already repairs them, measured the same day.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager, ReissueRequired
from modules.core.shell import MockShellExecutor
from modules.core.utils import classify_renewal_error

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'


def _lineage(tmp_path, *, flat_key=False, archive_key=False):
    d = tmp_path / DOMAIN
    (d / 'renewal').mkdir(parents=True)
    (d / 'renewal' / f'{DOMAIN}.conf').write_text('version = 2.10.0\n')
    archive = d / 'archive' / DOMAIN
    archive.mkdir(parents=True)
    for stem in ('cert', 'chain', 'fullchain'):
        (archive / f'{stem}1.pem').write_text(stem)
    if archive_key:
        (archive / 'privkey1.pem').write_text('key')
    (d / 'cert.pem').write_text('cert')
    if flat_key:
        (d / 'privkey.pem').write_text('key')
    (d / 'metadata.json').write_text('{"domain": "%s", "dns_provider": "cloudflare"}' % DOMAIN)
    return d


def _manager(tmp_path, shell):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {'challenge_type': 'dns-01'}
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')
    return CertificateManager(cert_dir=tmp_path, settings_manager=settings_mgr,
                              dns_manager=dns_mgr, storage_manager=None,
                              ca_manager=None, shell_executor=shell)


def test_no_key_anywhere_stops_before_certbot_and_says_reissue(tmp_path):
    """THE regression: scenario B, the share-safe restore."""
    _lineage(tmp_path)
    shell = MockShellExecutor()
    manager = _manager(tmp_path, shell)

    with pytest.raises(ReissueRequired) as raised:
        manager.renew_certificate(DOMAIN)

    assert shell.commands_executed == [], 'certbot was asked to renew a lineage with no key'
    assert 'reissue' in str(raised.value).lower()


@pytest.mark.parametrize('layout', [{'flat_key': True}, {'archive_key': True}])
def test_a_key_certbot_can_still_reach_is_left_to_the_ordinary_path(tmp_path, layout):
    """CONTROL: scenarios A and C self-heal through the renewal path, measured
    on LE staging. Taking them away from it would be a regression."""
    _lineage(tmp_path, **layout)
    shell = MockShellExecutor()
    manager = _manager(tmp_path, shell)

    try:
        manager.renew_certificate(DOMAIN)
    except ReissueRequired:
        pytest.fail('a recoverable key was reported as reissue-required')
    except Exception:
        pass  # the mock certbot's own outcome is not what this asserts
    assert shell.commands_executed, 'certbot was not reached'


def test_the_sweep_counts_it_and_says_what_to_do(tmp_path):
    _lineage(tmp_path)
    manager = _manager(tmp_path, MockShellExecutor())
    manager.get_certificate_info = MagicMock(return_value={
        'exists': True, 'needs_renewal': True, 'private_key_state': 'missing'})
    manager._audit_scheduled_renew = MagicMock()
    manager._record_renewal_metrics = MagicMock()
    manager._publish_failed_event = MagicMock()
    manager._publish_renewed_event = MagicMock()
    summary = {'checked': 0, 'renewed': 0, 'failed': 0, 'skipped_busy': 0,
               'skipped_not_due': 0, 'ari_advanced': 0, 'reissue_required': 0}

    assert manager._renew_if_due(DOMAIN, {}, summary) is False

    assert summary['reissue_required'] == 1
    assert summary['failed'] == 0, 'a known state is not a failure'
    manager._publish_failed_event.assert_called_once()
    assert 'reissue' in str(manager._publish_failed_event.call_args.args[1]).lower()


def test_the_api_gets_its_own_code():
    message, code = classify_renewal_error(str(ReissueRequired(DOMAIN)))
    assert code == 'REISSUE_REQUIRED'
    assert 'reissue' in message.lower()
