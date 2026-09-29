"""Opt-in: the sweep reissues certificates that lost their key (#966, step 4).

Decision recorded on #966: never by default, since a reissue changes the key
and after a share-safe restore of N certificates a silent reissue would be N
orders in one night. For unattended instances, `auto_reissue_keyless: true`
lets the sweep do it itself, under a per-sweep cap
(`auto_reissue_keyless_per_sweep`, default 5), with the same traces a renewal
leaves: an audit record and `certificate_renewed`, so deploy hooks ship the
new key and certificate.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager, ReissueRequired

pytestmark = [pytest.mark.unit]


def _manager(tmp_path, *, reissue_fails=()):
    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    manager.get_certificate_info = MagicMock(return_value={
        'exists': True, 'needs_renewal': True, 'private_key_state': 'missing'})
    manager.renew_certificate = MagicMock(side_effect=lambda d, force=False: (_ for _ in ()).throw(ReissueRequired(d)))
    reissued = []

    def reissue(domain):
        if domain in reissue_fails:
            raise RuntimeError('Certificate creation failed: rateLimited')
        reissued.append(domain)
        return {'success': True}

    manager._reissue_from_metadata = MagicMock(side_effect=reissue)
    manager._audit_scheduled_renew = MagicMock()
    manager._record_renewal_metrics = MagicMock()
    manager._publish_failed_event = MagicMock()
    manager._publish_renewed_event = MagicMock()
    return manager, reissued


def _summary():
    return {'checked': 0, 'renewed': 0, 'failed': 0, 'skipped_busy': 0,
            'skipped_not_due': 0, 'ari_advanced': 0, 'reissue_required': 0,
            'auto_reissued': 0}


def _sweep(manager, domains, settings):
    summary = _summary()
    for d in domains:
        manager._renew_if_due(d, settings, summary)
    return summary


def test_off_by_default_nothing_is_reissued(tmp_path):
    """THE control that matters most: the default is the decision."""
    manager, reissued = _manager(tmp_path)
    summary = _sweep(manager, ['a.example.com'], {})

    assert reissued == []
    assert summary['reissue_required'] == 1 and summary['auto_reissued'] == 0
    manager._publish_failed_event.assert_called_once()


def test_when_enabled_it_reissues_and_leaves_a_renewal_s_traces(tmp_path):
    manager, reissued = _manager(tmp_path)
    summary = _sweep(manager, ['a.example.com'], {'auto_reissue_keyless': True})

    assert reissued == ['a.example.com']
    assert summary['auto_reissued'] == 1 and summary['reissue_required'] == 0
    manager._publish_renewed_event.assert_called_once_with('a.example.com')
    status = manager._audit_scheduled_renew.call_args.args[1]
    details = manager._audit_scheduled_renew.call_args.kwargs.get('details')
    assert status == 'success' and details == {'auto_reissue_keyless': True}
    manager._publish_failed_event.assert_not_called()


def test_the_cap_holds_and_the_rest_wait_for_the_next_sweep(tmp_path):
    """The pace: N restored certificates must not be N orders in one night."""
    manager, reissued = _manager(tmp_path)
    domains = [f'd{i}.example.com' for i in range(5)]
    summary = _sweep(manager, domains, {'auto_reissue_keyless': True,
                                        'auto_reissue_keyless_per_sweep': 2})

    assert reissued == ['d0.example.com', 'd1.example.com']
    assert summary['auto_reissued'] == 2 and summary['reissue_required'] == 3


@pytest.mark.parametrize('raw, expected', [(0, 1), (-3, 1), (999, 50), ('x', 5), (None, 5)])
def test_the_cap_is_clamped_not_obeyed(raw, expected):
    """A typo must not mean 'reissue everything tonight' nor 'never'."""
    assert CertificateManager._auto_reissue_cap(
        {'auto_reissue_keyless_per_sweep': raw}) == expected


def test_a_reissue_that_fails_is_reported_as_the_state_it_left(tmp_path):
    manager, _reissued = _manager(tmp_path, reissue_fails={'a.example.com'})
    summary = _sweep(manager, ['a.example.com'], {'auto_reissue_keyless': True})

    assert summary['auto_reissued'] == 0
    assert summary['reissue_required'] == 1
    manager._publish_failed_event.assert_called_once()
    manager._publish_renewed_event.assert_not_called()


def test_the_reissue_uses_the_configuration_the_metadata_records(tmp_path):
    """What Edit & Reissue would send unchanged, read from metadata.json,
    which a share-safe backup keeps."""
    import json

    (tmp_path / 'a.example.com').mkdir()
    (tmp_path / 'a.example.com' / 'metadata.json').write_text(json.dumps({
        'domain': 'a.example.com', 'email': 'ops@example.com',
        'dns_provider': 'route53', 'account_id': 'prod', 'ca_provider': 'letsencrypt',
        'ca_account_id': None, 'domain_alias': '_acme.alias.example.net',
        'alias_dns_provider': 'cloudflare', 'challenge_type': 'dns-01',
        'san_domains': ['www.a.example.com']}))
    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    manager.settings_manager = MagicMock()
    manager.create_certificate = MagicMock(return_value={'success': True})

    manager._reissue_from_metadata('a.example.com')

    kwargs = manager.create_certificate.call_args.kwargs
    assert kwargs == {
        'domain': 'a.example.com', 'email': 'ops@example.com',
        'dns_provider': 'route53', 'account_id': 'prod', 'ca_provider': 'letsencrypt',
        'ca_account_id': None, 'domain_alias': '_acme.alias.example.net',
        'alias_dns_provider': 'cloudflare', 'challenge_type': 'dns-01',
        'san_domains': ['www.a.example.com'], 'replace': True}


def test_a_defect_in_the_reissue_surfaces_instead_of_reading_as_a_failed_reissue(tmp_path):
    """Only what a reissue raises when it does not happen (RuntimeError,
    ValueError, OSError) is absorbed. A TypeError is a bug, and reports as one
    through the sweep's own handler."""
    manager, _reissued = _manager(tmp_path)
    manager._reissue_from_metadata.side_effect = TypeError('a bug')

    with pytest.raises(TypeError):
        _sweep(manager, ['a.example.com'], {'auto_reissue_keyless': True})
