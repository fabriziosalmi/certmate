"""check_renewals must never skip a domain silently.

A malformed entry in settings['domains'] (a bare int, a dict with no
'domain' key, an empty domain string) used to be dropped with no
operator-visible signal, so a typo could silently exclude a domain from
automatic renewal forever. check_renewals now counts every checked /
renewed / failed / skipped entry and returns the summary.
"""

from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


def _manager(tmp_path, settings):
    mgr = CertificateManager(
        cert_dir=tmp_path,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
        shell_executor=MagicMock(),
    )
    mgr.settings_manager.load_settings.return_value = settings
    mgr.settings_manager.migrate_domains_format.side_effect = lambda s: s
    return mgr


def test_summary_counts_every_kind_of_entry(tmp_path):
    settings = {
        'auto_renew': True,
        'domains': [
            'good.com',                                   # str -> checked, needs renewal
            'fresh.com',                                  # str -> checked, no renewal
            {'domain': 'disabled.com', 'auto_renew': False},  # per-cert opt-out
            {'domain': '', 'auto_renew': True},           # empty domain -> invalid
            {'no_domain_key': True},                      # dict w/o domain -> invalid
            12345,                                        # not str/dict -> invalid
        ],
    }
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock(
        side_effect=lambda domain, **kw: {'needs_renewal': domain == 'good.com'}
    )
    mgr.renew_certificate = MagicMock()

    summary = mgr.check_renewals()

    assert summary == {
        'checked': 2,           # good.com + fresh.com
        'renewed': 1,           # good.com
        'failed': 0,
        'skipped_disabled': 1,  # disabled.com
        'skipped_invalid': 3,   # empty, dict-without-domain, int
    }
    mgr.renew_certificate.assert_called_once_with('good.com')


def test_renew_failure_is_counted_not_swallowed(tmp_path):
    settings = {'auto_renew': True, 'domains': ['boom.com']}
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock(return_value={'needs_renewal': True})
    mgr.renew_certificate = MagicMock(side_effect=RuntimeError("certbot failed"))

    summary = mgr.check_renewals()

    assert summary['checked'] == 1
    assert summary['renewed'] == 0
    assert summary['failed'] == 1


def test_global_auto_renew_disabled_short_circuits(tmp_path):
    settings = {'auto_renew': False, 'domains': ['x.com']}
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock()

    summary = mgr.check_renewals()

    assert summary['auto_renew_disabled'] is True
    mgr.get_certificate_info.assert_not_called()
