"""The renewal sweep counts a certificate that is not due yet (#1459).

The nightly line used to read, on an ordinary night, "200 checked, 0 renewed,
0 not-due": `_renew_if_due` returned without counting when CertMate's own rule
left a certificate alone, and `skipped_not_due` counts something narrower, a
renewal CertMate asked for that certbot declined. The line suggested the
opposite of what happened. Now `not_due` counts the first and the line names
both for what they are.
"""
import logging
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from tests.test_the_threshold_means_what_it_says import DAY, _manager, _sweep

pytestmark = [pytest.mark.unit]


def test_a_certificate_far_from_expiry_is_counted_as_not_due(tmp_path):
    manager, calls = _manager(tmp_path, seconds_left=80 * DAY, age_days=10)
    summary = _sweep(manager, ['fresh.example.com'], {})
    assert calls == [], 'a certificate with 80 days left was sent to certbot'
    assert summary['not_due'] == 1
    assert summary['skipped_not_due'] == 0, (
        'certbot was never asked, so it cannot have declined')
    assert summary['renewed'] == 0


def test_a_certificate_that_is_due_is_not_counted_as_not_due(tmp_path):
    """CONTROL: a counter that went up for every certificate would pass the
    test above."""
    manager, calls = _manager(tmp_path, seconds_left=10 * DAY)
    summary = _sweep(manager, ['due.example.com'], {})
    assert calls == [('due.example.com', True)]
    assert summary['not_due'] == 0
    assert summary['renewed'] == 1


def test_a_renewal_certbot_declines_is_not_counted_as_not_due(tmp_path):
    """The two counters stay apart: a key problem makes the certificate due,
    certbot is asked unforced and says "not yet", and that is certbot's word,
    not CertMate's rule."""
    manager, calls = _manager(tmp_path, seconds_left=60 * DAY, key_state='missing')
    summary = _sweep(manager, ['key.example.com'], {})
    assert calls == [('key.example.com', False)]
    assert summary['skipped_not_due'] == 1
    assert summary['not_due'] == 0


def test_the_summary_line_names_both_counts(tmp_path, caplog):
    mgr = CertificateManager(
        cert_dir=tmp_path,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
        shell_executor=MagicMock(),
    )
    mgr.settings_manager.load_settings.return_value = {
        'auto_renew': True, 'domains': ['fresh.example.com', 'calm.example.com']}
    mgr.settings_manager.migrate_domains_format.side_effect = lambda s: s
    mgr.get_certificate_info = MagicMock(return_value={'needs_renewal': False})
    mgr.renew_certificate = MagicMock()

    with caplog.at_level(logging.INFO, logger='modules.core.certificates'):
        summary = mgr.check_renewals()

    assert summary['not_due'] == 2
    mgr.renew_certificate.assert_not_called()
    line = next(r.getMessage() for r in caplog.records
                if r.getMessage().startswith('Renewal check complete'))
    assert '2 checked' in line
    assert '2 not due yet' in line, line
    assert '0 declined by certbot' in line, line
