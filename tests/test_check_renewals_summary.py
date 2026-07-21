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
        'skipped_not_due': 0,   # certbot didn't report any "not yet due" no-op
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


# --- #329: scheduled renewals must fire deploy hooks ----------------------
# The deployer listens for 'certificate_renewed' on the event bus. The
# manual/API path publishes it via the IssuanceExecutor; the scheduler calls
# renew_certificate() directly, so check_renewals has to publish it itself or
# background renewals silently skip every deploy hook.

def test_successful_scheduled_renewal_publishes_certificate_renewed(tmp_path):
    settings = {'auto_renew': True, 'domains': ['good.com', 'fresh.com']}
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock(
        side_effect=lambda domain, **kw: {'needs_renewal': domain == 'good.com'}
    )
    mgr.renew_certificate = MagicMock()
    bus = MagicMock()
    mgr.set_event_bus(bus)

    mgr.check_renewals()

    # Exactly the renewed domain, with the same payload the executor emits —
    # not fresh.com (no renewal) and not a duplicate.
    bus.publish.assert_called_once_with(
        'certificate_renewed', {'domain': 'good.com'}
    )


def test_failed_scheduled_renewal_does_not_publish_renewed(tmp_path):
    """A failure must not fire deploy hooks (#329) — but must notify (#417).

    This test originally asserted publish() was never called at all. That
    over-specified the rule: the point is that `certificate_renewed`, which
    the deployer listens for, must not fire on a failure. `certificate_failed`
    firing is exactly what reaches the operator's email/Slack.
    """
    settings = {'auto_renew': True, 'domains': ['boom.com']}
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock(return_value={'needs_renewal': True})
    mgr.renew_certificate = MagicMock(side_effect=RuntimeError("certbot failed"))
    bus = MagicMock()
    mgr.set_event_bus(bus)

    summary = mgr.check_renewals()

    assert summary['failed'] == 1
    published = [c.args[0] for c in bus.publish.call_args_list]
    assert 'certificate_renewed' not in published
    assert published == ['certificate_failed']


def test_scheduled_renewal_without_event_bus_does_not_crash(tmp_path):
    settings = {'auto_renew': True, 'domains': ['good.com']}
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock(return_value={'needs_renewal': True})
    mgr.renew_certificate = MagicMock()
    # No set_event_bus() call — standalone/unit default.

    summary = mgr.check_renewals()

    assert summary['renewed'] == 1


def test_publish_failure_does_not_fail_the_renewal(tmp_path):
    settings = {'auto_renew': True, 'domains': ['good.com']}
    mgr = _manager(tmp_path, settings)
    mgr.get_certificate_info = MagicMock(return_value={'needs_renewal': True})
    mgr.renew_certificate = MagicMock()
    bus = MagicMock()
    bus.publish.side_effect = RuntimeError("event bus down")
    mgr.set_event_bus(bus)

    summary = mgr.check_renewals()

    # A notification failure must not turn a successful renewal into a failure.
    assert summary['renewed'] == 1
    assert summary['failed'] == 0
