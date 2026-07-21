"""A failed unattended renewal must reach the operator's notification channels.

Regression test for #417. The scheduler audited and logged a failed renewal
but never published ``certificate_failed`` — the event the notifier turns into
an email or a Slack message, and a selectable event in the notifications UI.
The manual/API path (resources.py) and the async executor (cert_jobs.py) both
published it; only the path that runs unattended at 02:00, i.e. the one nobody
is watching, did not.

Concretely: a certificate whose DNS credentials were rotated failed to renew
every night for 30 days and the operator heard nothing until it expired.
"""

from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager


pytestmark = [pytest.mark.unit]


def _make_manager(tmp_path, domains, event_bus):
    settings_mgr = MagicMock()
    payload = {
        'auto_renew': True,
        'domains': [{'domain': d, 'auto_renew': True} for d in domains],
    }
    settings_mgr.load_settings.side_effect = lambda: dict(payload)
    settings_mgr.migrate_domains_format.side_effect = lambda s: s
    settings_mgr.get_domain_dns_provider.return_value = 'cloudflare'

    mgr = CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
    )
    # Public wiring API, same as the factory uses in production.
    if event_bus is not None:
        mgr.set_event_bus(event_bus)
    return mgr


def _published(bus, event):
    return [c.args[1] for c in bus.publish.call_args_list if c.args[0] == event]


def test_failed_scheduled_renewal_publishes_certificate_failed(tmp_path):
    bus = MagicMock()
    mgr = _make_manager(tmp_path, ['fail.example.com'], bus)
    mgr.get_certificate_info = lambda domain, settings=None, use_cache=True: {
        'domain': domain, 'exists': True, 'needs_renewal': True,
    }

    def boom(domain, force=False):
        raise RuntimeError('DNS credentials rejected')

    mgr.renew_certificate = boom

    summary = mgr.check_renewals()

    assert summary['failed'] == 1
    payloads = _published(bus, 'certificate_failed')
    assert len(payloads) == 1, "the operator would never hear about this failure"
    assert payloads[0]['domain'] == 'fail.example.com'
    assert 'DNS credentials rejected' in payloads[0]['error']


def test_successful_scheduled_renewal_does_not_publish_a_failure(tmp_path):
    bus = MagicMock()
    mgr = _make_manager(tmp_path, ['ok.example.com'], bus)
    mgr.get_certificate_info = lambda domain, settings=None, use_cache=True: {
        'domain': domain, 'exists': True, 'needs_renewal': True,
    }
    mgr.renew_certificate = lambda domain, force=False: {'renewed': True}

    mgr.check_renewals()

    assert _published(bus, 'certificate_failed') == []
    assert len(_published(bus, 'certificate_renewed')) == 1


def test_not_yet_due_is_not_reported_as_a_failure(tmp_path):
    """certbot's "not yet due" is a retry, not a failure — no alert."""
    bus = MagicMock()
    mgr = _make_manager(tmp_path, ['soon.example.com'], bus)
    mgr.get_certificate_info = lambda domain, settings=None, use_cache=True: {
        'domain': domain, 'exists': True, 'needs_renewal': True,
    }
    mgr.renew_certificate = lambda domain, force=False: {'renewed': False}

    summary = mgr.check_renewals()

    assert summary['skipped_not_due'] == 1
    assert _published(bus, 'certificate_failed') == []


def test_failure_while_checking_is_attributed_to_the_right_domain(tmp_path):
    """The outer except must not blame the previous iteration's domain."""
    bus = MagicMock()
    mgr = _make_manager(tmp_path, ['first.example.com', 'second.example.com'], bus)

    def info(domain, settings=None, use_cache=True):
        if domain == 'second.example.com':
            raise ValueError('unreadable metadata')
        return {'domain': domain, 'exists': True, 'needs_renewal': False}

    mgr.get_certificate_info = info

    summary = mgr.check_renewals()

    assert summary['failed'] == 1
    payloads = _published(bus, 'certificate_failed')
    assert [p['domain'] for p in payloads] == ['second.example.com']


def test_no_event_bus_is_not_an_error(tmp_path):
    """Notification wiring is optional; its absence must not break renewal."""
    mgr = _make_manager(tmp_path, ['fail.example.com'], None)
    mgr.get_certificate_info = lambda domain, settings=None, use_cache=True: {
        'domain': domain, 'exists': True, 'needs_renewal': True,
    }

    def boom(domain, force=False):
        raise RuntimeError('nope')

    mgr.renew_certificate = boom

    summary = mgr.check_renewals()
    assert summary['failed'] == 1


def test_a_broken_notifier_never_turns_into_a_renewal_error(tmp_path):
    """publish() raising must not escape check_renewals."""
    bus = MagicMock()
    bus.publish.side_effect = RuntimeError('smtp down')
    mgr = _make_manager(tmp_path, ['fail.example.com'], bus)
    mgr.get_certificate_info = lambda domain, settings=None, use_cache=True: {
        'domain': domain, 'exists': True, 'needs_renewal': True,
    }

    def boom(domain, force=False):
        raise RuntimeError('nope')

    mgr.renew_certificate = boom

    summary = mgr.check_renewals()
    assert summary['failed'] == 1
