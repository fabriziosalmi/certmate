"""Renewal telemetry must actually be emitted, not merely defined.

The collector has always exposed `certmate_background_job_last_run_timestamp`,
`certmate_certificate_renewals_total` and the renewal duration histogram, but
nothing in the application ever called the `record_*` methods that feed them.
Every one of those series was permanently empty, so the single alert an
operator most needs for a certificate manager — "the renewal sweep has not run
in N days" / "renewals are failing" — could not be written: a scheduler that
had silently stopped looked exactly like one that was working.

These tests assert the signals move on the real code paths (#649).
"""
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from prometheus_client import REGISTRY

from modules.core import factory
from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

LAST_RUN = 'certmate_background_job_last_run_timestamp'
RENEWALS = 'certmate_certificate_renewals_total'
ACME_ERRORS = 'certmate_acme_errors_total'


def _sample(name, labels):
    return REGISTRY.get_sample_value(name, labels)


def _run_job(manager, key='certificates', method='check_renewals'):
    app = Flask(__name__)
    app.config['MANAGERS'] = {key: manager}
    with patch.object(factory, '_flask_app', app):
        factory._run_manager_job(key, method)


# --------------------------------------------------------------------------
# The scheduled-job wrapper stamps that the sweep ran
# --------------------------------------------------------------------------

def test_a_scheduled_job_stamps_its_last_run_timestamp():
    labels = {'job_type': 'certificates.check_renewals'}
    before = _sample(LAST_RUN, labels)
    _run_job(MagicMock())
    after = _sample(LAST_RUN, labels)

    assert after is not None, (
        "the renewal sweep ran but left no last-run timestamp — an operator "
        "cannot distinguish a working scheduler from a dead one"
    )
    if before is not None:
        assert after >= before


def test_a_failing_job_still_stamps_that_it_ran():
    """CONTROL: liveness and success are different questions.

    A sweep that raised still *ran*; the failure counters say it failed. If
    only successful runs stamped, a permanently-failing scheduler would be
    indistinguishable from a stopped one.
    """
    labels = {'job_type': 'certificates.check_renewals'}
    _run_job(MagicMock())
    before = _sample(LAST_RUN, labels)

    failing = MagicMock()
    failing.check_renewals.side_effect = RuntimeError("sweep exploded")
    _run_job(failing)

    after = _sample(LAST_RUN, labels)
    assert after > before, "a failed sweep must still record that it executed"


# --------------------------------------------------------------------------
# check_renewals records the outcome of each renewal
# --------------------------------------------------------------------------

def _mgr_with_one_due_domain(tmp_path, domain):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'auto_renew': True,
        'domains': [{'domain': domain, 'auto_renew': True}],
    }
    # check_renewals passes settings through migrate_domains_format; a bare
    # MagicMock there would swallow the domain list and the loop would see
    # nothing to renew.
    settings_mgr.migrate_domains_format.side_effect = lambda s: s
    mgr = CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
        shell_executor=MagicMock(),
    )
    mgr.get_certificate_info = MagicMock(return_value={
        'needs_renewal': True, 'dns_provider': 'cloudflare',
    })
    mgr._audit_scheduled_renew = MagicMock()
    mgr._publish_renewed_event = MagicMock()
    mgr._publish_failed_event = MagicMock()
    return mgr


def test_a_successful_renewal_increments_the_success_counter(tmp_path):
    domain = 'metrics-ok.example.com'
    labels = {'domain': domain, 'dns_provider': 'cloudflare',
              'status': 'success'}
    before = _sample(RENEWALS, labels) or 0.0

    mgr = _mgr_with_one_due_domain(tmp_path, domain)
    mgr.renew_certificate = MagicMock(return_value={'renewed': True})
    summary = mgr.check_renewals()

    assert summary['renewed'] == 1
    assert (_sample(RENEWALS, labels) or 0.0) == before + 1, (
        "a renewal succeeded but certmate_certificate_renewals_total did not "
        "move — the success rate is unobservable"
    )


def test_a_failed_renewal_increments_the_failure_counter_and_an_acme_error(
        tmp_path):
    domain = 'metrics-fail.example.com'
    fail_labels = {'domain': domain, 'dns_provider': 'cloudflare',
                   'status': 'failure'}
    err_labels = {'error_type': 'RuntimeError', 'domain': domain,
                  'dns_provider': 'cloudflare'}
    before = _sample(RENEWALS, fail_labels) or 0.0
    before_err = _sample(ACME_ERRORS, err_labels) or 0.0

    mgr = _mgr_with_one_due_domain(tmp_path, domain)
    mgr.renew_certificate = MagicMock(side_effect=RuntimeError("CA said no"))
    summary = mgr.check_renewals()

    assert summary['failed'] == 1
    assert (_sample(RENEWALS, fail_labels) or 0.0) == before + 1, (
        "a renewal failed but the failure counter did not move"
    )
    assert (_sample(ACME_ERRORS, err_labels) or 0.0) == before_err + 1


def test_a_not_yet_due_result_is_not_counted_as_a_renewal(tmp_path):
    """CONTROL: certbot reporting 'not yet due' is not a renewal.

    Counting it would inflate the success rate and hide a sweep that is
    renewing nothing.
    """
    domain = 'metrics-notdue.example.com'
    labels = {'domain': domain, 'dns_provider': 'cloudflare',
              'status': 'success'}
    before = _sample(RENEWALS, labels) or 0.0

    mgr = _mgr_with_one_due_domain(tmp_path, domain)
    mgr.renew_certificate = MagicMock(return_value={'renewed': False})
    summary = mgr.check_renewals()

    assert summary['skipped_not_due'] == 1
    assert (_sample(RENEWALS, labels) or 0.0) == before, (
        "a 'not yet due' result must not count as a successful renewal"
    )


def test_telemetry_failure_never_breaks_a_renewal(tmp_path):
    """CONTROL: metrics are not allowed to cost a certificate."""
    mgr = _mgr_with_one_due_domain(tmp_path, 'metrics-boom.example.com')
    mgr.renew_certificate = MagicMock(return_value={'renewed': True})

    with patch('modules.core.metrics.metrics_collector'
               '.record_certificate_renewal',
               side_effect=RuntimeError("collector down")):
        summary = mgr.check_renewals()

    assert summary['renewed'] == 1, (
        "a telemetry error must not turn a successful renewal into a failure"
    )
