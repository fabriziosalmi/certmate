"""A renewal from the API or the dashboard reaches the renewal metrics (#666 D7).

`certmate_certificate_renewals_total`, the renewal duration histogram and the
rate-limit counter were fed by the nightly sweep and nothing else, while the
creation metrics are recorded inside `create_certificate` and so count every
path. A renewal an operator ran by hand, including the one the CA refused for
a rate limit, left no trace in Prometheus: the alert on
certmate_acme_rate_limit_hits_total could not fire for the renewal most likely
to hit it, the manual retry.

The service records them now (the sweep calls the manager directly and keeps
its own recording, so nothing is counted twice), with the sweep's rules: a
"not yet due" answer is not a renewal, and a busy domain, a missing
certificate or one that needs a reissue is not a failed renewal either.
"""
import json
from unittest.mock import MagicMock

import pytest
from prometheus_client import REGISTRY

from modules.core.cert_service import CertificateService
from modules.core.certificates import (
    CertificateManager, DomainOperationInProgress, ReissueRequired)

pytestmark = [pytest.mark.unit]

RENEWALS = 'certmate_certificate_renewals_total'
RATE_LIMITS = 'certmate_acme_rate_limit_hits_total'


def _service(tmp_path, domain, outcome):
    (tmp_path / domain).mkdir(parents=True)
    (tmp_path / domain / 'metadata.json').write_text(json.dumps({'dns_provider': 'route53'}))
    mgr = CertificateManager(cert_dir=tmp_path, settings_manager=MagicMock(),
                             dns_manager=MagicMock())
    if isinstance(outcome, Exception):
        mgr.renew_certificate = MagicMock(side_effect=outcome)
    else:
        mgr.renew_certificate = MagicMock(return_value=outcome)
    return CertificateService(mgr, MagicMock(), MagicMock())


def _count(domain, status):
    return REGISTRY.get_sample_value(
        RENEWALS, {'domain': domain, 'dns_provider': 'route53', 'status': status}) or 0


def _renew(service, domain):
    return service.issue_renew({'domain': domain, '_audit_ctx': None})


def test_a_manual_renewal_is_counted(tmp_path):
    domain = 'd7-ok.example.com'
    _renew(_service(tmp_path, domain, {'renewed': True}), domain)
    assert _count(domain, 'success') == 1


def test_not_yet_due_is_not_a_renewal(tmp_path):
    domain = 'd7-notdue.example.com'
    _renew(_service(tmp_path, domain, {'renewed': False}), domain)
    assert _count(domain, 'success') == 0
    assert _count(domain, 'failure') == 0


def test_a_refused_manual_renewal_is_counted_and_so_is_the_rate_limit(tmp_path):
    domain = 'd7-ratelimited.example.com'
    labels = {'limit_type': 'renewal', 'dns_provider': 'route53'}
    before = REGISTRY.get_sample_value(RATE_LIMITS, labels) or 0
    error = RuntimeError('Renewal failed: urn:ietf:params:acme:error:rateLimited: '
                         'too many certificates already issued')
    with pytest.raises(RuntimeError):
        _renew(_service(tmp_path, domain, error), domain)
    assert _count(domain, 'failure') == 1
    assert (REGISTRY.get_sample_value(RATE_LIMITS, labels) or 0) == before + 1


@pytest.mark.parametrize('error', [
    DomainOperationInProgress('d7-skip.example.com'),
    FileNotFoundError('no certificate'),
    ReissueRequired('no private key anywhere'),
], ids=['busy', 'missing', 'reissue-required'])
def test_what_is_not_a_failed_renewal_is_not_counted_as_one(tmp_path, error):
    domain = 'd7-skip.example.com'
    with pytest.raises(type(error)):
        _renew(_service(tmp_path, domain, error), domain)
    assert _count(domain, 'failure') == 0


def test_telemetry_cannot_fail_a_renewal_that_happened(tmp_path):
    domain = 'd7-unreadable.example.com'
    service = _service(tmp_path, domain, {'renewed': True})
    service._certs._load_metadata = MagicMock(side_effect=PermissionError('metadata.json'))
    result = _renew(service, domain)
    assert result['renewed'] is True and result.keys() == {'renewed', 'duration'}, (
        'the manager result comes back, with the duration the service adds (#1108), and nothing '
        'telemetry did to it')
    assert REGISTRY.get_sample_value(
        RENEWALS, {'domain': domain, 'dns_provider': 'unknown', 'status': 'success'}) == 1
