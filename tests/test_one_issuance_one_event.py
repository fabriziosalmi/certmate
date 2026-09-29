"""One issuance, one event — through the path the dashboard actually takes.

#916 moved lifecycle publishing into CertificateService, so every adapter
(web, RESTX, the async executor) passes through one place. The async
IssuanceExecutor kept publishing too. The dashboard always sends
`async: true`, so a certificate created or renewed from the UI announced
itself twice: deploy hooks ran twice, webhooks and notifications fired twice,
and a failed async renewal paged twice.

Each part was tested alone: the executor with a stub job, the service with
no executor. Only the composition double-publishes, so this drives the
composition — a real EventBus, a real IssuanceExecutor, a real
CertificateService — with certbot replaced by a manager that answers.
"""
import threading
import time

import pytest

from modules.core.cert_jobs import IssuanceExecutor
from modules.core.cert_service import CertificateService
from modules.core.certificates import DomainOperationInProgress
from modules.core.events import EventBus

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'


class _Manager:
    def __init__(self, renew_result=None, renew_error=None):
        self.renew_result = renew_result or {'success': True, 'renewed': True}
        self.renew_error = renew_error

    def create_certificate(self, **kwargs):
        return {'success': True, 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt'}

    def renew_certificate(self, domain, force=False):
        if self.renew_error is not None:
            raise self.renew_error
        return dict(self.renew_result)


class _Settings:
    def update(self, fn, reason):
        return True


def _composed(manager):
    bus = EventBus()
    published = []
    lock = threading.Lock()
    real_publish = bus.publish

    def counting(event, data=None):
        with lock:
            published.append(event)
        return real_publish(event, data)

    bus.publish = counting
    service = CertificateService(manager, _Settings(), auth_manager=None,
                                 audit_logger=None, event_bus=bus)
    executor = IssuanceExecutor(app=None)
    return service, executor, published


def _wait(executor, job_id, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = executor.get(job_id)
        if job and job.get('status') in ('succeeded', 'failed'):
            return job
        time.sleep(0.01)
    raise AssertionError(f'job {job_id} did not finish: {executor.get(job_id)}')


def _prepared():
    return {'domain': DOMAIN, 'email': 'a@example.com', 'dns_provider': 'cloudflare',
            'account_id': 'default', 'ca_provider': 'letsencrypt', 'domain_alias': None,
            'san_domains': [], 'challenge_type': 'dns-01', 'key_type': None,
            'key_size': None, 'elliptic_curve': None, '_settings_dns_provider': 'cloudflare'}


def test_an_async_create_announces_itself_once():
    """THE regression, for the dashboard's create."""
    service, executor, published = _composed(_Manager())
    job = executor.submit('create', DOMAIN, lambda: service.issue_create(_prepared()))
    assert _wait(executor, job)['status'] == 'succeeded'

    assert published.count('certificate_created') == 1, published


def test_an_async_renewal_announces_itself_once():
    """THE regression, for the dashboard's renew."""
    service, executor, published = _composed(_Manager())
    job = executor.submit('renew', DOMAIN, lambda: service.issue_renew({'domain': DOMAIN}))
    assert _wait(executor, job)['status'] == 'succeeded'

    assert published.count('certificate_renewed') == 1, published


def test_an_async_renewal_that_fails_pages_once():
    """Two identical certificate_failed messages is how a real alarm gets
    filed under "that one always comes twice"."""
    service, executor, published = _composed(_Manager(renew_error=RuntimeError('certbot exited 1')))
    job = executor.submit('renew', DOMAIN, lambda: service.issue_renew({'domain': DOMAIN}))
    assert _wait(executor, job)['status'] == 'failed'

    assert published.count('certificate_failed') == 1, published


def test_a_renewal_that_was_not_due_announces_nothing():
    """CONTROL. certbot's "not yet due" replaced nothing, so no deploy hook."""
    service, executor, published = _composed(_Manager(renew_result={'success': True, 'renewed': False}))
    job = executor.submit('renew', DOMAIN, lambda: service.issue_renew({'domain': DOMAIN}))
    assert _wait(executor, job)['status'] == 'succeeded'

    assert 'certificate_renewed' not in published, published


def test_a_busy_domain_is_not_a_failure():
    """CONTROL. A queue is not an incident."""
    service, executor, published = _composed(_Manager(renew_error=DomainOperationInProgress(DOMAIN)))
    job = executor.submit('renew', DOMAIN, lambda: service.issue_renew({'domain': DOMAIN}))
    assert _wait(executor, job)['status'] == 'failed'

    assert 'certificate_failed' not in published, published


def test_an_async_reissue_announces_itself_once():
    """Reissue was inverted: the service published nothing, and the sync
    route and the executor each kept a copy. Now it is the service's."""
    service, executor, published = _composed(_Manager())
    job = executor.submit('reissue', DOMAIN, lambda: service.issue_reissue(
        dict(_prepared(), alias_dns_provider=None)))
    assert _wait(executor, job)['status'] == 'succeeded'

    assert published.count('certificate_renewed') == 1, published


def test_a_reissue_without_the_executor_still_announces_itself():
    """CONTROL on the move: the sync route used to publish for itself. With
    that copy gone, the event must still come from the service."""
    service, _executor, published = _composed(_Manager())
    service.issue_reissue(dict(_prepared(), alias_dns_provider=None))

    assert published == ['certificate_renewed'], published


def test_a_reissue_that_fails_pages_once():
    class Failing(_Manager):
        def create_certificate(self, **kwargs):
            raise RuntimeError('Certificate creation failed: rateLimited')

    service, executor, published = _composed(Failing())
    job = executor.submit('reissue', DOMAIN, lambda: service.issue_reissue(
        dict(_prepared(), alias_dns_provider=None)))
    assert _wait(executor, job)['status'] == 'failed'

    assert published.count('certificate_failed') == 1, published


def test_a_create_that_fails_announces_nothing():
    """CONTROL, unchanged behaviour: a failed create has no certificate to
    announce, and the sync create route has never published one."""
    class Failing(_Manager):
        def create_certificate(self, **kwargs):
            raise RuntimeError('Certificate creation failed: rateLimited')

    service, executor, published = _composed(Failing())
    job = executor.submit('create', DOMAIN, lambda: service.issue_create(_prepared()))
    assert _wait(executor, job)['status'] == 'failed'

    assert published == [], published
