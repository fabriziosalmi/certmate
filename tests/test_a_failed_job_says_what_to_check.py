"""A create that failed in a background job says what to check, as the synchronous one does.

Found by the UX audit of 2026-11-17: the dashboard always issues through a
job (`async: true`), and a failed job carried certbot's message with
`error_code: null` and no hint, so the hint logic of the synchronous route
(#1460) was never shown. Against a private CA on a closed port, the toast
was the Python `ConnectionError` and certbot's "Ask for help at
community.letsencrypt.org".

Now a failed create or reissue job carries the `error_code` and `hint` its
synchronous request answers with, and a CA directory that cannot be reached
is named. The messages are certbot's own, as measured.
"""
import pytest

from modules.api.resources_lifecycle import _certbot_hint, _creation_failure
from modules.core.certificates import DomainOperationInProgress
from tests.test_async_issuance import _build_app, _exec, _wait_terminal

pytestmark = [pytest.mark.unit]

# certbot 5.8.0 against https://127.0.0.1:9/directory (measured 2026-11-17).
CA_CLOSED = ("Certificate creation failed: An unexpected error occurred:\n"
             "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='127.0.0.1', port=9): "
             "Max retries exceeded with url: /directory (Caused by NewConnectionError(\"HTTPSConnection("
             "host='127.0.0.1', port=9): Failed to establish a new connection: [Errno 61] Connection refused\"))\n"
             "Ask for help or search for solutions at https://community.letsencrypt.org.")
HTTP01_REFUSED = ("Certificate creation failed: Some challenges have failed.\n"
                  "Domain: a.example.test\nType: connection\nDetail: 203.0.113.7: Fetching "
                  "http://a.example.test/.well-known/acme-challenge/abc: Connection refused")


def _failing_job(message, explain):
    ex = _exec()

    def fn():
        raise RuntimeError(message)
    return _wait_terminal(ex, ex.submit('create', 'a.example.test', fn, explain=explain))


def test_a_failed_job_carries_the_code_and_the_hint():
    job = _failing_job(HTTP01_REFUSED, lambda m: _creation_failure(m, 'http-01'))
    assert job['status'] == 'failed'
    assert job['error_code'] == 'CERTIFICATE_CREATION_FAILED'
    assert 'port 80' in job['hint']


def test_a_job_without_an_explanation_has_none():
    """CONTROL: a renewal job passes no explanation, and invents none."""
    job = _failing_job(HTTP01_REFUSED, None)
    assert job['error_code'] is None and job['hint'] is None


def test_a_busy_domain_keeps_its_own_code():
    ex = _exec()

    def fn():
        raise DomainOperationInProgress('a.example.test')
    job = _wait_terminal(ex, ex.submit('create', 'a.example.test', fn,
                                       explain=lambda m: _creation_failure(m, 'dns-01')))
    assert job['error_code'] == 'DOMAIN_OPERATION_IN_PROGRESS'
    assert job['hint'] is None


def test_an_unreachable_ca_is_named_with_its_url():
    hint = _certbot_hint(CA_CLOSED, 'dns-01')
    assert 'could not reach the CA' in hint
    assert 'https://127.0.0.1:9/directory' in hint
    assert 'DNS provider credentials' not in hint


def test_the_ca_failing_to_reach_this_host_keeps_its_http01_hint():
    """CONTROL: "Connection refused" from the CA is about this host's port 80,
    not about reaching the CA."""
    hint = _certbot_hint(HTTP01_REFUSED, None)
    assert 'port 80' in hint and 'could not reach the CA' not in hint


def test_an_untrusted_private_ca_points_at_its_trust_bundle():
    message = ("requests.exceptions.SSLError: HTTPSConnectionPool(host='ca.lab.internal', port=443): "
               "Max retries exceeded with url: /acme/directory (Caused by SSLError(SSLCertVerificationError("
               "1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer')))")
    hint = _certbot_hint(message, 'dns-01')
    assert 'trust bundle' in hint and 'https://ca.lab.internal:443/acme/directory' in hint


def test_an_async_create_through_the_api_says_what_to_check(tmp_path):
    """The whole path: the route hands the job its explanation."""
    ex = _exec()
    app, managers = _build_app(tmp_path, ex)
    managers['certificates'].create_certificate.side_effect = RuntimeError(CA_CLOSED)
    client = app.test_client()

    accepted = client.post('/api/certificates/create', json={
        'domain': 'x.example.com', 'dns_provider': 'cloudflare', 'async': True})
    assert accepted.status_code == 202, accepted.get_json()
    _wait_terminal(ex, accepted.get_json()['job_id'])
    job = client.get(accepted.get_json()['status_url']).get_json()

    assert job['status'] == 'failed'
    assert job['error_code'] == 'CERTIFICATE_CREATION_FAILED'
    assert 'https://127.0.0.1:9/directory' in job['hint']
