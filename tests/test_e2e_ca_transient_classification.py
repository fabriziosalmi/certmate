"""A CA refusal is a skip; a CertMate defect is a failure. Never the reverse.

The e2e suite treats a failed issuance as a failure of CertMate. Sometimes it
is not: Let's Encrypt staging answers "Service busy; retry later" and the job
fails for reasons entirely outside the code. Twice in one evening that turned a
green change red, and the reliable human response to a test that fails for
reasons unrelated to the change is to re-run it until it passes — which is
exactly how a genuine regression gets waved through.

So CA-side refusals became skips. That is only safe if the classification is
narrow: a filter that swallowed real defects would be far worse than the
flakiness it replaced, because it would convert failures into silence (#664).

These tests pin both directions.
"""
import pytest

from tests.test_async_issuance_e2e import _skip_if_the_ca_was_unavailable

pytestmark = [pytest.mark.unit]


def _failed(error):
    return {'status': 'failed', 'error': error}


@pytest.mark.parametrize('error', [
    'An unexpected error occurred: Service busy; retry later.',
    'Error creating new order :: too many requests',
    'urn:ietf:params:acme:error:rateLimited: rate limit exceeded',
    'Timeout during connect (likely firewall problem)',
    'The server experienced an internal error',
])
def test_a_refusal_by_the_certificate_authority_is_a_skip(error):
    with pytest.raises(pytest.skip.Exception):
        _skip_if_the_ca_was_unavailable(_failed(error))


@pytest.mark.parametrize('error', [
    'Certificate creation failed: expected certificate files are missing',
    "DNS provider 'cloudflare' is not configured",
    'certbot: error: unrecognized arguments: --dns-nope',
    'Failed to store certificate in backend: permission denied',
    'expected certificate files are missing after a successful certbot run',
    '',
    None,
])
def test_a_certmate_defect_still_fails(error):
    """The direction that matters more.

    If this ever starts skipping, the suite has stopped reporting the defects
    it exists to catch — silence instead of a red build.
    """
    _skip_if_the_ca_was_unavailable(_failed(error))  # must not raise


def test_a_succeeded_job_is_never_skipped():
    _skip_if_the_ca_was_unavailable({'status': 'succeeded', 'error': None})


def test_a_malformed_result_is_not_treated_as_a_ca_refusal():
    """CONTROL: only an explicit CA phrase may excuse a failure."""
    for value in (None, 'failed', 42, {'status': 'failed'}):
        _skip_if_the_ca_was_unavailable(value)  # must not raise
