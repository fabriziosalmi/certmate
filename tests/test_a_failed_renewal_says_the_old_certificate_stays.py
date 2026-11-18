"""A renewal that failed in a background job says what to check, and that the
previous certificate is still in place; a hint never names a cause the error
does not.

Found by the UX perception audit of 2026-11-18.

P02: the dashboard renews through a job (`async: true`), and the renew route
handed the job no explanation, so a failed renewal had `hint: null` while a
create or a reissue against the same dead CA had one. The toast then showed
certbot's raw dump, with the Let's Encrypt forum and a server-side log path,
and nothing said the site was still served by the old certificate.

P01: `_certbot_hint` ended on a generic DNS or port-80 hint whatever the
error said. Let's Encrypt refusing the account email was told to check DNS
credentials, and CertMate's own "HTTP-01 challenge does not support wildcard
domains" was told to check port 80. The toast leads with the hint, so the
wrong cause was the first thing read.
"""
import pytest

from modules.api.resources_lifecycle import _certbot_hint, _creation_failure
from tests.test_a_failed_job_says_what_to_check import CA_CLOSED
from tests.test_async_issuance import _build_app, _exec, _wait_terminal

pytestmark = [pytest.mark.unit]

# certbot's words when the CA refuses the account's contact email, as the
# audit run recorded them from Let's Encrypt (2026-11-18).
EMAIL_REFUSED = ("Certificate creation failed: Unable to register an account with ACME server. "
                 "The ACME server believes me@homelab.example is an invalid email address. "
                 "Please ensure it is a valid email and attempt registration again.")
# The same refusal as an RFC 8555 problem type, as a CA other than certbot's
# wording may report it. Not measured: built from the problem type's name.
EMAIL_PROBLEM_TYPE =("urn:ietf:params:acme:error:invalidEmail :: The ACME server believes "
                      "me@homelab.example is an invalid email address")
# CertMate's own ValueError, raised inside create_certificate (certificates.py).
WILDCARD_HTTP01 = 'HTTP-01 challenge does not support wildcard domains. Use DNS-01 instead.'


def _renew_job(tmp_path, side_effect):
    ex = _exec()
    app, managers = _build_app(tmp_path, ex)
    managers['certificates'].renew_certificate.side_effect = side_effect
    client = app.test_client()
    accepted = client.post('/api/certificates/x.example.com/renew', json={'async': True})
    assert accepted.status_code == 202, accepted.get_json()
    _wait_terminal(ex, accepted.get_json()['job_id'])
    return client.get(accepted.get_json()['status_url']).get_json()


def test_a_failed_async_renewal_says_what_to_check_and_that_the_old_certificate_stays(tmp_path):
    job = _renew_job(tmp_path, RuntimeError(CA_CLOSED))
    assert job['status'] == 'failed'
    assert job['hint'], job
    assert 'could not reach the CA' in job['hint']
    assert 'still in place' in job['hint']
    assert 'community.letsencrypt.org' not in job['hint']


def test_a_renewal_with_nothing_to_explain_still_says_the_old_certificate_stays(tmp_path):
    job = _renew_job(tmp_path, RuntimeError('Renewal failed: something no rule knows'))
    assert job['hint'] == 'The previous certificate is still in place.'


@pytest.mark.parametrize('message', [EMAIL_REFUSED, EMAIL_PROBLEM_TYPE])
@pytest.mark.parametrize('challenge', ['dns-01', 'http-01'])
def test_a_refused_account_email_points_at_the_email_not_dns(message, challenge):
    hint = _certbot_hint(message, challenge)
    assert hint and 'email' in hint.lower(), hint
    assert 'Settings > CA' in hint
    assert 'dns' not in hint.lower() and 'port 80' not in hint, hint


@pytest.mark.parametrize('challenge', ['http-01', 'dns-01', None])
def test_certmates_own_wildcard_refusal_gets_no_generic_hint(challenge):
    assert _certbot_hint(WILDCARD_HTTP01, challenge) is None
    body = _creation_failure(WILDCARD_HTTP01, challenge)
    assert body['hint'] is None
    assert 'wildcard' in body['error']


def test_an_error_no_rule_knows_gets_no_hint():
    """The toast reads hint || error: a guessed hint hides the real cause."""
    assert _certbot_hint('something else entirely', 'dns-01') is None
    assert _certbot_hint('something else entirely', 'http-01') is None
