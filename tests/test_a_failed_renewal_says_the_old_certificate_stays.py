"""A renewal that failed in a background job says what to check, and that the
previous certificate is still in place; a job's hint never names a cause the
error does not.

Found by the UX perception audit of 2026-11-18.

P02: the dashboard renews through a job (`async: true`), and the renew route
handed the job no explanation, so a failed renewal had `hint: null` and
`error_code: null` while a create or a reissue against the same dead CA had
one. The toast then showed certbot's raw dump, and nothing said the site was
still served by the old certificate.

P01: `_certbot_hint` ended on a generic DNS or port-80 hint whatever the
error said. Let's Encrypt refusing the account email was told to check DNS
credentials, and CertMate's own "HTTP-01 challenge does not support wildcard
domains" was told to check port 80. A job's explanation no longer takes that
fallback; the synchronous 422 keeps it, so its `hint` stays a string. The
toast leads with the error's cause either way (tests/
test_ui_a_failed_job_toast_leads_with_the_cause.py).
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.api.resources_lifecycle import _certbot_hint, _creation_failure
from modules.core.failure_hints import PREVIOUS_KEPT as _PREVIOUS_KEPT
from tests.test_a_failed_job_says_what_to_check import CA_CLOSED
from tests.test_async_issuance import _build_app, _exec, _passthrough_decorator, _wait_terminal

pytestmark = [pytest.mark.unit]

# certbot's words when the CA refuses the account's contact email, as the
# audit run recorded them from Let's Encrypt (2026-11-18).
EMAIL_REFUSED = ("Certificate creation failed: Unable to register an account with ACME server. "
                 "The ACME server believes me@homelab.example is an invalid email address. "
                 "Please ensure it is a valid email and attempt registration again.")
# The refusal as each ACME problem type may name it, one marker per message,
# so deleting any one marker fails its own case. invalidContact and
# unsupportedContact are RFC 8555's; invalidEmail is the ACME v1 name. Not
# measured: built from the problem types' names.
ACCOUNT_REFUSALS = {
    'certbot': 'Unable to register an account with ACME server',
    'invalidcontact': 'urn:ietf:params:acme:error:invalidContact :: contact email has invalid domain',
    'unsupportedcontact': 'urn:ietf:params:acme:error:unsupportedContact :: contact URL scheme not supported',
    'invalidemail': 'urn:ietf:params:acme:error:invalidEmail :: Error creating new account',
    'wording': 'The ACME server believes me@homelab.example is an invalid email address',
}
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


def _create(tmp_path, side_effect, asynchronous):
    ex = _exec()
    app, managers = _build_app(tmp_path, ex)
    managers['certificates'].create_certificate.side_effect = side_effect
    client = app.test_client()
    answer = client.post('/api/certificates/create', json={
        'domain': 'x.example.com', 'dns_provider': 'cloudflare', 'async': asynchronous})
    if not asynchronous:
        return answer.status_code, answer.get_json()
    assert answer.status_code == 202, answer.get_json()
    _wait_terminal(ex, answer.get_json()['job_id'])
    return 200, client.get(answer.get_json()['status_url']).get_json()


def _reissue_job(tmp_path, side_effect, challenge):
    """An async reissue whose certbot run raises *side_effect*: the job record."""
    ex = _exec()
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth.user_can_access_domain.return_value = True
    settings = MagicMock()
    settings.load_settings.return_value = {'challenge_type': challenge}
    service = MagicMock()
    # What prepare_reissue answers: the job records the CA it resolved (2.72).
    service.prepare_reissue.return_value = {'domain': 'x.example.com', 'ca_provider': 'letsencrypt'}
    service.issue_reissue.side_effect = side_effect
    managers = {'auth': auth, 'settings': settings, 'certificates': MagicMock(cert_dir=Path(tmp_path)),
                'file_ops': MagicMock(cert_dir=Path(tmp_path)), 'cache': MagicMock(), 'dns': MagicMock(),
                'audit': None, 'cert_executor': ex, 'cert_service': service}
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['CertificateReissue'], '/<string:domain>/reissue')
    ns.add_resource(resources['CertificateJob'], '/jobs/<string:job_id>')

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    client = app.test_client()
    accepted = client.post('/api/certificates/x.example.com/reissue', json={'async': True})
    assert accepted.status_code == 202, accepted.get_json()
    _wait_terminal(ex, accepted.get_json()['job_id'])
    return client.get(accepted.get_json()['status_url']).get_json()


def test_a_failed_async_renewal_says_what_to_check_and_that_the_old_certificate_stays(tmp_path):
    job = _renew_job(tmp_path, RuntimeError(CA_CLOSED))
    assert job['status'] == 'failed'
    assert job['error_code'] == 'RENEWAL_FAILED'
    assert 'could not reach the CA' in job['hint']
    assert job['hint'].endswith(_PREVIOUS_KEPT)
    assert 'community.letsencrypt.org' not in job['hint']


@pytest.mark.parametrize('error,code,says', [
    ("DNS provider 'cloudflare' account 'default' not configured", 'DNS_ACCOUNT_NOT_CONFIGURED',
     'Re-add it in Settings'),
    ('ReissueRequired: x.example.com has no private key anywhere', 'REISSUE_REQUIRED', 'Reissue it'),
    ('renewal configuration file is broken (parsefail)', 'RENEWAL_CONFIG_BROKEN', 'Use Edit & Reissue'),
])
def test_a_renewal_whose_cause_is_known_says_it_as_the_synchronous_renew_does(tmp_path, error, code, says):
    """The synchronous renew answers these with classify_renewal_error's
    message; the job carries the same code and that message as its hint."""
    job = _renew_job(tmp_path, RuntimeError(error))
    assert job['error_code'] == code, job
    assert says in job['hint'], job['hint']
    assert job['hint'].endswith(' ' + _PREVIOUS_KEPT), job['hint']


def test_a_renewal_no_rule_knows_names_no_cause_and_keeps_the_error(tmp_path):
    """No guessed cause: the hint only says the old certificate stays, and the
    error carries the real one, which the toast shows first."""
    job = _renew_job(tmp_path, RuntimeError('Renewal failed: something no rule knows'))
    assert job['error_code'] == 'RENEWAL_FAILED'
    assert job['hint'] == _PREVIOUS_KEPT
    assert 'something no rule knows' in job['error']


@pytest.mark.parametrize('challenge', ['dns-01', 'http-01'])
def test_an_async_reissue_no_rule_knows_only_says_the_old_certificate_stays(tmp_path, challenge):
    """No guessed cause on a reissue either: without fallback=False the hint
    would tell the user to check DNS credentials or port 80."""
    job = _reissue_job(tmp_path, RuntimeError('something no rule knows'), challenge)
    assert job['status'] == 'failed', job
    assert job['error_code'] == 'CERTIFICATE_REISSUE_FAILED', job
    assert job['hint'] == _PREVIOUS_KEPT, job['hint']
    assert 'dns' not in job['hint'].lower() and 'port 80' not in job['hint'], job['hint']
    assert 'something no rule knows' in job['error']


@pytest.mark.parametrize('marker', sorted(ACCOUNT_REFUSALS))
@pytest.mark.parametrize('challenge', ['dns-01', 'http-01'])
def test_a_refused_account_email_points_at_the_email_not_dns(marker, challenge):
    hint = _certbot_hint(ACCOUNT_REFUSALS[marker], challenge)
    assert hint and 'email' in hint.lower(), hint
    assert 'Settings > CA' in hint
    assert 'dns' not in hint.lower() and 'port 80' not in hint, hint


@pytest.mark.parametrize('challenge', ['http-01', 'dns-01', None])
def test_a_job_gets_no_generic_hint_for_certmates_own_wildcard_refusal(challenge):
    assert _certbot_hint(WILDCARD_HTTP01, challenge, fallback=False) is None
    body = _creation_failure(WILDCARD_HTTP01, challenge, fallback=False)
    assert body['hint'] is None
    assert 'wildcard' in body['error']


def test_an_async_create_no_rule_knows_has_a_null_hint(tmp_path):
    _, job = _create(tmp_path, RuntimeError('something else entirely'), asynchronous=True)
    assert job['status'] == 'failed'
    assert job['error_code'] == 'CERTIFICATE_CREATION_FAILED'
    assert job['hint'] is None
    assert 'something else entirely' in job['error']


def test_the_synchronous_422_keeps_a_string_hint(tmp_path):
    """CONTROL: the 422 CERTIFICATE_CREATION_FAILED is not retyped; an error no
    rule knows still answers with the generic hint, a string."""
    status, body = _create(tmp_path, RuntimeError('something else entirely'), asynchronous=False)
    assert status == 422, body
    assert body['code'] == 'CERTIFICATE_CREATION_FAILED'
    assert isinstance(body['hint'], str) and body['hint']
