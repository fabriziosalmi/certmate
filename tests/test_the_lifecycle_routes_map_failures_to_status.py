"""Every way a create, renew or reissue can fail must reach the right status.

`resources_lifecycle.py` is the entry point for every certificate create, renew
and reissue request, and it carried the thinnest coverage floor in the project
after `settings_routes` — 55, against core modules floored far higher. The
uncovered lines were not happy paths: they were the `except` arms, which are
where all the behaviour is. Each one turns an exception into a status code and
a machine-readable code, and the difference between them is what a client acts
on:

* **403** the key is not allowed this domain — do not retry;
* **409** the domain is busy — retry shortly;
* **404** there is no certificate here;
* **422** the CA or the configuration refused — retrying unchanged will fail
  the same way, and the message says what to fix;
* **500** something in CertMate broke — the operator's problem, not the
  caller's.

Getting one of those wrong is not a cosmetic error. A 500 where a 422 belongs
sends an operator looking at CertMate for a problem in their DNS provider; a
500 where a 409 belongs makes a client retry-storm a domain that is simply
mid-issuance.

These drive the resources directly rather than through `create_app`, so each
arm is reached by making the service raise, which is what actually happens.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.core.certificates import DomainOperationInProgress
from modules.core.cert_service import DomainOutOfScope

pytestmark = [pytest.mark.unit]


class _Managers(dict):
    def __missing__(self, key):
        value = MagicMock()
        self[key] = value
        return value


@pytest.fixture
def app_and_service():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['RESTX_VALIDATE'] = True
    api = Api(app, prefix='/api')

    managers = _Managers()
    auth = managers['auth']
    auth.require_role = lambda role: (lambda fn: fn)
    auth.user_can_access_domain.return_value = True
    service = managers['cert_service']

    resources = create_api_resources(api, create_api_models(api), managers)
    api.add_resource(resources['CreateCertificate'], '/certificates/create')
    api.add_resource(resources['RenewCertificate'],
                     '/certificates/<string:domain>/renew')
    api.add_resource(resources['CertificateReissue'],
                     '/certificates/<string:domain>/reissue')
    return app, service


@pytest.fixture
def client(app_and_service):
    app, _ = app_and_service
    return app.test_client()


@pytest.fixture
def service(app_and_service):
    return app_and_service[1]


def _renew(client):
    return client.post('/api/certificates/example.com/renew', json={})


def _create(client):
    return client.post('/api/certificates/create',
                       json={'domain': 'example.com'})


# --- renew ---------------------------------------------------------------

@pytest.mark.parametrize('raised, status, code', [
    (DomainOutOfScope('example.com'), 403, 'DOMAIN_OUT_OF_SCOPE'),
    (DomainOperationInProgress('example.com'), 409,
     'DOMAIN_OPERATION_IN_PROGRESS'),
    (FileNotFoundError('no such certificate'), 404, 'NOT_FOUND'),
])
def test_renew_maps_each_failure_to_its_status(client, service, raised,
                                               status, code):
    service.renew.side_effect = raised
    response = _renew(client)

    assert response.status_code == status
    assert response.get_json()['code'] == code


def test_a_renewal_the_ca_refused_is_422_not_500(client, service):
    """The distinction that matters most here. 500 sends the operator looking
    inside CertMate for a problem that is in their DNS provider or their
    configuration, and tells a client to retry something that will fail the
    same way."""
    service.renew.side_effect = RuntimeError(
        'DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com')

    response = _renew(client)

    assert response.status_code == 422
    body = response.get_json()
    assert body['code'] and body['code'] != 'CERTIFICATE_RENEWAL_ERROR'
    assert 'error' in body


def test_an_unexpected_failure_is_500_and_says_nothing_specific(client,
                                                                service):
    """CONTROL: the 422 arm must not swallow genuine faults. An
    AttributeError inside CertMate is the operator's problem, and the message
    must not invite the caller to fix their DNS."""
    service.renew.side_effect = AttributeError("'NoneType' has no attribute")

    response = _renew(client)

    assert response.status_code == 500
    assert response.get_json()['code'] == 'CERTIFICATE_RENEWAL_ERROR'


def test_a_domain_that_is_busy_publishes_no_failure_event(client, service):
    """409 is not a failure — it is "try again in a minute". Publishing a
    certificate_failed event for it would page someone for a queue."""
    from flask import current_app
    service.renew.side_effect = DomainOperationInProgress('example.com')

    with client.application.app_context():
        bus = MagicMock()
        current_app.config['EVENT_BUS'] = bus
        _renew(client)

    assert not bus.publish.called


def test_a_real_renewal_failure_does_publish_one(client, service, app_and_service):
    """CONTROL for the above: the event must still fire when the renewal
    genuinely failed, or the notifier goes quiet on the case it exists for."""
    app, _ = app_and_service
    bus = MagicMock()
    app.config['EVENT_BUS'] = bus
    service.renew.side_effect = RuntimeError('certbot exited 1')

    _renew(client)

    assert bus.publish.called
    assert bus.publish.call_args.args[0] == 'certificate_failed'


# --- create --------------------------------------------------------------

@pytest.mark.parametrize('raised, status, code', [
    (DomainOutOfScope('example.com'), 403, 'DOMAIN_OUT_OF_SCOPE'),
    (DomainOperationInProgress('example.com'), 409,
     'DOMAIN_OPERATION_IN_PROGRESS'),
])
def test_create_maps_each_failure_to_its_status(client, service, raised,
                                                status, code):
    # The synchronous path — no async flag in the payload — calls create().
    # prepare_create is the async one; stubbing that alone lets the request
    # reach the real return statement and serialise a MagicMock.
    service.create.side_effect = raised
    response = _create(client)

    assert response.status_code == status
    assert response.get_json()['code'] == code


def test_a_rejected_create_request_is_400_with_a_hint(client, service):
    """A ValueError here is bad input, and the hint is what makes it
    actionable — it is the difference between "invalid" and "you have no
    email configured"."""
    service.create.side_effect = ValueError('Email not configured')

    response = _create(client)

    assert response.status_code == 400
    body = response.get_json()
    assert 'Email not configured' in body['error']
    assert body.get('hint'), 'a 400 with no hint tells the caller nothing'


def test_an_existing_certificate_is_reported_as_such(client, service):
    service.create.side_effect = FileExistsError(
        'certificate already exists')

    response = _create(client)

    assert response.status_code in (409, 422)
    assert response.get_json()['code']


# --- reissue -------------------------------------------------------------

@pytest.mark.parametrize('raised, status', [
    (DomainOutOfScope('example.com'), 403),
    (DomainOperationInProgress('example.com'), 409),
    (FileNotFoundError('gone'), 404),
])
def test_reissue_maps_each_failure_to_its_status(client, service, raised,
                                                 status):
    service.prepare_reissue.side_effect = raised
    response = client.post('/api/certificates/example.com/reissue', json={})

    assert response.status_code == status
    assert response.get_json()['code']


def test_a_failed_reissue_says_the_old_certificate_is_still_there(client,
                                                                  service):
    """The one thing an operator needs to know after a reissue fails, and the
    one thing a generic 422 would not tell them."""
    service.prepare_reissue.side_effect = RuntimeError('certbot exited 1')

    response = client.post('/api/certificates/example.com/reissue', json={})

    assert response.status_code == 422
    body = str(response.get_json())
    assert 'still in place' in body, (
        f'the refusal does not say the previous certificate survived: {body}'
    )


# --- every arm carries a code -------------------------------------------

def test_no_failure_arm_answers_without_a_code(client, service):
    """A caller that cannot branch on the outcome has to match English. The
    ratchet in test_api_errors_carry_a_code.py holds this file at zero; this
    exercises the arms so that "zero uncoded" is measured rather than
    inferred from the source."""
    for raised in (DomainOutOfScope('example.com'),
                   DomainOperationInProgress('example.com'),
                   FileNotFoundError('gone'),
                   RuntimeError('certbot exited 1'),
                   AttributeError('boom')):
        service.renew.side_effect = raised
        body = _renew(client).get_json()
        assert body.get('code'), f'{type(raised).__name__} answered without a code'
