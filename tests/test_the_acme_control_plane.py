"""What the ACME server issued, to whom, and what an admin can do about it (#476, H1-H3).

GET /api/acme/certificates lists every certificate issued over ACME with the
account and EAB key behind it, to a viewer as client certificates are listed.
An admin revokes one from there, and the CRL says so; an admin lists the
accounts and deactivates one, which stops it ordering where disabling its EAB
key does not. Each action is in the audit log.
"""
import sqlite3

import pytest
from cryptography import x509

from tests.acme_support import ChallengeServer, eab_for, problem, registered_client, served_app
from tests.test_the_acme_server_issues_and_revokes import _crl, _issue

pytestmark = [pytest.mark.unit]


@pytest.fixture
def responder():
    server = ChallengeServer()
    yield server
    server.close()


@pytest.fixture
def app(responder):
    return served_app(responder)


@pytest.fixture
def client(app):
    return registered_client(app, eab_for(app))


@pytest.fixture
def admin(app):
    http = app.test_client()
    http.environ_base['HTTP_AUTHORIZATION'] = f"Bearer {app.extensions['certmate_test_token']}"
    return http


@pytest.fixture
def viewer(app, admin):
    key = admin.post('/api/keys', json={'name': 'acme-viewer', 'role': 'viewer'}).get_json()
    http = app.test_client()
    http.environ_base['HTTP_AUTHORIZATION'] = f"Bearer {key['token']}"
    return http


def _serial(pem_response):
    return format(x509.load_pem_x509_certificate(pem_response.data).serial_number, 'x')


def test_nothing_is_listed_and_no_database_is_made_before_anything_was_issued(app, admin):
    assert admin.get('/api/acme/certificates').get_json() == {'certificates': []}
    assert admin.get('/api/acme/accounts').get_json() == {'accounts': []}
    assert not app.extensions['certmate_container'].managers['acme_server'].db_path.exists()


def test_the_certificates_are_listed_newest_first_with_who_ordered_them(client, responder, viewer):
    _, _, first, _ = _issue(client, responder, ('web.lab.internal',))
    _, _, second, _ = _issue(client, responder, ('api.lab.internal', 'db.lab.internal'))
    listed = viewer.get('/api/acme/certificates').get_json()['certificates']
    assert [c['names'] for c in listed] == [['api.lab.internal', 'db.lab.internal'], ['web.lab.internal']]
    assert [c['serial'] for c in listed] == [_serial(second), _serial(first)]
    for c in listed:
        assert c['status'] == 'valid' and c['eab_kid'] == 'team-a'
        assert c['account_id'] == client.account_url.rsplit('/', 1)[-1]
        assert c['not_after'].endswith('Z') and c['created_at'].endswith('Z')
        assert c['revoked_at'] is None and c['revocation_reason'] is None


def test_an_expired_certificate_reads_as_expired(app, client, responder, admin):
    _issue(client, responder, ('web.lab.internal',))
    db = app.extensions['certmate_container'].managers['acme_server'].db_path
    with sqlite3.connect(db) as con:
        con.execute("UPDATE certificates SET not_after = '2020-01-01T00:00:00'")
    assert admin.get('/api/acme/certificates').get_json()['certificates'][0]['status'] == 'expired'


def test_an_admin_revokes_and_the_crl_says_so(app, client, responder, admin):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    certificate_id = admin.get('/api/acme/certificates').get_json()['certificates'][0]['id']
    serial = x509.load_pem_x509_certificate(pem.data).serial_number
    assert _crl(client).get_revoked_certificate_by_serial_number(serial) is None  # read, and kept
    revoked = admin.post(f'/api/acme/certificates/{certificate_id}/revoke', json={'reason': 1})
    assert revoked.status_code == 200
    assert revoked.get_json()['status'] == 'revoked' and revoked.get_json()['revocation_reason'] == 'keyCompromise'
    entry = _crl(client).get_revoked_certificate_by_serial_number(serial)
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.key_compromise
    again = admin.post(f'/api/acme/certificates/{certificate_id}/revoke', json={})
    assert again.status_code == 409 and again.get_json()['code'] == 'ACME_CERTIFICATE_ALREADY_REVOKED'
    entries = app.extensions['certmate_container'].managers['audit'].get_recent_entries(50)
    assert any(e.get('operation') == 'revoke_certificate' for e in entries)


@pytest.mark.parametrize('certificate_id,body,status', [
    ('nobody', {}, 404),
    (None, {'reason': 7}, 400),
    (None, {'reason': True}, 400),
])
def test_a_revocation_the_api_cannot_honour_is_refused(client, responder, admin, certificate_id, body, status):
    _issue(client, responder, ('web.lab.internal',))
    certificate_id = certificate_id or admin.get('/api/acme/certificates').get_json()['certificates'][0]['id']
    assert admin.post(f'/api/acme/certificates/{certificate_id}/revoke', json=body).status_code == status
    assert admin.get('/api/acme/certificates').get_json()['certificates'][0]['status'] == 'valid'


def test_a_deactivated_account_orders_nothing_and_its_certificates_stay(app, client, responder, admin):
    _issue(client, responder, ('web.lab.internal',))
    accounts = admin.get('/api/acme/accounts').get_json()['accounts']
    assert len(accounts) == 1
    account = accounts[0]
    assert (account['status'], account['eab_kid'], account['orders'], account['certificates']) == \
        ('valid', 'team-a', 1, 1)
    deactivated = admin.post(f"/api/acme/accounts/{account['id']}/deactivate")
    assert deactivated.status_code == 200 and deactivated.get_json()['status'] == 'deactivated'
    order = client.post('new-order', {'identifiers': [{'type': 'dns', 'value': 'api.lab.internal'}]})
    assert problem(order, 'deactivated') == 'unauthorized'
    assert admin.get('/api/acme/certificates').get_json()['certificates'][0]['status'] == 'valid'
    again = admin.post(f"/api/acme/accounts/{account['id']}/deactivate")
    assert again.status_code == 409
    assert admin.post('/api/acme/accounts/nobody/deactivate').status_code == 404
    entries = app.extensions['certmate_container'].managers['audit'].get_recent_entries(50)
    assert any(e.get('operation') == 'deactivate_account' for e in entries)


def test_a_viewer_reads_the_certificates_and_acts_on_nothing(client, responder, viewer):
    _issue(client, responder, ('web.lab.internal',))
    certificate_id = viewer.get('/api/acme/certificates').get_json()['certificates'][0]['id']
    assert viewer.post(f'/api/acme/certificates/{certificate_id}/revoke', json={}).status_code == 403
    assert viewer.get('/api/acme/accounts').status_code == 403
    account_id = client.account_url.rsplit('/', 1)[-1]
    assert viewer.post(f'/api/acme/accounts/{account_id}/deactivate').status_code == 403
