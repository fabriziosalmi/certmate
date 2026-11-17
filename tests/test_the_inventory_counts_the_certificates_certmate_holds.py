"""The inventory counts the certificates CertMate holds, without probing for them.

Found by the UX audit of 2026-11-17: Inventory showed "Managed 0, Total 0"
on an instance that managed 14 certificates. The inventory's `issued` source
was never written; a managed certificate entered only when discovery, which
is opt-in, probed its host. Decided the same day that it counts them.

Through the real application with its bearer token, real certificates on
disk, and the real event bus.
"""
import datetime
import secrets
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = [pytest.mark.unit]


def _certificate(name, days=60):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _hold(cert_dir, name, pem):
    directory = cert_dir / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'cert.pem').write_bytes(pem)


@pytest.fixture
def instance(tmp_path, monkeypatch):
    cert_dir = tmp_path / 'certificates'
    _hold(cert_dir, 'before.example.test', _certificate('before.example.test'))
    _hold(cert_dir, 'unreadable.example.test', b'not a certificate')

    from modules.factory import create_app
    root = tmp_path / 'app' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.factory.__file__', str(root / 'factory.py'))
    token = secrets.token_urlsafe(32)
    for name, value in (('FLASK_ENV', 'testing'), ('TESTING', 'true'), ('API_BEARER_TOKEN', token),
                        ('CERTMATE_CERT_DIR', str(cert_dir))):
        monkeypatch.setenv(name, value)
    app, container = create_app()
    container.inventory_held_sync.join(timeout=30)
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client, container, cert_dir


def _inventory(client, **query):
    answer = client.get('/api/inventory', query_string=query)
    assert answer.status_code == 200, answer.get_json()
    return answer.get_json()


def _wait(predicate, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_a_certificate_held_at_startup_is_counted_as_managed(instance):
    client, _container, _ = instance
    body = _inventory(client)
    assert body['summary']['issued'] == 1, body['summary']
    record = body['certificates'][0]
    assert record['managed'] and record['source'] == 'issued'
    assert record['managed_domain'] == 'before.example.test'


def test_a_certificate_created_later_is_counted_when_it_is_announced(instance):
    client, container, cert_dir = instance
    _hold(cert_dir, 'after.example.test', _certificate('after.example.test'))
    container.managers['events'].publish('certificate_created', {'domain': 'after.example.test'})
    inventory = container.managers['cert_inventory']
    assert _wait(lambda: len(inventory.list_all()) == 2), inventory.list_all()
    assert _inventory(client)['summary']['issued'] == 2


def test_a_renewal_shows_the_new_certificate_and_supersedes_the_old(instance):
    client, container, cert_dir = instance
    old = _inventory(client)['certificates'][0]['fingerprint']
    _hold(cert_dir, 'before.example.test', _certificate('before.example.test', days=90))
    container.managers['events'].publish('certificate_renewed', {'domain': 'before.example.test'})

    inventory = container.managers['cert_inventory']
    assert _wait(lambda: len(inventory.list_all()) == 2), inventory.list_all()
    # As the Inventory page asks: superseded certificates left out.
    body = _inventory(client, include_superseded='false')
    assert body['summary']['issued'] == 1, body['summary']
    assert [r['fingerprint'] for r in body['certificates']] != [old]
    everything = _inventory(client)['summary']
    assert everything['superseded'] == 1 and everything['total'] == 2, everything


def test_an_event_about_something_else_records_nothing(instance):
    """CONTROL: only a created or renewed certificate is read."""
    client, container, cert_dir = instance
    _hold(cert_dir, 'quiet.example.test', _certificate('quiet.example.test'))
    container.managers['events'].publish('certificate_expiring', {'domain': 'quiet.example.test'})
    time.sleep(0.5)
    assert _inventory(client)['summary']['issued'] == 1
