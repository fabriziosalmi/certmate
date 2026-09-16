"""#578 (from #562): rebuilding the client CA, without taking anything else with it.

`PrivateCAGenerator.initialize(force=True)` has always been able to back up and
regenerate the CA, and nothing ever called it with `force`. So an operator who
wanted their own CA subject, or who had to rotate a CA key, had no way to do it
short of deleting files by hand and hoping.

The whole risk of this action is in the word "leaves": it destroys every client
certificate the old CA signed, because they can no longer be verified against
anything, and it must destroy nothing else. Server certificates, settings and
DNS accounts are not its business.

The CRL is the subtle one. It is signed by the CA key, so the moment that key
changes the old CRL cannot be verified by anyone, and the revocations it
carried are meaningless: the certificates they revoked cannot be presented
against the new CA anyway. The reset therefore regenerates it rather than
leaving a file that nothing can check.
"""
import json

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from modules.core.client_certificates import ClientCertificateManager
from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance(tmp_path):
    ca_dir = tmp_path / 'certs' / 'ca'
    client_dir = tmp_path / 'certs' / 'client'
    server_dir = tmp_path / 'certificates'
    server_dir.mkdir(parents=True)
    (server_dir / 'example.com').mkdir()
    (server_dir / 'example.com' / 'cert.pem').write_text('a server certificate')
    settings = tmp_path / 'data' / 'settings.json'
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({'dns_provider': 'cloudflare'}))

    ca = PrivateCAGenerator(ca_dir)
    assert ca.initialize()
    manager = ClientCertificateManager(client_dir, ca)
    return manager, ca, ca_dir, client_dir, server_dir, settings


def _issue(manager, name='alice@example.com'):
    ok, error, data = manager.create_client_certificate(common_name=name)
    assert ok, error
    return data


def test_the_ca_is_replaced_and_the_old_one_kept(instance):
    manager, ca, ca_dir, _client, _server, _settings = instance
    before = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes())
    key_before = (ca_dir / 'ca.key').read_bytes()

    ok, error, summary = manager.reset_certificate_authority()
    assert ok, error

    after = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes())
    assert after.serial_number != before.serial_number
    assert (ca_dir / 'ca.key').read_bytes() != key_before
    backups = list(ca_dir.glob('backup*/**/ca.key')) + list(ca_dir.glob('**/ca.key.*'))
    assert backups or summary.get('backup'), (
        'the old CA was discarded without a backup; it is the only thing that '
        'can ever sign a CRL for the certificates it issued'
    )


def test_the_client_certificates_go(instance):
    manager, _ca, _ca_dir, _client, _server, _settings = instance
    _issue(manager, 'alice@example.com')
    _issue(manager, 'bob@example.com')
    assert len(manager.list_client_certificates()) == 2

    ok, error, summary = manager.reset_certificate_authority()
    assert ok, error

    assert manager.list_client_certificates() == []
    assert summary['certificates_removed'] == 2


def test_nothing_else_goes(instance):
    """The reason this is an action and not `rm -rf`."""
    manager, _ca, _ca_dir, _client, server_dir, settings = instance
    _issue(manager)

    ok, error, _summary = manager.reset_certificate_authority()
    assert ok, error

    assert (server_dir / 'example.com' / 'cert.pem').read_text() == 'a server certificate'
    assert json.loads(settings.read_text()) == {'dns_provider': 'cloudflare'}


def test_a_new_subject_can_be_given_at_reset(instance):
    """The reason most people will reach for this: the CA was born Swiss."""
    manager, _ca, ca_dir, _client, _server, _settings = instance

    ok, error, _summary = manager.reset_certificate_authority(subject={
        'country': 'IT', 'organization': 'Acme SpA',
        'common_name': 'Acme Client CA'})
    assert ok, error

    subject = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes()).subject
    assert subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'Acme Client CA'
    assert subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'IT'


def test_a_bad_subject_changes_nothing(instance):
    """Refused before anything is touched, not halfway through."""
    manager, _ca, ca_dir, _client, _server, _settings = instance
    _issue(manager)
    key_before = (ca_dir / 'ca.key').read_bytes()

    ok, error, _summary = manager.reset_certificate_authority(
        subject={'country': 'Italy', 'common_name': 'Acme'})

    assert not ok
    assert 'two-letter' in (error or '').lower()
    assert (ca_dir / 'ca.key').read_bytes() == key_before
    assert len(manager.list_client_certificates()) == 1, (
        'the certificates were destroyed for a reset that then failed'
    )


def test_it_is_written_to_the_audit_log(instance):
    manager, _ca, _ca_dir, _client, _server, _settings = instance
    _issue(manager)
    written = []

    class _Audit:
        # log_operation, not an interface invented for the test: it is what
        # _audit_scheduled_renew already calls on this same collaborator.
        def log_operation(self, **kwargs):
            written.append(kwargs)

    manager.set_audit_logger(_Audit())

    ok, error, _summary = manager.reset_certificate_authority()
    assert ok, error

    assert written, 'a destructive action left no trace in the audit log'
    assert written[0]['operation'] == 'ca_reset'
    assert written[0]['resource_type'] == 'client_ca'
    assert written[0]['details']['certificates_removed'] == 1


def test_certificates_issued_after_the_reset_chain_to_the_new_ca(instance):
    """The point of the whole thing: the CA still works afterwards."""
    manager, _ca, ca_dir, _client, _server, _settings = instance

    ok, error, _summary = manager.reset_certificate_authority()
    assert ok, error
    data = _issue(manager, 'carol@example.com')

    issued = x509.load_pem_x509_certificate(
        data['certificate'].encode() if isinstance(data.get('certificate'), str)
        else manager.get_certificate_file(data['identifier'], 'crt'))
    ca_cert = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes())
    assert issued.issuer == ca_cert.subject
