"""A certificate is issued for its host, and scoped by it, never by its name (#854).

A certificate's name identifies it (its directory, certbot's lineage, the
routes about it); its host is what it certifies. A certificate named apart from
its domain records the host in its metadata as ``host`` (#1360). Asking the CA
for the name instead would request a certificate for ``internal.example.net``
when ``example.com`` is the host it serves, and an API key's scope checked
against the name would judge a name no request ever serves.

So the CA is asked for the host (``-d``, ``--ip-address`` for an address)
while ``--cert-name`` stays the name, the challenge records held around the
run are the host's, a CSR has to cover the host, and the names a scope check
reads start with the host.
"""

import datetime
import json
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from modules.core.ca_manager import CAManager
from modules.core.certificates import CertificateManager
from modules.core.domain_paths import certificate_dir
from modules.core.shell import MockShellExecutor
from tests.test_caa import _cert_mgr

pytestmark = [pytest.mark.unit]

NAME = 'internal.example.net'
HOST = 'example.com'


# --------------------------------------------------------------------------- #
# The command builder
# --------------------------------------------------------------------------- #

def _command(identifier=None, name=NAME, **kwargs):
    cmd, _env = CAManager(MagicMock()).build_certbot_command(
        name, 't@example.com', 'letsencrypt', 'cloudflare', {}, {},
        cert_dir='/tmp', identifier=identifier, **kwargs)
    return cmd


def test_the_ca_is_asked_for_the_identifier_and_the_lineage_keeps_the_name():
    cmd = _command(HOST, san_domains=['api.example.com'])
    assert cmd[cmd.index('--cert-name') + 1] == NAME
    assert [cmd[i + 1] for i, arg in enumerate(cmd) if arg == '-d'] == [HOST, 'api.example.com']


def test_an_address_identifier_goes_in_ip_address():
    cmd = _command('203.0.113.5', name='ip-203-0-113-5')
    assert cmd[cmd.index('--ip-address') + 1] == '203.0.113.5'
    assert '-d' not in cmd


def test_without_an_identifier_the_name_is_asked_for():
    cmd = _command(None, name='shop.example.com')
    assert cmd[cmd.index('-d') + 1] == 'shop.example.com'


# --------------------------------------------------------------------------- #
# A reissue through create_certificate
# --------------------------------------------------------------------------- #

def _issued(cert_dir, metadata):
    directory = certificate_dir(cert_dir, NAME)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'cert.pem').write_text('x')
    (directory / 'metadata.json').write_text(json.dumps({'domain': NAME, **metadata}))
    return directory


def _manager(tmp_path):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=1, stderr='stop here')
    manager = _cert_mgr(tmp_path, shell)
    manager._caa_explanation = lambda *a, **k: ''
    manager.ca_manager = None  # the real builder
    held = []

    @contextmanager
    def records_held(domain, domains, domain_alias, challenge_type):
        held.append(list(domains))
        yield

    manager._challenge_records_held = records_held
    return manager, held


def _reissue(manager, tmp_path, **kwargs):
    with patch('modules.core.certificates.acme_webroot_dir', return_value=tmp_path):
        with pytest.raises(RuntimeError, match='stop here'):
            manager.create_certificate(domain=NAME, email='t@example.com',
                                       ca_provider='letsencrypt', challenge_type='http-01',
                                       replace=True, **kwargs)
    return manager.shell_executor.commands_executed[0].split()


def test_a_reissue_asks_the_ca_for_the_host(tmp_path):
    manager, held = _manager(tmp_path)
    _issued(tmp_path, {'host': HOST})

    cmd = _reissue(manager, tmp_path)

    assert cmd[cmd.index('--cert-name') + 1] == NAME
    assert [cmd[i + 1] for i, arg in enumerate(cmd) if arg == '-d'] == [HOST]
    assert held == [[HOST]]


def test_a_reissue_without_a_host_asks_for_the_name(tmp_path):
    manager, held = _manager(tmp_path)
    _issued(tmp_path, {})

    cmd = _reissue(manager, tmp_path)

    assert [cmd[i + 1] for i, arg in enumerate(cmd) if arg == '-d'] == [NAME]
    assert held == [[NAME]]


def test_a_new_certificate_is_asked_for_as_requested(tmp_path):
    """No metadata exists before the first issuance: the request is the host."""
    manager, held = _manager(tmp_path)
    with patch('modules.core.certificates.acme_webroot_dir', return_value=tmp_path):
        with pytest.raises(RuntimeError, match='stop here'):
            manager.create_certificate(domain='shop.example.com', email='t@example.com',
                                       ca_provider='letsencrypt', challenge_type='http-01')
    cmd = manager.shell_executor.commands_executed[0].split()
    assert [cmd[i + 1] for i, arg in enumerate(cmd) if arg == '-d'] == ['shop.example.com']
    assert held == [['shop.example.com']]


def _csr(*names):
    key = ec.generate_private_key(ec.SECP256R1())
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()).public_bytes(Encoding.PEM).decode())


def test_a_csr_renewal_with_a_csr_for_the_host_reaches_the_ca(tmp_path):
    """In CSR mode the CSR names what is issued (certbot drops -d and
    --cert-name, csr_issuance): what matters is that a CSR for the host is
    accepted, and the records held are the host's."""
    manager, held = _manager(tmp_path)
    _issued(tmp_path, {'host': HOST, 'key_management': 'external'})

    cmd = _reissue(manager, tmp_path, csr_pem=_csr(HOST), renewal=True)

    assert '--csr' in cmd
    assert held == [[HOST]]


def test_a_csr_for_another_name_is_refused_naming_the_host(tmp_path):
    manager, _held = _manager(tmp_path)
    _issued(tmp_path, {'host': HOST, 'key_management': 'external'})

    with patch('modules.core.certificates.acme_webroot_dir', return_value=tmp_path):
        with pytest.raises(RuntimeError, match=f'does not cover {HOST}'):
            manager.create_certificate(domain=NAME, email='t@example.com',
                                       ca_provider='letsencrypt', challenge_type='http-01',
                                       replace=True, renewal=True, csr_pem=_csr(NAME))
    assert manager.shell_executor.commands_executed == []


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def _held_certificate(tmp_path, metadata, sans=()):
    directory = certificate_dir(tmp_path, NAME)
    directory.mkdir(parents=True)
    (directory / 'metadata.json').write_text(json.dumps({'domain': NAME, **metadata}))
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.DNSName(n) for n in (HOST, *sans)]), critical=False)
                   .sign(key, hashes.SHA256()))
    (directory / 'cert.pem').write_bytes(certificate.public_bytes(Encoding.PEM))
    return CertificateManager(tmp_path, MagicMock(), MagicMock())


def test_the_names_a_scope_reads_start_with_the_host(tmp_path):
    manager = _held_certificate(tmp_path, {'host': HOST, 'san_domains': ['api.example.com']},
                                sans=['api.example.com'])
    assert manager.names_covered(NAME) == [HOST, 'api.example.com']


def test_a_key_scoped_to_the_host_covers_the_certificate_and_one_scoped_to_the_name_does_not(tmp_path):
    manager = _held_certificate(tmp_path, {'host': HOST})
    assert manager.every_name_matches(NAME, lambda name: name == HOST)
    assert not manager.every_name_matches(NAME, lambda name: name == NAME)


def test_without_a_host_the_name_comes_first_as_before(tmp_path):
    directory = certificate_dir(tmp_path, 'shop.example.com')
    directory.mkdir(parents=True)
    (directory / 'metadata.json').write_text(json.dumps(
        {'domain': 'shop.example.com', 'san_domains': ['www.shop.example.com']}))
    manager = CertificateManager(tmp_path, MagicMock(), MagicMock())
    assert manager.names_covered('shop.example.com') == ['shop.example.com', 'www.shop.example.com']
