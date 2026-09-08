"""Reading a certificate should not re-validate a private key that has not changed.

`private_key_state` answers "is there a usable private key beside this
certificate", and it answers it by loading the key — which OpenSSL validates as
it parses. That is not a cheap parse. Measured on one machine at the commit
this file was written against:

    load_pem_private_key   RSA-2048    51.6 ms
    load_pem_private_key   RSA-4096   275.5 ms
    load_pem_private_key   EC P-256     0.020 ms

    get_certificate_info, real RSA-2048 key beside the certificate   58.7 ms
    get_certificate_info, key present but unparseable                 0.19 ms

CertMate's default key shape is `rsa`/2048 (see `settings.py`), so on the
common installation ~99% of the cost of reading one certificate's information
was re-answering a question whose inputs had not moved. It is called once per
domain by the dashboard listing, by every Prometheus collection (serially, on
the request thread) and by every renewal sweep.

The answer is a pure function of two files' contents, so it is remembered per
`(sha256(privkey.pem), sha256(cert.pem))`. Hashing both costs tens of
microseconds against tens of milliseconds, and — unlike an mtime or a TTL — it
is exact: any change to either file produces a different digest and the
comparison runs again. That matters here more than it usually would, because
the three ways these files change are renewal, re-keying, and a torn publish
leaving a new certificate beside the previous key, and the last one is the
condition this check exists to catch.

What is asserted below is the number of parses, not the elapsed time: a
wall-clock ceiling measures the runner, and the reliable response to a flaky
one is to raise it until it never fires. The timing is printed instead
(`pytest -s`), in the same spirit as tests/test_three_operations_have_a_number.py.
"""
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


def _key(kind='ec'):
    if kind == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def _pem_pair(key, common_name='perf.example.com', days_left=60):
    """A self-signed certificate for *key*, and the key, both PEM."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now + timedelta(days=days_left))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(common_name)]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


@pytest.fixture
def manager(tmp_path):
    cert_dir = tmp_path / 'certificates'
    data_dir = tmp_path / 'data'
    for directory in (cert_dir, data_dir, tmp_path / 'backups', tmp_path / 'logs'):
        directory.mkdir()
    file_ops = FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                              backup_dir=tmp_path / 'backups',
                              logs_dir=tmp_path / 'logs')
    settings = SettingsManager(file_ops=file_ops,
                               settings_file=data_dir / 'settings.json')
    return CertificateManager(cert_dir=cert_dir, settings_manager=settings,
                              dns_manager=None, shell_executor=None)


def _plant(manager, domain, cert_pem, key_pem=None):
    directory = manager.cert_dir / domain
    directory.mkdir(exist_ok=True)
    (directory / 'cert.pem').write_bytes(cert_pem)
    if key_pem is not None:
        (directory / 'privkey.pem').write_bytes(key_pem)
    return directory


@pytest.fixture
def parses(monkeypatch):
    """Count how often a private key is actually parsed.

    Patched on the cryptography module rather than on CertMate's own helper:
    the property under test is 'the expensive operation does not happen twice',
    and hanging the count on our own seam would keep passing if that seam were
    refactored away.
    """
    calls = []
    real = serialization.load_pem_private_key

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(serialization, 'load_pem_private_key', counting)
    return calls


# --- THE regression ------------------------------------------------------

def test_the_key_is_parsed_once_across_repeated_reads(manager, parses):
    key = _key()
    cert_pem, key_pem = _pem_pair(key)
    _plant(manager, 'perf.example.com', cert_pem, key_pem)

    answers = {manager.private_key_state('perf.example.com', cert_pem)
               for _ in range(10)}

    assert answers == {'present'}
    assert len(parses) == 1, (
        f'{len(parses)} private-key parses for 10 reads of the same unchanged '
        f'files — the answer is being recomputed per read again')


# --- the answer itself is unchanged --------------------------------------

def test_a_matching_key_is_present(manager):
    key = _key()
    cert_pem, key_pem = _pem_pair(key)
    _plant(manager, 'a.example.com', cert_pem, key_pem)

    assert manager.private_key_state('a.example.com', cert_pem) == 'present'


def test_a_key_from_another_issuance_is_mismatched(manager):
    cert_pem, _ = _pem_pair(_key())
    _, other_key_pem = _pem_pair(_key())
    _plant(manager, 'b.example.com', cert_pem, other_key_pem)

    assert manager.private_key_state('b.example.com', cert_pem) == 'mismatched'


def test_no_key_at_all_is_missing(manager):
    cert_pem, _ = _pem_pair(_key())
    _plant(manager, 'c.example.com', cert_pem)

    assert manager.private_key_state('c.example.com', cert_pem) == 'missing'


def test_a_csr_only_certificate_is_external(manager):
    """The key was never ours to hold, so its absence is the feature (#599)."""
    cert_pem, _ = _pem_pair(_key())
    _plant(manager, 'd.example.com', cert_pem)

    assert manager.private_key_state(
        'd.example.com', cert_pem,
        {'key_management': 'external'}) == 'external'


def test_no_certificate_to_compare_against_is_present(manager):
    """The cheap path: a key file exists and there is nothing to compare it
    with, so nothing is parsed and nothing is remembered."""
    cert_pem, key_pem = _pem_pair(_key())
    _plant(manager, 'e.example.com', cert_pem, key_pem)

    assert manager.private_key_state('e.example.com') == 'present'


# --- the cache cannot answer for files that moved ------------------------

def test_a_rekeyed_certificate_is_compared_again(manager, parses):
    key = _key()
    cert_pem, key_pem = _pem_pair(key)
    directory = _plant(manager, 'f.example.com', cert_pem, key_pem)
    assert manager.private_key_state('f.example.com', cert_pem) == 'present'

    _, foreign_key_pem = _pem_pair(_key())
    (directory / 'privkey.pem').write_bytes(foreign_key_pem)

    assert manager.private_key_state('f.example.com', cert_pem) == 'mismatched'
    assert len(parses) == 2, 'the replaced key was answered from the cache'


def test_a_renewed_certificate_is_compared_again(manager, parses):
    """THE case this check exists for. A promote that tore leaves a NEW
    cert.pem beside the PREVIOUS privkey.pem; if the certificate side were not
    part of the key, the cached 'present' from before the renewal would hide
    exactly that."""
    key = _key()
    cert_pem, key_pem = _pem_pair(key)
    _plant(manager, 'g.example.com', cert_pem, key_pem)
    assert manager.private_key_state('g.example.com', cert_pem) == 'present'

    renewed_pem, _ = _pem_pair(_key())  # new generation, and a new key with it

    assert manager.private_key_state('g.example.com', renewed_pem) == 'mismatched'
    assert len(parses) == 2, 'the new certificate was answered from the cache'


def test_identical_bytes_rewritten_still_hit(manager, parses):
    """The key is the content, not the timestamp. Republishing the same bytes
    — which `reconcile_served_copies` can do — must not cost another parse."""
    key = _key()
    cert_pem, key_pem = _pem_pair(key)
    directory = _plant(manager, 'h.example.com', cert_pem, key_pem)
    assert manager.private_key_state('h.example.com', cert_pem) == 'present'

    time.sleep(0.01)
    (directory / 'privkey.pem').write_bytes(key_pem)

    assert manager.private_key_state('h.example.com', cert_pem) == 'present'
    assert len(parses) == 1


# --- controls ------------------------------------------------------------

def test_two_domains_do_not_share_an_answer(manager, parses):
    """CONTROL. A cache keyed carelessly would let one domain's verdict answer
    for another, which for this particular answer means reporting a keyless
    certificate as healthy."""
    key = _key()
    cert_pem, key_pem = _pem_pair(key)
    _plant(manager, 'i.example.com', cert_pem, key_pem)
    _, foreign_key_pem = _pem_pair(_key())
    _plant(manager, 'j.example.com', cert_pem, foreign_key_pem)

    assert manager.private_key_state('i.example.com', cert_pem) == 'present'
    assert manager.private_key_state('j.example.com', cert_pem) == 'mismatched'
    assert len(parses) == 2


def test_an_unparseable_key_is_never_remembered_as_present(manager):
    """CONTROL. The failure arm returns 'mismatched' and that is what must be
    remembered — a cache that stored the optimistic answer on the error path
    would report a certificate whose key cannot be loaded as servable."""
    cert_pem, _ = _pem_pair(_key())
    _plant(manager, 'k.example.com', cert_pem, b'-----BEGIN PRIVATE KEY-----\nnope\n')

    assert manager.private_key_state('k.example.com', cert_pem) == 'mismatched'
    assert manager.private_key_state('k.example.com', cert_pem) == 'mismatched'


def test_the_expensive_half_is_still_reachable_on_its_own(manager, parses):
    """CONTROL for the split: the comparison must still be the thing that
    decides, so a test that stubs the cache away gets the real answer."""
    key = _key()
    cert_pem, key_pem = _pem_pair(key)

    assert manager._compare_key_to_certificate(
        'l.example.com', key_pem, cert_pem) == 'present'
    assert len(parses) == 1


# --- what it is worth, measured rather than asserted ---------------------

@pytest.mark.parametrize('kind', ['rsa', 'ec'])
def test_report_the_cost_of_a_repeated_read(manager, kind):
    """Not a ceiling — a number to compare against. Printed with `-s`.

    Measured while writing this (Apple silicon, warm page cache):

        rsa  first read 45.14 ms, repeat 0.03 ms
        ec   first read  0.08 ms, repeat 0.02 ms

    The RSA row is the default installation.
    """
    domain = f'cost-{kind}.example.com'
    cert_pem, key_pem = _pem_pair(_key(kind), common_name=domain)
    _plant(manager, domain, cert_pem, key_pem)

    started = time.perf_counter()
    first = manager.private_key_state(domain, cert_pem)
    cold = time.perf_counter() - started

    started = time.perf_counter()
    for _ in range(20):
        manager.private_key_state(domain, cert_pem)
    warm = (time.perf_counter() - started) / 20

    print(f'\n{kind}: first read {cold * 1000:.2f} ms, '
          f'repeat {warm * 1000:.2f} ms')
    assert first == 'present'
