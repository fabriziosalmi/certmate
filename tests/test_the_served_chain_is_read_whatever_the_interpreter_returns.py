"""The served chain is read from what `get_unverified_chain()` returns, in either form.

Python 3.13 added `SSLSocket.get_unverified_chain()` and it returns the chain as
DER `bytes`. `_served_chain_der` read each entry as an object with
`public_bytes()`, which `bytes` does not have: every entry raised
`AttributeError`, was skipped, and the probe reported no served chain for every
server, silently, with `chain_available` false. The image runs 3.12, which has no
getter, so the line never ran in production, and CI runs only 3.12, so the one
test written for 3.13+ (`test_probe_live_server_serves_chain`) never took its 3.13+
branch either. The fake sockets here exercise the reading on any interpreter.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core import cert_probe

pytestmark = [pytest.mark.unit]


def _der(common_name):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


class _Socket:
    def __init__(self, chain):
        self._chain = chain

    def get_unverified_chain(self):
        return self._chain


class _ObjectEntry:
    """What an older interpreter's certificate object looked like: public_bytes(format)."""

    def __init__(self, der):
        self._der = der

    def public_bytes(self, encoding):
        return self._der


def test_der_bytes_as_python_3_13_returns_them_are_the_chain():
    leaf, root = _der('leaf'), _der('root')
    assert cert_probe._served_chain_der(_Socket([leaf, root])) == [leaf, root]


def test_a_bytearray_is_accepted_too():
    leaf = _der('leaf')
    assert cert_probe._served_chain_der(_Socket([bytearray(leaf)])) == [leaf]


def test_certificate_objects_are_still_read():
    leaf, root = _der('leaf'), _der('root')
    assert cert_probe._served_chain_der(
        _Socket([_ObjectEntry(leaf), _ObjectEntry(root)])) == [leaf, root]


def test_what_cannot_be_read_is_skipped_not_fatal():
    leaf = _der('leaf')
    assert cert_probe._served_chain_der(_Socket([object(), leaf])) == [leaf]


def test_no_getter_is_an_empty_chain():
    assert cert_probe._served_chain_der(object()) == []


def test_the_chain_the_probe_reports_comes_from_those_bytes():
    chain = cert_probe._served_chain(cert_probe._served_chain_der(_Socket([_der('leaf'), _der('root')])))
    assert [entry['subject_cn'] for entry in chain] == ['leaf', 'root']
