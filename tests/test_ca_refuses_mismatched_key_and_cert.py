"""The private CA must not load a key and certificate from different
generations, sign with them, and report itself healthy.

`_load_ca` reads ca.key and ca.crt from two separate files and validated only
expiry — never that the private key matches the certificate. A share-safe
backup carries ca.crt but excludes ca.key (key material), so restoring one
over a node whose ca.key was regenerated leaves a matched-by-filename,
mismatched-by-content pair. CertMate loaded it, reported the CA healthy, and
kept signing: leaf certs then fail verify_directly_issued_by(published_ca),
and a CRL signed with the wrong key is discarded as unauthentic — revocation
fails open. _load_ca now refuses the pair unless the public keys match.
"""
import shutil

import pytest
from cryptography.hazmat.primitives import serialization

from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]


def _pub(obj):
    return obj.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope='module')
def two_generations(tmp_path_factory):
    """Two independently generated CAs, shared across the module: generating a
    4096-bit RSA CA is expensive and these are only ever read from (each test
    copies key/cert out into its own per-test dir), so one pair per module is
    enough (Copilot review)."""
    root = tmp_path_factory.mktemp('cas')
    g1, g2 = root / 'g1', root / 'g2'
    g1.mkdir()
    g2.mkdir()
    assert PrivateCAGenerator(g1).initialize()
    assert PrivateCAGenerator(g2).initialize()
    return g1, g2


def test_a_mismatched_pair_is_refused(two_generations, tmp_path):
    g1, g2 = two_generations
    live = tmp_path / 'live'
    live.mkdir()
    shutil.copy2(g1 / 'ca.key', live / 'ca.key')   # key gen 1
    shutil.copy2(g2 / 'ca.crt', live / 'ca.crt')   # cert gen 2

    ca = PrivateCAGenerator(live)
    assert ca._load_ca() is False
    assert ca.is_ca_loaded() is False


def test_initialize_does_not_regenerate_over_a_mismatch(two_generations, tmp_path):
    """A refused load must not silently regenerate the CA — that would destroy
    the private key an operator may still be able to pair correctly."""
    g1, g2 = two_generations
    live = tmp_path / 'live'
    live.mkdir()
    key_bytes = (g1 / 'ca.key').read_bytes()
    (live / 'ca.key').write_bytes(key_bytes)
    shutil.copy2(g2 / 'ca.crt', live / 'ca.crt')

    assert PrivateCAGenerator(live).initialize() is False
    assert (live / 'ca.key').read_bytes() == key_bytes, \
        "the private key on disk must be untouched"


def test_a_coherent_pair_still_loads(two_generations, tmp_path):
    """CONTROL: a matching key/cert pair must still load, or the check would
    break every legitimate private CA."""
    g1, _ = two_generations
    live = tmp_path / 'live'
    live.mkdir()
    shutil.copy2(g1 / 'ca.key', live / 'ca.key')
    shutil.copy2(g1 / 'ca.crt', live / 'ca.crt')

    ca = PrivateCAGenerator(live)
    assert ca._load_ca() is True
    assert ca.is_ca_loaded() is True
    assert _pub(ca._ca_key) == _pub(ca._ca_cert)


def test_a_freshly_generated_ca_loads(tmp_path):
    """CONTROL: initialize() on an empty dir generates a coherent pair that
    loads clean."""
    d = tmp_path / 'fresh'
    d.mkdir()
    ca = PrivateCAGenerator(d)
    assert ca.initialize() is True
    assert ca.is_ca_loaded() is True
