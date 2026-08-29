"""initialize() must not regenerate the CA when only one of ca.crt/ca.key is present.

The guard loaded the CA only when BOTH files existed; with exactly one present
(a masked restore that brought back ca.crt without ca.key, a failed extraction,
operator error) it fell through to _generate_ca(), which overwrites BOTH files
with a brand-new CA and no backup (the backup is gated on force). That silently
destroys either the ca.crt every deployed client trusts, or the only copy of the
signing key — after which no CRL can ever be signed for the old CA again.

initialize() now refuses on a partial CA and leaves the surviving file untouched.
"""
import shutil

import pytest

from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def real_ca_files(tmp_path_factory):
    """A genuine ca.crt/ca.key pair to plant (4096-bit keygen once)."""
    d = tmp_path_factory.mktemp('src')
    assert PrivateCAGenerator(d).initialize()
    return (d / 'ca.crt').read_bytes(), (d / 'ca.key').read_bytes()


def _plant(tmp_path, files):
    d = tmp_path / 'ca'
    d.mkdir()
    for name, data in files.items():
        (d / name).write_bytes(data)
    return d, PrivateCAGenerator(d)


def test_only_the_cert_present_is_refused_and_preserved(real_ca_files, tmp_path):
    crt, _key = real_ca_files
    d, ca = _plant(tmp_path, {'ca.crt': crt})
    assert ca.initialize() is False
    assert (d / 'ca.crt').read_bytes() == crt, "surviving ca.crt was destroyed"
    assert not (d / 'ca.key').exists(), "a new key must not be generated"


def test_only_the_key_present_is_refused_and_preserved(real_ca_files, tmp_path):
    _crt, key = real_ca_files
    d, ca = _plant(tmp_path, {'ca.key': key})
    assert ca.initialize() is False
    assert (d / 'ca.key').read_bytes() == key, "surviving ca.key was destroyed"
    assert not (d / 'ca.crt').exists()


def test_a_complete_ca_still_loads(real_ca_files, tmp_path):
    """CONTROL: both files present must still load, not be treated as partial."""
    crt, key = real_ca_files
    d, ca = _plant(tmp_path, {'ca.crt': crt, 'ca.key': key})
    assert ca.initialize() is True
    assert ca.is_ca_loaded() is True
    assert (d / 'ca.crt').read_bytes() == crt


def test_an_empty_dir_still_generates(tmp_path):
    """CONTROL: first run (neither file present) must generate a CA."""
    d = tmp_path / 'ca'
    d.mkdir()
    ca = PrivateCAGenerator(d)
    assert ca.initialize() is True
    assert (d / 'ca.crt').exists() and (d / 'ca.key').exists()


def test_force_still_regenerates_over_a_partial(real_ca_files, tmp_path):
    """A deliberate force must still regenerate even from a partial state — the
    refusal is only for the accidental (non-force) case."""
    crt, _key = real_ca_files
    d, ca = _plant(tmp_path, {'ca.crt': crt})
    assert ca.initialize(force=True) is True
    assert (d / 'ca.key').exists(), "force must produce a full new CA"
