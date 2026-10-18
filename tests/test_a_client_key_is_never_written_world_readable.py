"""A client certificate's private key is 0600 from its first byte.

Both places that write one used open() and chmod-ed afterwards, so the key
existed for a moment under the process umask (0644 on most hosts), and a
crash in between left it there. They now write through the CA's atomic
writer: a 0600 temporary file, renamed into place.
"""
import builtins
import stat

import pytest

from tests.test_a_client_identity_the_operator_can_describe import manager  # noqa: F401

pytestmark = [pytest.mark.unit]


@pytest.fixture
def key_opens(monkeypatch):
    """Every file ending in .key that open() is asked to write."""
    seen = []
    real_open = builtins.open

    def watching(file, mode='r', *args, **kwargs):
        if str(file).endswith('.key') and any(m in mode for m in 'wax'):
            seen.append(str(file))
        return real_open(file, mode, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', watching)
    return seen


def test_a_generated_client_key(manager, key_opens):  # noqa: F811
    ok, err, data = manager.create_client_certificate(common_name='alice.example.com')
    assert ok, err
    key = next((manager._get_cert_subdir('api-mtls') / data['identifier']).glob('*.key'))
    assert key_opens == []
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


def test_a_saved_csr_key(tmp_path, key_opens):
    from modules.core.csr_handler import CSRHandler
    ok, _csr, _key_path = CSRHandler.save_csr_and_key(b'csr', b'private key', tmp_path, 'probe')
    assert ok
    assert key_opens == []
    assert stat.S_IMODE((tmp_path / 'probe.key').stat().st_mode) == 0o600
