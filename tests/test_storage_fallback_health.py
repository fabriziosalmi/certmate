"""P2 (2026-07-02 audit): when the configured storage backend fails to
initialise, StorageManager silently falls back to local disk — the operator
believes certs are in Azure/Vault/S3 but they are on (often ephemeral) local
disk. That split-brain was only a log line; StorageManager now records it and
/health surfaces it as 'degraded'."""
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import StorageManager

pytestmark = [pytest.mark.unit]


def _mgr(storage_config):
    sm = MagicMock()
    sm.load_settings.return_value = {'certificate_storage': storage_config}
    return StorageManager(sm)


def test_no_fallback_for_local_backend():
    mgr = _mgr({'backend': 'local_filesystem'})
    assert mgr.get_fallback_backend() is None


def test_fallback_recorded_for_unknown_backend():
    mgr = _mgr({'backend': 'definitely-not-a-real-backend'})
    # Falls back to local, but records what the operator asked for.
    assert mgr.get_fallback_backend() == 'definitely-not-a-real-backend'


def test_fallback_recorded_on_backend_init_failure(monkeypatch):
    """A configured cloud backend that raises on construction must fall back to
    local AND record the split-brain (this is the real-world case: wrong creds
    / missing field)."""
    import modules.core.storage_backends as sb

    class _Boom:
        def __init__(self, *a, **kw):
            raise ValueError('bad config')

    monkeypatch.setattr(sb, 'AzureKeyVaultBackend', _Boom)
    mgr = _mgr({'backend': 'azure_keyvault', 'azure_keyvault': {}})
    assert mgr.get_fallback_backend() == 'azure_keyvault'
    # And it still serves a working (local) backend rather than crashing.
    assert mgr.get_backend() is not None
