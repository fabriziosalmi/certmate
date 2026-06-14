"""deSEC and Scaleway DNS-01 wiring.

Both are generic multi-provider entries (no dedicated strategy class). The only
provider-specific logic is the credential -> certbot-plugin INI key mapping in
_MULTI_PROVIDER_TEMPLATE_MAP; getting that key wrong silently breaks auth. These
tests pin the exact INI key each plugin expects:
  - certbot-dns-desec      -> dns_desec_token
  - certbot-dns-scaleway   -> dns_scaleway_application_token
"""
import pytest

from modules.core.utils import create_multi_provider_config

pytestmark = [pytest.mark.unit]


def test_desec_config_writes_plugin_ini_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = create_multi_provider_config('desec', {'api_token': 'tok-desec-123'})
    assert path is not None, "deSEC config not written"
    assert path.read_text().strip() == 'dns_desec_token = tok-desec-123'
    # credentials file carries a secret -> must be 0600
    assert (path.stat().st_mode & 0o777) == 0o600


def test_scaleway_config_writes_plugin_ini_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = create_multi_provider_config('scaleway', {'application_token': 'scw-secret-key'})
    assert path is not None, "Scaleway config not written"
    assert path.read_text().strip() == 'dns_scaleway_application_token = scw-secret-key'
    assert (path.stat().st_mode & 0o777) == 0o600


def test_missing_credential_returns_none(tmp_path, monkeypatch):
    """An empty/missing credential must fail validation and write no file."""
    monkeypatch.chdir(tmp_path)
    assert create_multi_provider_config('desec', {'api_token': ''}) is None
    assert create_multi_provider_config('scaleway', {}) is None
