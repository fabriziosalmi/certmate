"""
Regression tests for issue #82.

RFC2136 config generation must write the INI keys expected by certbot.
"""

from pathlib import Path

import pytest

from modules.core.utils import create_multi_provider_config


pytestmark = [pytest.mark.unit]


def test_rfc2136_config_uses_certbot_server_key(tmp_path, monkeypatch):
    """RFC2136 credentials files must use dns_rfc2136_server."""
    monkeypatch.chdir(tmp_path)

    config_file = create_multi_provider_config(
        'rfc2136',
        {
            'nameserver': 'ns1.example.com',
            'tsig_key': 'certmate-key',
            'tsig_secret': 'base64-secret',
        },
    )

    assert config_file == Path('letsencrypt/config/rfc2136.ini')
    assert config_file.exists()

    content = config_file.read_text(encoding='utf-8')
    assert 'dns_rfc2136_server = ns1.example.com' in content
    assert 'dns_rfc2136_name = certmate-key' in content
    assert 'dns_rfc2136_secret = base64-secret' in content
    assert 'dns_rfc2136_algorithm = HMAC-SHA512' in content
    assert 'dns_rfc2136_nameserver' not in content

    assert config_file.stat().st_mode & 0o777 == 0o600