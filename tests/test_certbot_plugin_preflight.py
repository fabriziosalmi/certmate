"""Checking Cloudflare must not initialize an unrelated Route53 plugin."""

import subprocess
from unittest.mock import patch

import pytest

from modules.core.dns_strategies import check_certbot_plugin_installed


pytestmark = pytest.mark.unit


def test_installed_plugin_is_found_even_if_another_plugin_cannot_prepare():
    def certbot(cmd, **kwargs):
        assert kwargs['timeout'] == 30
        if '--prepare' in cmd:
            return subprocess.CompletedProcess(cmd, 1, '', 'ProfileNotFound: default')
        return subprocess.CompletedProcess(cmd, 0, '* dns-cloudflare\n* dns-route53\n', '')

    with patch('modules.core.dns_strategies.subprocess.run', side_effect=certbot):
        assert check_certbot_plugin_installed('dns-cloudflare')
        assert not check_certbot_plugin_installed('dns-cloud')
