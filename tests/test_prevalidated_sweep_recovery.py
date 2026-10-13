"""Disk-only Sectigo certificates do not need DNS credentials to renew."""
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('provider,renewable', [('sectigo', True), ('letsencrypt', False)])
def test_disk_only_prevalidated_sweep_uses_ca_not_dns(tmp_path, provider, renewable):
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=MagicMock(), dns_manager=MagicMock())
    (tmp_path / 'example.com').mkdir()
    assert manager._save_metadata('example.com', {'ca_provider': provider, 'challenge_type': 'prevalidated'})
    manager._renew_if_due = MagicMock(return_value=True)
    manager._reregister_domain = MagicMock()
    summary = {'checked': 0, 'unmanaged': 0}
    manager._sweep_unregistered('example.com', {}, summary)
    assert summary == {'checked': int(renewable), 'unmanaged': int(not renewable)}
    assert manager._renew_if_due.called is renewable
    assert manager._reregister_domain.called is renewable
    manager.dns_manager.get_dns_provider_account_config.assert_not_called()
