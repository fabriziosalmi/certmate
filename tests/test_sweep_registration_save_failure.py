"""A failed settings save is not reported as a recovered registration."""
import logging
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('saved', [False, True])
def test_reregistration_counts_only_successful_settings_save(tmp_path, saved, caplog):
    settings = MagicMock()
    settings.update.return_value = saved
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings, dns_manager=MagicMock())
    manager._audit_scheduled_renew = MagicMock()
    summary = {'reregistered': 0}
    with caplog.at_level(logging.ERROR, logger='modules.core.certificates'):
        manager._reregister_domain('example.com', summary)
    assert summary['reregistered'] == int(saved)
    assert manager._audit_scheduled_renew.called is saved
    assert ('could not re-register' in caplog.text) is (not saved)
