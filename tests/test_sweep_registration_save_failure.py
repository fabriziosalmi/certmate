"""A failed settings save is not reported as a recovered registration.

Neither is a save that succeeds without keeping the entry: the settings save
drops an entry whose name it does not accept and still answers True, which the
sweep counted as re-registered after every renewal.
"""
import logging
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('saved, kept, counted', [
    (False, [], False),
    (True, [{'domain': 'example.com', 'auto_renew': True}], True),
    (True, [], False),
], ids=['not-saved', 'saved-and-kept', 'saved-but-dropped'])
def test_reregistration_counts_only_an_entry_the_settings_keep(tmp_path, saved, kept, counted, caplog):
    settings = MagicMock()
    settings.update.return_value = saved
    settings.load_settings.return_value = {'domains': kept}
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings, dns_manager=MagicMock())
    manager._audit_scheduled_renew = MagicMock()
    summary = {'reregistered': 0}
    with caplog.at_level(logging.ERROR, logger='modules.core.certificates'):
        manager._reregister_domain('example.com', summary)
    assert summary['reregistered'] == int(counted)
    assert manager._audit_scheduled_renew.called is counted
    assert ('could not re-register' in caplog.text) is (not counted)
