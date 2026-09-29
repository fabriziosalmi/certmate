"""A reissue keeps the CA account the certificate was issued under.

Found in #983 and fixed there for every reissue, not only the Sectigo one:
`prepare_reissue` never carried `ca_account_id`, so `create_certificate` was
called without it and resolved the CA's DEFAULT account. A certificate issued
under a second account of the same CA (a second ZeroSSL or Sectigo EAB
account, another organisation's key) came back from "Edit & Reissue" issued
under the first one, with nothing in the response to say so.

When the reissue moves to a different CA, the recorded account belongs to the
old one and is not carried over: the new CA's default is used, as before.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.cert_service import CertificateService
from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

DOMAIN = 'example.com'


def _service(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'default_ca': 'zerossl', 'email': 'ops@example.com', 'dns_provider': 'cloudflare',
    }
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), storage_manager=None)
    (tmp_path / DOMAIN).mkdir()
    (tmp_path / DOMAIN / 'cert.pem').write_bytes(b'original certificate')
    manager._load_metadata = lambda domain: {
        'ca_provider': 'zerossl', 'ca_account_id': 'second-org',
        'dns_provider': 'cloudflare', 'account_id': 'cf',
        'challenge_type': 'dns-01', 'san_domains': [],
    }
    return manager, CertificateService(manager, settings, MagicMock())


def test_an_ordinary_dns_reissue_keeps_the_recorded_ca_account(tmp_path):
    manager, service = _service(tmp_path)
    prepared = service.prepare_reissue(domain=DOMAIN, user={})
    assert prepared.get('ca_account_id') == 'second-org'
    with patch.object(manager, 'create_certificate', return_value={'success': True}) as issue:
        service.issue_reissue(prepared)
    assert issue.call_args.kwargs['ca_account_id'] == 'second-org'
    assert issue.call_args.kwargs['challenge_type'] == 'dns-01'


def test_a_reissue_to_another_ca_does_not_carry_the_old_account(tmp_path):
    manager, service = _service(tmp_path)
    prepared = service.prepare_reissue(domain=DOMAIN, ca_provider='letsencrypt', user={})
    assert prepared.get('ca_account_id') is None
    with patch.object(manager, 'create_certificate', return_value={'success': True}) as issue:
        service.issue_reissue(prepared)
    assert issue.call_args.kwargs['ca_account_id'] is None
