"""Two things the renewal path did not have that issuance did.

1. REQUESTS_CA_BUNDLE. ``build_certbot_command`` hands certbot the private
   CA's trust bundle at issuance; ``renew_certificate`` built its own
   environment and never read ``ca_provider``, so every renewal against a
   private ACME CA with a self-signed endpoint failed TLS verification —
   silently, until the certificate expired.
2. A corrupt metadata.json was read with a bare json.load under a bare
   except, replaced by ``{}`` in memory, and then saved back with
   ``renewed_at`` — every other key gone, no ``.corrupt-*`` copy, success
   reported. ``_load_metadata`` already quarantined; renewal did not use it.
"""
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIB-private-root\n-----END CERTIFICATE-----\n"


def _build_cm(tmp_path, shell, ca_manager=None):
    cert_dir, data_dir, backup_dir, logs_dir = (
        tmp_path / "certificates", tmp_path / "data", tmp_path / "backups", tmp_path / "logs")
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                              backup_dir=backup_dir, logs_dir=logs_dir)
    settings_manager = SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")
    return CertificateManager(cert_dir=cert_dir, settings_manager=settings_manager,
                              dns_manager=MagicMock(), ca_manager=ca_manager,
                              shell_executor=shell)


def _seed(cm, domain, metadata_text):
    domain_dir = cm.cert_dir / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "cert.pem").write_text("placeholder")
    (domain_dir / "metadata.json").write_text(metadata_text)
    return domain_dir


def _real_ca_manager():
    """A CAManager whose private_ca account carries a trust bundle —
    get_ca_config / create_ca_trust_bundle are the real methods."""
    from modules.core.ca_manager import CAManager
    cam = CAManager.__new__(CAManager)
    cam.get_ca_config = MagicMock(return_value=({'ca_cert': CA_PEM, 'acme_url': 'https://ca.internal/acme/directory'}, 'default'))
    return cam


def test_renewal_against_a_private_ca_carries_the_trust_bundle(tmp_path):
    shell = MagicMock()
    shell.run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="bail")
    cm = _build_cm(tmp_path, shell, ca_manager=_real_ca_manager())
    _seed(cm, "app.internal", '{"domain": "app.internal", "ca_provider": "private_ca", "dns_provider": "cloudflare"}')
    cm.dns_manager.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')

    with pytest.raises(RuntimeError):
        cm.renew_certificate("app.internal", force=True)

    env = shell.run.call_args.kwargs['env']
    bundle = env.get('REQUESTS_CA_BUNDLE')
    assert bundle, "renewal did not hand certbot the private CA trust bundle"
    cm.ca_manager.get_ca_config.assert_called_once_with('private_ca', None)
    # The temp bundle is removed once certbot has run, like the credentials ini.
    assert not os.path.exists(bundle)


def test_renewal_against_a_public_ca_leaves_the_environment_alone(tmp_path, monkeypatch):
    monkeypatch.delenv('REQUESTS_CA_BUNDLE', raising=False)
    shell = MagicMock()
    shell.run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="bail")
    cam = _real_ca_manager()
    cm = _build_cm(tmp_path, shell, ca_manager=cam)
    _seed(cm, "example.com", '{"domain": "example.com", "ca_provider": "letsencrypt", "dns_provider": "cloudflare"}')
    cm.dns_manager.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')
    with pytest.raises(RuntimeError):
        cm.renew_certificate("example.com", force=True)
    assert 'REQUESTS_CA_BUNDLE' not in shell.run.call_args.kwargs['env']
    cam.get_ca_config.assert_not_called()


def test_a_missing_ca_account_does_not_block_the_attempt(tmp_path):
    shell = MagicMock()
    shell.run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="bail")
    cam = _real_ca_manager()
    cam.get_ca_config = MagicMock(side_effect=ValueError("no such CA account"))
    cm = _build_cm(tmp_path, shell, ca_manager=cam)
    _seed(cm, "app.internal", '{"domain": "app.internal", "ca_provider": "private_ca", "dns_provider": "cloudflare"}')
    cm.dns_manager.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')
    with pytest.raises(RuntimeError):
        cm.renew_certificate("app.internal", force=True)
    assert shell.run.called
    assert 'REQUESTS_CA_BUNDLE' not in shell.run.call_args.kwargs['env']


def test_corrupt_metadata_is_quarantined_not_overwritten(tmp_path):
    shell = MagicMock()
    shell.run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="bail")
    cm = _build_cm(tmp_path, shell)
    truncated = '{"domain": "example.com", "dns_provider": "cloudflare", "san_domains": ["a.exa'
    domain_dir = _seed(cm, "example.com", truncated)

    with pytest.raises(RuntimeError):
        cm.renew_certificate("example.com", force=True)

    quarantined = list(domain_dir.glob("metadata.json.corrupt-*"))
    assert quarantined, "the unreadable metadata was not set aside"
    assert quarantined[0].read_text() == truncated, "the quarantined copy must be byte-identical"
    assert not (domain_dir / "metadata.json").exists() or \
        (domain_dir / "metadata.json").read_text() != '{}', \
        "metadata.json must not be replaced by an empty object"
