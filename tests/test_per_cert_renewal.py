"""
Unit tests for issue #111: per-certificate auto-renewal disabling.

The DELETE certificate endpoint shipped in v2.3.8 (#105) — the only new
backend behavior here is the per-cert auto_renew flag, which gates renewal
in CertificateManager.check_renewals and is mutated via set_auto_renew.

These tests do not require Docker — they exercise the certificate manager
and settings manager directly with a temporary data directory.
"""

from unittest.mock import MagicMock
from types import SimpleNamespace

import pytest

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


@pytest.fixture
def cert_manager(tmp_path):
    """Build a CertificateManager wired to a tmp directory.

    DNS / CA managers are unused by the code paths under test, so we
    pass MagicMocks. get_certificate_info is monkey-patched per-test
    when needed.
    """
    base_dir = tmp_path
    cert_dir = base_dir / "certificates"
    data_dir = base_dir / "data"
    backup_dir = base_dir / "backups"
    logs_dir = base_dir / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()

    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    settings_file = data_dir / "settings.json"
    settings_manager = SettingsManager(file_ops=file_ops, settings_file=settings_file)

    cm = CertificateManager(
        cert_dir=cert_dir,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
    )
    return cm


def _seed_settings(cm: CertificateManager, domains):
    settings = cm.settings_manager.load_settings()
    settings['email'] = 'test@example.com'
    settings['domains'] = domains
    settings['auto_renew'] = True
    cm.settings_manager.save_settings(settings, "test_seed")


def test_check_renewals_skips_disabled_domain(cert_manager, monkeypatch):
    """A domain entry with auto_renew=False must not be renewed."""
    _seed_settings(cert_manager, [
        {'domain': 'enabled.example.com', 'dns_provider': 'cloudflare',
         'account_id': 'default', 'auto_renew': True},
        {'domain': 'disabled.example.com', 'dns_provider': 'cloudflare',
         'account_id': 'default', 'auto_renew': False},
    ])

    # Both certs report needs_renewal=True so the only thing protecting the
    # disabled one is the new per-cert flag.
    monkeypatch.setattr(
        cert_manager,
        'get_certificate_info',
        lambda domain, settings=None: {
            'domain': domain,
            'exists': True,
            'needs_renewal': True,
            'days_until_expiry': 5,
        },
    )

    renewed = []
    monkeypatch.setattr(
        cert_manager,
        'renew_certificate',
        lambda domain: renewed.append(domain) or {'dns_provider': 'cloudflare'},
    )

    cert_manager.check_renewals()

    assert renewed == ['enabled.example.com'], (
        f"Only the enabled cert should be renewed; got {renewed}"
    )


def test_check_renewals_legacy_string_entries_default_to_enabled(cert_manager, monkeypatch):
    """Legacy string-form domain entries renew normally (no opt-out)."""
    _seed_settings(cert_manager, ['legacy.example.com'])

    monkeypatch.setattr(
        cert_manager,
        'get_certificate_info',
        lambda domain, settings=None: {'domain': domain, 'exists': True, 'needs_renewal': True},
    )
    renewed = []
    monkeypatch.setattr(
        cert_manager,
        'renew_certificate',
        lambda domain: renewed.append(domain) or {},
    )

    cert_manager.check_renewals()

    assert renewed == ['legacy.example.com']


def test_forced_renew_adds_certbot_force_flag(cert_manager, tmp_path):
    domain_dir = cert_manager.cert_dir / "force.example.com"
    domain_dir.mkdir()
    (domain_dir / "cert.pem").write_text("placeholder cert")
    (domain_dir / "live" / "force.example.com").mkdir(parents=True)

    cert_manager.shell_executor.run = MagicMock(
        return_value=SimpleNamespace(returncode=0, stdout="", stderr="")
    )

    result = cert_manager.renew_certificate("force.example.com", force=True)

    assert result["success"] is True
    cmd = cert_manager.shell_executor.run.call_args.args[0]
    assert "--force-renewal" in cmd


def test_scheduled_renew_uses_certbot_due_logic(cert_manager, tmp_path):
    domain_dir = cert_manager.cert_dir / "scheduled.example.com"
    domain_dir.mkdir()
    (domain_dir / "cert.pem").write_text("placeholder cert")
    (domain_dir / "live" / "scheduled.example.com").mkdir(parents=True)

    cert_manager.shell_executor.run = MagicMock(
        return_value=SimpleNamespace(returncode=0, stdout="", stderr="")
    )

    result = cert_manager.renew_certificate("scheduled.example.com")

    assert result["success"] is True
    cmd = cert_manager.shell_executor.run.call_args.args[0]
    assert "--force-renewal" not in cmd


def test_set_auto_renew_persists_flag(cert_manager):
    """set_auto_renew updates the dict entry and saves to disk."""
    _seed_settings(cert_manager, [
        {'domain': 'a.example.com', 'dns_provider': 'cloudflare', 'account_id': 'default'},
    ])

    assert cert_manager.set_auto_renew('a.example.com', False) is True

    settings = cert_manager.settings_manager.load_settings()
    entry = next(d for d in settings['domains'] if d['domain'] == 'a.example.com')
    assert entry['auto_renew'] is False

    # Re-enabling flips it back.
    assert cert_manager.set_auto_renew('a.example.com', True) is True
    settings = cert_manager.settings_manager.load_settings()
    entry = next(d for d in settings['domains'] if d['domain'] == 'a.example.com')
    assert entry['auto_renew'] is True


def test_set_auto_renew_unknown_domain_returns_false(cert_manager):
    """set_auto_renew on a domain not in settings is a no-op."""
    _seed_settings(cert_manager, [
        {'domain': 'known.example.com', 'dns_provider': 'cloudflare', 'account_id': 'default'},
    ])
    assert cert_manager.set_auto_renew('unknown.example.com', False) is False


def test_set_auto_renew_upgrades_legacy_string_entry(cert_manager):
    """A legacy string entry should be upgraded to dict so the flag persists."""
    _seed_settings(cert_manager, ['legacy.example.com'])

    assert cert_manager.set_auto_renew('legacy.example.com', False) is True

    settings = cert_manager.settings_manager.load_settings()
    entry = next(
        d for d in settings['domains']
        if isinstance(d, dict) and d.get('domain') == 'legacy.example.com'
    )
    assert entry['auto_renew'] is False
