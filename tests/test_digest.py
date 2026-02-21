"""
Unit tests for the WeeklyDigest module.
These run without Docker — they mock the managers.
"""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from modules.core.digest import WeeklyDigest


@pytest.fixture
def mock_managers():
    """Create mock managers for digest tests."""
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'domains': [
            {'domain': 'example.com'},
            {'domain': 'expired.com'},
            {'domain': 'expiring.com'},
        ],
        'renewal_threshold_days': 30,
        'notifications': {
            'enabled': True,
            'digest_enabled': True,
            'channels': {
                'smtp': {
                    'enabled': True,
                    'host': 'smtp.test.com',
                    'port': 587,
                    'username': 'user',
                    'password': 'pass',
                    'from_address': 'test@test.com',
                    'to_addresses': ['admin@test.com'],
                    'use_tls': True,
                },
                'webhooks': []
            }
        }
    }
    settings_mgr.migrate_domains_format.side_effect = lambda s: s

    cert_mgr = MagicMock()
    cert_mgr.cert_dir = Path('/tmp/test_certs_nonexist')

    def get_cert_info(domain):
        if domain == 'example.com':
            return {'domain': domain, 'exists': True, 'days_left': 60}
        elif domain == 'expired.com':
            return {'domain': domain, 'exists': True, 'days_left': -5}
        elif domain == 'expiring.com':
            return {'domain': domain, 'exists': True, 'days_left': 10}
        return None

    cert_mgr.get_certificate_info.side_effect = get_cert_info

    client_cert_mgr = MagicMock()
    client_cert_mgr.list_client_certificates.return_value = [
        {'identifier': 'client1', 'revoked': False},
        {'identifier': 'client2', 'revoked': True},
        {'identifier': 'client3', 'revoked': False},
    ]

    audit_logger = MagicMock()
    audit_logger.get_recent_entries.return_value = [
        {'timestamp': '2099-01-01T00:00:00', 'operation': 'certificate_created', 'status': 'success'},
        {'timestamp': '2099-01-02T00:00:00', 'operation': 'certificate_renewed', 'status': 'success'},
        {'timestamp': '2099-01-03T00:00:00', 'operation': 'certificate_create', 'status': 'failure'},
    ]

    notifier = MagicMock()
    notifier._get_config.return_value = settings_mgr.load_settings()['notifications']

    return {
        'cert_mgr': cert_mgr,
        'client_cert_mgr': client_cert_mgr,
        'audit_logger': audit_logger,
        'notifier': notifier,
        'settings_mgr': settings_mgr,
    }


@pytest.fixture
def digest(mock_managers):
    return WeeklyDigest(
        certificate_manager=mock_managers['cert_mgr'],
        client_cert_manager=mock_managers['client_cert_mgr'],
        audit_logger=mock_managers['audit_logger'],
        notifier=mock_managers['notifier'],
        settings_manager=mock_managers['settings_mgr'],
    )


class TestBuildDigest:
    """Test digest data collection."""

    def test_server_cert_stats(self, digest):
        data = digest.build_digest()
        s = data['server_certs']
        assert s['total'] == 3
        assert s['valid'] == 1
        assert s['expiring_soon'] == 1
        assert s['expired'] == 1
        assert len(s['expiring_domains']) == 1
        assert 'expiring.com' in s['expiring_domains'][0]

    def test_client_cert_stats(self, digest):
        data = digest.build_digest()
        c = data['client_certs']
        assert c['total'] == 3
        assert c['active'] == 2
        assert c['revoked'] == 1

    def test_activity_stats(self, digest):
        data = digest.build_digest()
        a = data['activity']
        assert a['created'] == 1
        assert a['renewed'] == 1
        assert a['failed'] == 1

    def test_has_generated_at(self, digest):
        data = digest.build_digest()
        assert 'generated_at' in data
        assert data['generated_at'].endswith('Z')


class TestFormatDigest:
    """Test text and HTML formatting."""

    def test_text_format(self, digest):
        data = digest.build_digest()
        text = digest._format_text(data)
        assert 'Weekly Certificate Digest' in text
        assert 'Server Certificates' in text
        assert 'Client Certificates' in text
        assert 'expiring.com' in text

    def test_html_format(self, digest):
        data = digest.build_digest()
        html = digest._format_html(data)
        assert '<h2' in html
        assert 'Weekly Digest' in html
        assert 'expiring.com' in html


class TestSendDigest:
    """Test send logic (skip conditions)."""

    def test_skip_when_notifications_disabled(self, digest, mock_managers):
        mock_managers['notifier']._get_config.return_value = {'enabled': False}
        result = digest.send()
        assert result.get('skipped') == 'notifications disabled'

    def test_skip_when_smtp_disabled(self, digest, mock_managers):
        mock_managers['notifier']._get_config.return_value = {
            'enabled': True,
            'channels': {'smtp': {'enabled': False}}
        }
        result = digest.send()
        assert result.get('skipped') == 'SMTP not enabled'

    def test_skip_when_digest_disabled(self, digest, mock_managers):
        mock_managers['notifier']._get_config.return_value = {
            'enabled': True,
            'digest_enabled': False,
            'channels': {'smtp': {'enabled': True}}
        }
        result = digest.send()
        assert result.get('skipped') == 'digest disabled'

    @patch('modules.core.digest.smtplib')
    def test_send_success(self, mock_smtplib, digest):
        mock_server = MagicMock()
        mock_smtplib.SMTP.return_value = mock_server
        result = digest.send()
        assert result.get('success') is True
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()
