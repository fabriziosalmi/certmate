"""
Test to verify certificates are added to settings.json after creation (Issue #50)
"""
import pytest
import tempfile
import json
from pathlib import Path
from modules.core.certificates import CertificateManager
from modules.core.settings import SettingsManager
from modules.core.dns_providers import DNSManager
from modules.core.file_operations import FileOperations
from modules.core.shell import MockShellExecutor


def test_certificate_added_to_settings_after_creation():
    """Test that creating a certificate adds the domain to settings.json"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        cert_dir = tmppath / "certs"
        data_dir = tmppath / "data"
        backup_dir = tmppath / "backups"
        logs_dir = tmppath / "logs"
        
        for d in [cert_dir, data_dir, backup_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Initialize managers
        file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
        settings_file = data_dir / "settings.json"
        settings_manager = SettingsManager(file_ops, settings_file)
        dns_manager = DNSManager(settings_manager)
        
        # Create mock executor
        mock_executor = MockShellExecutor()
        
        # Initialize CertificateManager with mock
        cert_manager = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager,
            shell_executor=mock_executor
        )
        
        # Load initial settings and set up DNS provider
        settings = settings_manager.load_settings()
        settings['email'] = 'test@example.com'
        settings['dns_provider'] = 'cloudflare'
        settings['dns_providers'] = {
            'cloudflare': {
                'accounts': {
                    'default': {
                        'api_token': 'test_token_12345'
                    }
                }
            }
        }
        settings['domains'] = []  # Start with empty domains list
        settings_manager.save_settings(settings)
        
        # Set up mock executor to simulate successful certbot execution
        mock_executor.set_next_result(returncode=0, stdout="Certificate created successfully")
        
        # Create certificate directory structure that certbot would create
        test_domain = "test.example.com"
        domain_dir = cert_dir / test_domain
        live_dir = domain_dir / "live" / test_domain
        live_dir.mkdir(parents=True, exist_ok=True)
        
        # Create fake certificate files
        for cert_file in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
            (live_dir / cert_file).write_text(f"fake {cert_file} content")
        
        # Create certificate
        result = cert_manager.create_certificate(
            domain=test_domain,
            email='test@example.com',
            dns_provider='cloudflare',
            account_id='default',
            staging=False
        )
        
        # Verify certificate creation succeeded
        assert result['success'] is True
        assert result['domain'] == test_domain
        
        # Load settings and verify domain was added
        updated_settings = settings_manager.load_settings()
        domains = updated_settings.get('domains', [])
        
        # Verify domain was added to settings
        assert len(domains) == 1, f"Expected 1 domain in settings, found {len(domains)}"
        
        # Verify domain entry format
        domain_entry = domains[0]
        assert isinstance(domain_entry, dict), "Domain entry should be a dict"
        assert domain_entry['domain'] == test_domain
        assert domain_entry['dns_provider'] == 'cloudflare'
        assert domain_entry['account_id'] == 'default'


def test_certificate_not_duplicated_in_settings():
    """Test that creating a certificate twice doesn't duplicate the domain in settings.json"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        cert_dir = tmppath / "certs"
        data_dir = tmppath / "data"
        backup_dir = tmppath / "backups"
        logs_dir = tmppath / "logs"
        
        for d in [cert_dir, data_dir, backup_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Initialize managers
        file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
        settings_file = data_dir / "settings.json"
        settings_manager = SettingsManager(file_ops, settings_file)
        dns_manager = DNSManager(settings_manager)
        
        # Create mock executor
        mock_executor = MockShellExecutor()
        
        # Initialize CertificateManager with mock
        cert_manager = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager,
            shell_executor=mock_executor
        )
        
        # Load initial settings and set up DNS provider
        settings = settings_manager.load_settings()
        settings['email'] = 'test@example.com'
        settings['dns_provider'] = 'cloudflare'
        settings['dns_providers'] = {
            'cloudflare': {
                'accounts': {
                    'default': {
                        'api_token': 'test_token_12345'
                    }
                }
            }
        }
        # Pre-add the domain in dict format
        test_domain = "existing.example.com"
        settings['domains'] = [
            {
                'domain': test_domain,
                'dns_provider': 'cloudflare',
                'account_id': 'default'
            }
        ]
        settings_manager.save_settings(settings)
        
        # Set up mock executor to simulate successful certbot execution
        mock_executor.set_next_result(returncode=0, stdout="Certificate renewed successfully")
        
        # Create certificate directory structure
        domain_dir = cert_dir / test_domain
        live_dir = domain_dir / "live" / test_domain
        live_dir.mkdir(parents=True, exist_ok=True)
        
        # Create fake certificate files
        for cert_file in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
            (live_dir / cert_file).write_text(f"fake {cert_file} content")
        
        # Create certificate again (simulating renewal or recreation)
        result = cert_manager.create_certificate(
            domain=test_domain,
            email='test@example.com',
            dns_provider='cloudflare',
            account_id='default',
            staging=False
        )
        
        # Verify certificate creation succeeded
        assert result['success'] is True
        
        # Load settings and verify domain was not duplicated
        updated_settings = settings_manager.load_settings()
        domains = updated_settings.get('domains', [])
        
        # Should still have only 1 domain
        assert len(domains) == 1, f"Expected 1 domain in settings, found {len(domains)}"
        assert domains[0]['domain'] == test_domain


def test_certificate_added_with_string_format_existing():
    """Test that new certificates are added correctly even when existing domains are in string format"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        cert_dir = tmppath / "certs"
        data_dir = tmppath / "data"
        backup_dir = tmppath / "backups"
        logs_dir = tmppath / "logs"
        
        for d in [cert_dir, data_dir, backup_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Initialize managers
        file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
        settings_file = data_dir / "settings.json"
        settings_manager = SettingsManager(file_ops, settings_file)
        dns_manager = DNSManager(settings_manager)
        
        # Create mock executor
        mock_executor = MockShellExecutor()
        
        # Initialize CertificateManager with mock
        cert_manager = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager,
            shell_executor=mock_executor
        )
        
        # Load initial settings and set up DNS provider
        settings = settings_manager.load_settings()
        settings['email'] = 'test@example.com'
        settings['dns_provider'] = 'cloudflare'
        settings['dns_providers'] = {
            'cloudflare': {
                'accounts': {
                    'default': {
                        'api_token': 'test_token_12345'
                    }
                }
            }
        }
        # Pre-add a domain in old string format (backward compatibility)
        settings['domains'] = ['old-format.example.com']
        settings_manager.save_settings(settings)
        
        # Set up mock executor to simulate successful certbot execution
        mock_executor.set_next_result(returncode=0, stdout="Certificate created successfully")
        
        # Create certificate directory structure
        test_domain = "new.example.com"
        domain_dir = cert_dir / test_domain
        live_dir = domain_dir / "live" / test_domain
        live_dir.mkdir(parents=True, exist_ok=True)
        
        # Create fake certificate files
        for cert_file in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
            (live_dir / cert_file).write_text(f"fake {cert_file} content")
        
        # Create certificate
        result = cert_manager.create_certificate(
            domain=test_domain,
            email='test@example.com',
            dns_provider='cloudflare',
            account_id='default',
            staging=False
        )
        
        # Verify certificate creation succeeded
        assert result['success'] is True
        
        # Load settings and verify both domains exist
        updated_settings = settings_manager.load_settings()
        domains = updated_settings.get('domains', [])
        
        # Should have 2 domains now
        assert len(domains) == 2, f"Expected 2 domains in settings, found {len(domains)}"
        
        # Both should be in dict format (settings manager auto-migrates string format to dict)
        assert isinstance(domains[0], dict)
        assert domains[0]['domain'] == 'old-format.example.com'
        
        # Second should be new dict format
        assert isinstance(domains[1], dict)
        assert domains[1]['domain'] == test_domain


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
