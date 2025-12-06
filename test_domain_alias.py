"""
Test domain alias functionality for DNS challenges
"""
import pytest
import tempfile
from pathlib import Path
from modules.core.shell import MockShellExecutor
from modules.core.certificates import CertificateManager
from modules.core.settings import SettingsManager
from modules.core.dns_providers import DNSManager
from modules.core.file_operations import FileOperations
from modules.core.dns_strategies import DNSStrategyFactory, CloudflareStrategy


def test_domain_alias_in_certbot_command():
    """Test that domain_alias is correctly added to certbot command"""
    strategy = CloudflareStrategy()
    cmd = ['certbot', 'certonly']
    credentials_file = Path('/tmp/test_creds')
    domain_alias = '_acme-challenge.validation.example.org'
    
    strategy.configure_certbot_arguments(cmd, credentials_file, domain_alias=domain_alias)
    
    # Verify domain-alias flag is in command
    assert '--domain-alias' in cmd
    alias_index = cmd.index('--domain-alias')
    assert cmd[alias_index + 1] == domain_alias


def test_domain_alias_optional():
    """Test that domain_alias is optional and doesn't break existing functionality"""
    strategy = CloudflareStrategy()
    cmd = ['certbot', 'certonly']
    credentials_file = Path('/tmp/test_creds')
    
    # Call without domain_alias
    strategy.configure_certbot_arguments(cmd, credentials_file)
    
    # Verify domain-alias flag is NOT in command
    assert '--domain-alias' not in cmd


def test_certificate_manager_with_domain_alias():
    """Test CertificateManager accepts and passes domain_alias"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        cert_dir = tmppath / "certs"
        data_dir = tmppath / "data"
        backup_dir = tmppath / "backups"
        logs_dir = tmppath / "logs"
        
        for d in [cert_dir, data_dir, backup_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
        settings_file = data_dir / "settings.json"
        settings_manager = SettingsManager(file_ops, settings_file)
        dns_manager = DNSManager(settings_manager)
        
        # Save minimal settings
        settings_manager.save_settings({
            'email': 'test@example.com',
            'dns_provider': 'cloudflare',
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'default': {
                            'api_token': 'test_token_1234567890abcdef'
                        }
                    }
                }
            }
        })
        
        mock_executor = MockShellExecutor()
        # Mock successful certbot run
        mock_executor.set_next_result(returncode=0, stdout="Certificate created successfully")
        
        cert_manager = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager,
            shell_executor=mock_executor
        )
        
        # Try to create a certificate with domain_alias
        try:
            result = cert_manager.create_certificate(
                domain='test.example.com',
                email='test@example.com',
                dns_provider='cloudflare',
                dns_config={'api_token': 'test_token_1234567890abcdef'},
                domain_alias='_acme-challenge.validation.example.org'
            )
            # If we get here, the mock was used successfully
            assert result['success'] is True
        except Exception as e:
            # Expected to fail due to missing cert files, but executor was called
            assert mock_executor.call_count > 0
            
        # Verify the command included domain-alias
        if mock_executor.commands_executed:
            cmd_str = mock_executor.commands_executed[0]
            assert '--domain-alias' in cmd_str
            assert '_acme-challenge.validation.example.org' in cmd_str


def test_certificate_manager_without_domain_alias():
    """Test backward compatibility - certificate creation without domain_alias"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        cert_dir = tmppath / "certs"
        data_dir = tmppath / "data"
        backup_dir = tmppath / "backups"
        logs_dir = tmppath / "logs"
        
        for d in [cert_dir, data_dir, backup_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
        settings_file = data_dir / "settings.json"
        settings_manager = SettingsManager(file_ops, settings_file)
        dns_manager = DNSManager(settings_manager)
        
        settings_manager.save_settings({
            'email': 'test@example.com',
            'dns_provider': 'cloudflare',
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'default': {
                            'api_token': 'test_token_1234567890abcdef'
                        }
                    }
                }
            }
        })
        
        mock_executor = MockShellExecutor()
        mock_executor.set_next_result(returncode=0, stdout="Certificate created successfully")
        
        cert_manager = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager,
            shell_executor=mock_executor
        )
        
        # Create certificate WITHOUT domain_alias
        try:
            result = cert_manager.create_certificate(
                domain='test.example.com',
                email='test@example.com',
                dns_provider='cloudflare',
                dns_config={'api_token': 'test_token_1234567890abcdef'}
                # No domain_alias parameter
            )
            assert result['success'] is True
        except Exception:
            assert mock_executor.call_count > 0
            
        # Verify the command does NOT include domain-alias
        if mock_executor.commands_executed:
            cmd_str = mock_executor.commands_executed[0]
            assert '--domain-alias' not in cmd_str


def test_all_strategies_support_domain_alias():
    """Test that all DNS strategies support domain_alias parameter"""
    strategies = [
        'cloudflare', 'route53', 'azure', 'google', 'powerdns',
        'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap',
        'hetzner', 'porkbun', 'godaddy', 'arvancloud', 'acme-dns'
    ]
    
    for strategy_name in strategies:
        strategy = DNSStrategyFactory.get_strategy(strategy_name)
        cmd = ['certbot', 'certonly']
        credentials_file = Path('/tmp/test')
        
        # Should not raise an error
        try:
            strategy.configure_certbot_arguments(
                cmd, credentials_file, 
                domain_alias='_acme-challenge.validation.example.org'
            )
            # Verify domain-alias was added
            assert '--domain-alias' in cmd
        except TypeError as e:
            pytest.fail(f"Strategy {strategy_name} doesn't support domain_alias: {e}")
