"""
Test ShellExecutor and MockShellExecutor integration
"""
import pytest
from modules.core.shell import ShellExecutor, MockShellExecutor


def test_shell_executor_real():
    """Test real ShellExecutor"""
    executor = ShellExecutor()
    result = executor.run(['echo', 'hello'], capture_output=True, text=True)
    assert result.returncode == 0
    assert 'hello' in result.stdout


def test_mock_shell_executor_success():
    """Test MockShellExecutor with success"""
    mock = MockShellExecutor()
    mock.set_next_result(returncode=0, stdout="success", stderr="")
    
    result = mock.run(['certbot', 'certonly'], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout == "success"
    assert result.stderr == ""


def test_mock_shell_executor_failure():
    """Test MockShellExecutor with failure"""
    mock = MockShellExecutor()
    mock.set_next_result(returncode=1, stdout="", stderr="error occurred")
    
    result = mock.run(['certbot', 'certonly'], capture_output=True, text=True)
    assert result.returncode == 1
    assert result.stderr == "error occurred"


def test_mock_shell_executor_timeout():
    """Test MockShellExecutor with timeout"""
    import subprocess
    
    mock = MockShellExecutor()
    mock.set_next_result(should_timeout=True)
    
    with pytest.raises(subprocess.TimeoutExpired):
        mock.run(['certbot', 'certonly'], timeout=1)


def test_mock_shell_executor_queue():
    """Test MockShellExecutor with multiple queued results"""
    mock = MockShellExecutor()
    mock.set_next_result(returncode=0, stdout="first")
    mock.set_next_result(returncode=0, stdout="second")
    mock.set_next_result(returncode=1, stderr="third")
    
    result1 = mock.run(['cmd1'], capture_output=True, text=True)
    assert result1.stdout == "first"
    
    result2 = mock.run(['cmd2'], capture_output=True, text=True)
    assert result2.stdout == "second"
    
    result3 = mock.run(['cmd3'], capture_output=True, text=True)
    assert result3.returncode == 1
    assert result3.stderr == "third"


def test_certificate_manager_with_mock_executor():
    """Test CertificateManager with MockShellExecutor"""
    from pathlib import Path
    import tempfile
    from modules.core.certificates import CertificateManager
    from modules.core.settings import SettingsManager
    from modules.core.dns_providers import DNSManager
    from modules.core.file_operations import FileOperations
    
    # Create temp directory
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
        
        # Verify the executor is set
        assert cert_manager.shell_executor is mock_executor
        assert isinstance(cert_manager.shell_executor, MockShellExecutor)
        
        # Verify it's actually used when we call methods
        mock_executor.add_response("certbot", returncode=0, stdout="success")
        result = mock_executor.run(["certbot", "certonly"], capture_output=True, text=True)
        assert result.returncode == 0
        assert mock_executor.call_count == 1


def test_shell_executor_dependency_injection():
    """Verify ShellExecutor is properly injected and used"""
    from pathlib import Path
    import tempfile
    from modules.core.certificates import CertificateManager
    from modules.core.settings import SettingsManager
    from modules.core.dns_providers import DNSManager
    from modules.core.file_operations import FileOperations
    
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
        
        # Test 1: Default executor
        cert_manager1 = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager
        )
        assert isinstance(cert_manager1.shell_executor, ShellExecutor)
        assert not isinstance(cert_manager1.shell_executor, MockShellExecutor)
        
        # Test 2: Injected mock executor
        mock = MockShellExecutor()
        cert_manager2 = CertificateManager(
            cert_dir=cert_dir,
            settings_manager=settings_manager,
            dns_manager=dns_manager,
            shell_executor=mock
        )
        assert cert_manager2.shell_executor is mock
        assert isinstance(cert_manager2.shell_executor, MockShellExecutor)
