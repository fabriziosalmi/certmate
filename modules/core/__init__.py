"""
Core module for CertMate
Contains core functionality including file operations, settings, authentication, 
certificate management, DNS providers, cache management, and storage backends
"""

from .file_operations import FileOperations
from .settings import SettingsManager
from .auth import AuthManager
from .certificates import CertificateManager
from .dns_providers import DNSManager
from .cache import CacheManager
from .storage_backends import (
    StorageManager,
    CertificateStorageBackend,
    LocalFileSystemBackend,
    AzureKeyVaultBackend,
    AWSSecretsManagerBackend,
    HashiCorpVaultBackend,
    InfisicalBackend
)
from .private_ca import PrivateCAGenerator
from .csr_handler import CSRHandler
from .client_certificates import ClientCertificateManager
from .ocsp_crl import OCSPResponder, CRLManager
from .audit import AuditLogger
from .rate_limit import RateLimitConfig, SimpleRateLimiter, rate_limit_decorator
from .structured_logging import (
    get_logger,
    get_certmate_logger,
    configure_structured_logging,
    LogContext,
    set_context,
    clear_context,
    timed,
    log_request,
    JSONFormatter
)

__all__ = [
    'FileOperations',
    'SettingsManager',
    'AuthManager',
    'CertificateManager',
    'DNSManager',
    'CacheManager',
    'StorageManager',
    'CertificateStorageBackend',
    'LocalFileSystemBackend',
    'AzureKeyVaultBackend',
    'AWSSecretsManagerBackend',
    'HashiCorpVaultBackend',
    'InfisicalBackend',
    'PrivateCAGenerator',
    'CSRHandler',
    'ClientCertificateManager',
    'OCSPResponder',
    'CRLManager',
    'AuditLogger',
    'RateLimitConfig',
    'SimpleRateLimiter',
    'rate_limit_decorator',
    # Structured logging
    'get_logger',
    'get_certmate_logger',
    'configure_structured_logging',
    'LogContext',
    'set_context',
    'clear_context',
    'timed',
    'log_request',
    'JSONFormatter'
]
