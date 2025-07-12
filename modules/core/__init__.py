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
    'InfisicalBackend'
]
