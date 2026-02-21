"""
Certificate storage backends module for CertMate
Provides pluggable storage solutions for certificate storage including 
local filesystem, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, and Infisical
"""

import os
import json
import logging
import re
import tempfile
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from .constants import CERTIFICATE_FILES

logger = logging.getLogger(__name__)

_SAFE_DOMAIN_RE = re.compile(r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$')


def _validate_storage_domain(domain: str) -> str:
    """Validate domain name for use in storage backend paths/keys.
    Raises ValueError if domain contains path traversal or invalid chars."""
    if not domain or '..' in domain or '/' in domain or '\\' in domain or '\x00' in domain:
        raise ValueError(f"Invalid domain for storage: contains illegal characters")
    if not _SAFE_DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain for storage: does not match domain pattern")
    return domain


class CertificateStorageBackend(ABC):
    """Abstract base class for certificate storage backends"""
    
    @abstractmethod
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata for a domain"""
        pass
    
    @abstractmethod
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata for a domain"""
        pass
    
    @abstractmethod
    def list_certificates(self) -> List[str]:
        """List all stored certificate domains"""
        pass
    
    @abstractmethod
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate for a domain"""
        pass
    
    @abstractmethod
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists for a domain"""
        pass

    @abstractmethod
    def get_backend_name(self) -> str:
        """Get the name of this storage backend"""
        pass


class LocalFileSystemBackend(CertificateStorageBackend):
    """Local filesystem storage backend (default/legacy behavior)"""
    
    def __init__(self, cert_dir: Path):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"LocalFileSystemBackend initialized with cert_dir: {self.cert_dir}")
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to local filesystem"""
        try:
            domain_dir = self.cert_dir / domain
            domain_dir.mkdir(parents=True, exist_ok=True)
            
            # Store certificate files
            for filename, content in cert_files.items():
                file_path = domain_dir / filename
                with open(file_path, 'wb') as f:
                    f.write(content)
                # Set secure permissions for private keys
                if 'key' in filename.lower() or filename == 'privkey.pem':
                    os.chmod(file_path, 0o600)
                else:
                    os.chmod(file_path, 0o644)
            
            # Store metadata
            metadata_file = domain_dir / 'metadata.json'
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Certificate stored successfully for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from local filesystem"""
        try:
            domain_dir = self.cert_dir / domain
            if not domain_dir.exists():
                return None
            
            cert_files = {}
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                file_path = domain_dir / filename
                if file_path.exists():
                    with open(file_path, 'rb') as f:
                        cert_files[filename] = f.read()
            
            # Load metadata
            metadata = {}
            metadata_file = domain_dir / 'metadata.json'
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in local filesystem"""
        try:
            domains = []
            if self.cert_dir.exists():
                for domain_dir in self.cert_dir.iterdir():
                    if domain_dir.is_dir() and (domain_dir / 'cert.pem').exists():
                        domains.append(domain_dir.name)
            return sorted(domains)
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from local filesystem"""
        try:
            import shutil
            domain_dir = self.cert_dir / domain
            if domain_dir.exists():
                shutil.rmtree(domain_dir)
                logger.info(f"Certificate deleted for {domain}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete certificate for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in local filesystem"""
        domain_dir = self.cert_dir / domain
        return domain_dir.exists() and (domain_dir / 'cert.pem').exists()
    
    def get_backend_name(self) -> str:
        return "local_filesystem"


class AzureKeyVaultBackend(CertificateStorageBackend):
    """Azure Key Vault storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.vault_url = config.get('vault_url')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.tenant_id = config.get('tenant_id')
        
        if not all([self.vault_url, self.client_id, self.client_secret, self.tenant_id]):
            raise ValueError("Azure Key Vault backend requires vault_url, client_id, client_secret, and tenant_id")
        
        self._client = None
        logger.info(f"AzureKeyVaultBackend initialized for vault: {self.vault_url}")
    
    def _get_client(self):
        """Get Azure Key Vault client with lazy initialization"""
        if self._client is None:
            try:
                from azure.keyvault.secrets import SecretClient
                from azure.identity import ClientSecretCredential
                
                credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                self._client = SecretClient(vault_url=self.vault_url, credential=credential)
            except ImportError:
                raise ImportError("Azure Key Vault backend requires 'azure-keyvault-secrets' and 'azure-identity' packages")
        return self._client
    
    def _sanitize_secret_name(self, name: str) -> str:
        """Sanitize name for Azure Key Vault secret naming requirements"""
        # Azure Key Vault secret names can only contain alphanumeric characters and hyphens
        import re
        sanitized = re.sub(r'[^a-zA-Z0-9-]', '-', name)
        return sanitized.strip('-')
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to Azure Key Vault"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Store certificate files as individual secrets
            for filename, content in cert_files.items():
                secret_name = self._sanitize_secret_name(f"cert-{domain}-{filename.replace('.', '-')}")
                client.set_secret(secret_name, content.decode('utf-8'))
            
            # Store metadata
            metadata_name = self._sanitize_secret_name(f"cert-{domain}-metadata")
            client.set_secret(metadata_name, json.dumps(metadata))
            
            logger.info(f"Certificate stored successfully in Azure Key Vault for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in Azure Key Vault for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from Azure Key Vault"""
        try:
            client = self._get_client()
            
            cert_files = {}
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                try:
                    secret_name = self._sanitize_secret_name(f"cert-{domain}-{filename.replace('.', '-')}")
                    secret = client.get_secret(secret_name)
                    cert_files[filename] = secret.value.encode('utf-8')
                except Exception as e:
                    logger.debug(f"Secret {secret_name} not found for {domain}: {e}")
                    continue

            if not cert_files:
                return None

            # Load metadata
            metadata = {}
            try:
                metadata_name = self._sanitize_secret_name(f"cert-{domain}-metadata")
                secret = client.get_secret(metadata_name)
                metadata = json.loads(secret.value)
            except Exception as e:
                logger.debug(f"Metadata not found in Azure Key Vault for {domain}: {e}")
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Azure Key Vault for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in Azure Key Vault"""
        try:
            client = self._get_client()
            domains = set()
            
            for secret_properties in client.list_properties_of_secrets():
                if secret_properties.name.startswith('cert-') and secret_properties.name.endswith('-cert-pem'):
                    # Extract domain from secret name
                    domain = secret_properties.name.replace('cert-', '').replace('-cert-pem', '').replace('-', '.')
                    domains.add(domain)
            
            return sorted(list(domains))
            
        except Exception as e:
            logger.error(f"Failed to list certificates from Azure Key Vault: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from Azure Key Vault"""
        try:
            client = self._get_client()
            
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                try:
                    secret_name = self._sanitize_secret_name(f"cert-{domain}-{filename.replace('.', '-')}")
                    client.begin_delete_secret(secret_name)
                except Exception as e:
                    logger.debug(f"Could not delete secret {secret_name} for {domain}: {e}")
                    continue

            # Delete metadata
            try:
                metadata_name = self._sanitize_secret_name(f"cert-{domain}-metadata")
                client.begin_delete_secret(metadata_name)
            except Exception as e:
                logger.debug(f"Could not delete metadata for {domain} from Azure Key Vault: {e}")
            
            logger.info(f"Certificate deleted from Azure Key Vault for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from Azure Key Vault for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in Azure Key Vault"""
        try:
            client = self._get_client()
            secret_name = self._sanitize_secret_name(f"cert-{domain}-cert-pem")
            client.get_secret(secret_name)
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "azure_keyvault"


class AWSSecretsManagerBackend(CertificateStorageBackend):
    """AWS Secrets Manager storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.region = config.get('region', 'us-east-1')
        self.access_key_id = config.get('access_key_id')
        self.secret_access_key = config.get('secret_access_key')
        
        if not all([self.access_key_id, self.secret_access_key]):
            raise ValueError("AWS Secrets Manager backend requires access_key_id and secret_access_key")
        
        self._client = None
        logger.info(f"AWSSecretsManagerBackend initialized for region: {self.region}")
    
    def _get_client(self):
        """Get AWS Secrets Manager client with lazy initialization"""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    'secretsmanager',
                    region_name=self.region,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key
                )
            except ImportError:
                raise ImportError("AWS Secrets Manager backend requires 'boto3' package")
        return self._client
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to AWS Secrets Manager"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Combine all certificate data into a single secret
            secret_data = {
                'files': {k: v.decode('utf-8') for k, v in cert_files.items()},
                'metadata': metadata
            }
            
            secret_name = f"certmate/certificates/{domain}"
            
            try:
                # Try to update existing secret
                client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_data)
                )
            except client.exceptions.ResourceNotFoundException:
                # Create new secret
                client.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_data),
                    Description=f"SSL certificate for {domain} managed by CertMate"
                )
            
            logger.info(f"Certificate stored successfully in AWS Secrets Manager for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in AWS Secrets Manager for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"certmate/certificates/{domain}"
            
            response = client.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response['SecretString'])
            
            cert_files = {k: v.encode('utf-8') for k, v in secret_data.get('files', {}).items()}
            metadata = secret_data.get('metadata', {})
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from AWS Secrets Manager for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in AWS Secrets Manager"""
        try:
            client = self._get_client()
            domains = []
            
            paginator = client.get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    name = secret['Name']
                    if name.startswith('certmate/certificates/'):
                        domain = name.replace('certmate/certificates/', '')
                        domains.append(domain)
            
            return sorted(domains)
            
        except Exception as e:
            logger.error(f"Failed to list certificates from AWS Secrets Manager: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"certmate/certificates/{domain}"
            
            client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            
            logger.info(f"Certificate deleted from AWS Secrets Manager for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from AWS Secrets Manager for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"certmate/certificates/{domain}"
            client.describe_secret(SecretId=secret_name)
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "aws_secrets_manager"


class HashiCorpVaultBackend(CertificateStorageBackend):
    """HashiCorp Vault storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.vault_url = config.get('vault_url')
        self.vault_token = config.get('vault_token')
        self.mount_point = config.get('mount_point', 'secret')
        self.engine_version = config.get('engine_version', 'v2')
        
        if not all([self.vault_url, self.vault_token]):
            raise ValueError("HashiCorp Vault backend requires vault_url and vault_token")
        
        self._client = None
        logger.info(f"HashiCorpVaultBackend initialized for vault: {self.vault_url}")
    
    def _get_client(self):
        """Get HashiCorp Vault client with lazy initialization"""
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(url=self.vault_url, token=self.vault_token)
                if not self._client.is_authenticated():
                    raise ValueError("Failed to authenticate with HashiCorp Vault")
            except ImportError:
                raise ImportError("HashiCorp Vault backend requires 'hvac' package")
        return self._client
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to HashiCorp Vault"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Prepare secret data
            secret_data = {
                'files': {k: v.decode('utf-8') for k, v in cert_files.items()},
                'metadata': metadata
            }
            
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                client.secrets.kv.v2.create_or_update_secret(
                    path=secret_path,
                    secret=secret_data,
                    mount_point=self.mount_point
                )
            else:
                client.secrets.kv.v1.create_or_update_secret(
                    path=secret_path,
                    secret=secret_data,
                    mount_point=self.mount_point
                )
            
            logger.info(f"Certificate stored successfully in HashiCorp Vault for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in HashiCorp Vault for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from HashiCorp Vault"""
        try:
            client = self._get_client()
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                response = client.secrets.kv.v2.read_secret_version(
                    path=secret_path,
                    mount_point=self.mount_point
                )
                secret_data = response['data']['data']
            else:
                response = client.secrets.kv.v1.read_secret(
                    path=secret_path,
                    mount_point=self.mount_point
                )
                secret_data = response['data']
            
            cert_files = {k: v.encode('utf-8') for k, v in secret_data.get('files', {}).items()}
            metadata = secret_data.get('metadata', {})
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from HashiCorp Vault for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in HashiCorp Vault"""
        try:
            client = self._get_client()
            
            if self.engine_version == 'v2':
                response = client.secrets.kv.v2.list_secrets(
                    path="certmate/certificates",
                    mount_point=self.mount_point
                )
            else:
                response = client.secrets.kv.v1.list_secrets(
                    path="certmate/certificates",
                    mount_point=self.mount_point
                )
            
            return sorted(response.get('data', {}).get('keys', []))
            
        except Exception as e:
            logger.error(f"Failed to list certificates from HashiCorp Vault: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from HashiCorp Vault"""
        try:
            client = self._get_client()
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            else:
                client.secrets.kv.v1.delete_secret(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            
            logger.info(f"Certificate deleted from HashiCorp Vault for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from HashiCorp Vault for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in HashiCorp Vault"""
        try:
            client = self._get_client()
            secret_path = f"certmate/certificates/{domain}"
            
            if self.engine_version == 'v2':
                client.secrets.kv.v2.read_secret_version(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            else:
                client.secrets.kv.v1.read_secret(
                    path=secret_path,
                    mount_point=self.mount_point
                )
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "hashicorp_vault"


class InfisicalBackend(CertificateStorageBackend):
    """Infisical storage backend"""
    
    def __init__(self, config: Dict[str, str]):
        self.site_url = config.get('site_url', 'https://app.infisical.com')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.project_id = config.get('project_id')
        self.environment = config.get('environment', 'prod')
        
        if not all([self.client_id, self.client_secret, self.project_id]):
            raise ValueError("Infisical backend requires client_id, client_secret, and project_id")
        
        self._client = None
        logger.info(f"InfisicalBackend initialized for project: {self.project_id}")
    
    def _get_client(self):
        """Get Infisical client with lazy initialization"""
        if self._client is None:
            try:
                from infisical import InfisicalClient, ClientSettings
                
                settings = ClientSettings(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    site_url=self.site_url
                )
                self._client = InfisicalClient(settings)
            except ImportError:
                raise ImportError("Infisical backend requires 'infisical-python' package")
        return self._client
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate files and metadata to Infisical"""
        try:
            _validate_storage_domain(domain)
            client = self._get_client()

            # Store certificate files as individual secrets
            for filename, content in cert_files.items():
                secret_key = f"certmate-{domain}-{filename.replace('.', '-')}"
                client.create_secret(
                    secret_name=secret_key,
                    secret_value=content.decode('utf-8'),
                    project_id=self.project_id,
                    environment=self.environment
                )
            
            # Store metadata
            metadata_key = f"certmate-{domain}-metadata"
            client.create_secret(
                secret_name=metadata_key,
                secret_value=json.dumps(metadata),
                project_id=self.project_id,
                environment=self.environment
            )
            
            logger.info(f"Certificate stored successfully in Infisical for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store certificate in Infisical for {domain}: {e}")
            return False
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate files and metadata from Infisical"""
        try:
            client = self._get_client()
            
            cert_files = {}
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                try:
                    secret_key = f"certmate-{domain}-{filename.replace('.', '-')}"
                    secret = client.get_secret(
                        secret_name=secret_key,
                        project_id=self.project_id,
                        environment=self.environment
                    )
                    cert_files[filename] = secret.secret_value.encode('utf-8')
                except Exception as e:
                    logger.debug(f"Secret {secret_key} not found for {domain}: {e}")
                    continue

            if not cert_files:
                return None

            # Load metadata
            metadata = {}
            try:
                metadata_key = f"certmate-{domain}-metadata"
                secret = client.get_secret(
                    secret_name=metadata_key,
                    project_id=self.project_id,
                    environment=self.environment
                )
                metadata = json.loads(secret.secret_value)
            except Exception as e:
                logger.debug(f"Metadata not found in Infisical for {domain}: {e}")
            
            return cert_files, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Infisical for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[str]:
        """List all certificate domains in Infisical"""
        try:
            client = self._get_client()
            domains = set()
            
            secrets = client.list_secrets(
                project_id=self.project_id,
                environment=self.environment
            )
            
            for secret in secrets:
                if secret.secret_name.startswith('certmate-') and secret.secret_name.endswith('-cert-pem'):
                    # Extract domain from secret name
                    domain = secret.secret_name.replace('certmate-', '').replace('-cert-pem', '').replace('-', '.')
                    domains.add(domain)
            
            return sorted(list(domains))
            
        except Exception as e:
            logger.error(f"Failed to list certificates from Infisical: {e}")
            return []
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate from Infisical"""
        try:
            client = self._get_client()
            
            standard_files = list(CERTIFICATE_FILES)
            
            for filename in standard_files:
                try:
                    secret_key = f"certmate-{domain}-{filename.replace('.', '-')}"
                    client.delete_secret(
                        secret_name=secret_key,
                        project_id=self.project_id,
                        environment=self.environment
                    )
                except Exception as e:
                    logger.debug(f"Could not delete secret {secret_key} for {domain}: {e}")
                    continue

            # Delete metadata
            try:
                metadata_key = f"certmate-{domain}-metadata"
                client.delete_secret(
                    secret_name=metadata_key,
                    project_id=self.project_id,
                    environment=self.environment
                )
            except Exception as e:
                logger.debug(f"Could not delete metadata for {domain} from Infisical: {e}")
            
            logger.info(f"Certificate deleted from Infisical for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete certificate from Infisical for {domain}: {e}")
            return False
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists in Infisical"""
        try:
            client = self._get_client()
            secret_key = f"certmate-{domain}-cert-pem"
            client.get_secret(
                secret_name=secret_key,
                project_id=self.project_id,
                environment=self.environment
            )
            return True
        except Exception:
            return False
    
    def get_backend_name(self) -> str:
        return "infisical"


class StorageManager:
    """Manager class for certificate storage backends"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        self._backend = None
        self._initialized = False
    
    def _initialize_backend(self):
        """Initialize storage backend based on settings"""
        if self._initialized:
            return
        
        try:
            settings = self.settings_manager.load_settings()
            storage_config = settings.get('certificate_storage', {})
            backend_type = storage_config.get('backend', 'local_filesystem')
            
            if backend_type == 'local_filesystem':
                # Default local filesystem backend
                cert_dir = Path(storage_config.get('cert_dir', 'certificates'))
                self._backend = LocalFileSystemBackend(cert_dir)
                
            elif backend_type == 'azure_keyvault':
                config = storage_config.get('azure_keyvault', {})
                self._backend = AzureKeyVaultBackend(config)
                
            elif backend_type == 'aws_secrets_manager':
                config = storage_config.get('aws_secrets_manager', {})
                self._backend = AWSSecretsManagerBackend(config)
                
            elif backend_type == 'hashicorp_vault':
                config = storage_config.get('hashicorp_vault', {})
                self._backend = HashiCorpVaultBackend(config)
                
            elif backend_type == 'infisical':
                config = storage_config.get('infisical', {})
                self._backend = InfisicalBackend(config)
                
            else:
                logger.warning(f"Unknown storage backend: {backend_type}, falling back to local filesystem")
                cert_dir = Path('certificates')
                self._backend = LocalFileSystemBackend(cert_dir)
            
            self._initialized = True
            logger.info(f"Storage backend initialized: {self._backend.get_backend_name()}")
            
        except Exception as e:
            logger.error(f"Failed to initialize storage backend: {e}")
            # Fallback to local filesystem
            self._backend = LocalFileSystemBackend(Path('certificates'))
            self._initialized = True
    
    def get_backend(self) -> CertificateStorageBackend:
        """Get the current storage backend"""
        self._initialize_backend()
        return self._backend
    
    def store_certificate(self, domain: str, cert_files: Dict[str, bytes], metadata: Dict[str, Any]) -> bool:
        """Store certificate using the configured backend"""
        backend = self.get_backend()
        return backend.store_certificate(domain, cert_files, metadata)
    
    def retrieve_certificate(self, domain: str) -> Optional[Tuple[Dict[str, bytes], Dict[str, Any]]]:
        """Retrieve certificate using the configured backend"""
        backend = self.get_backend()
        return backend.retrieve_certificate(domain)
    
    def list_certificates(self) -> List[str]:
        """List certificates using the configured backend"""
        backend = self.get_backend()
        return backend.list_certificates()
    
    def delete_certificate(self, domain: str) -> bool:
        """Delete certificate using the configured backend"""
        backend = self.get_backend()
        return backend.delete_certificate(domain)
    
    def certificate_exists(self, domain: str) -> bool:
        """Check if certificate exists using the configured backend"""
        backend = self.get_backend()
        return backend.certificate_exists(domain)
    
    def get_backend_name(self) -> str:
        """Get the name of the current storage backend"""
        backend = self.get_backend()
        return backend.get_backend_name()
    
    def migrate_certificates(self, source_backend: CertificateStorageBackend, target_backend: CertificateStorageBackend) -> Dict[str, bool]:
        """Migrate certificates from one backend to another"""
        migration_results = {}
        
        try:
            domains = source_backend.list_certificates()
            logger.info(f"Starting migration of {len(domains)} certificates from {source_backend.get_backend_name()} to {target_backend.get_backend_name()}")
            
            for domain in domains:
                try:
                    # Retrieve from source
                    cert_data = source_backend.retrieve_certificate(domain)
                    if cert_data:
                        cert_files, metadata = cert_data
                        # Store in target
                        success = target_backend.store_certificate(domain, cert_files, metadata)
                        migration_results[domain] = success
                        if success:
                            logger.info(f"Successfully migrated certificate for {domain}")
                        else:
                            logger.error(f"Failed to migrate certificate for {domain}")
                    else:
                        migration_results[domain] = False
                        logger.error(f"Failed to retrieve certificate for {domain} from source backend")
                except Exception as e:
                    migration_results[domain] = False
                    logger.error(f"Error migrating certificate for {domain}: {e}")
            
            successful = sum(1 for success in migration_results.values() if success)
            logger.info(f"Migration completed: {successful}/{len(domains)} certificates migrated successfully")
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
        
        return migration_results
