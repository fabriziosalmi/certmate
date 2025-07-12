"""
File operations module for CertMate
Handles file I/O, backup management, and safe file operations
"""

import os
import json
import tempfile
import zipfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import fcntl
import logging

logger = logging.getLogger(__name__)

# Backup constants
BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
MAX_BACKUPS_PER_TYPE = 50   # Maximum number of backups to keep per type


class FileOperations:
    """Class to handle file operations and backup management"""
    
    def __init__(self, cert_dir, data_dir, backup_dir, logs_dir):
        self.cert_dir = Path(cert_dir)
        self.data_dir = Path(data_dir)
        self.backup_dir = Path(backup_dir)
        self.logs_dir = Path(logs_dir)
        self.allowed_dirs = [
            self.cert_dir.resolve(),
            self.data_dir.resolve(),
            self.backup_dir.resolve(),
            self.logs_dir.resolve()
        ]

    def safe_file_read(self, file_path, is_json=False, default=None):
        """Safely read a file with proper error handling and file locking"""
        try:
            # Validate file path to prevent path traversal
            file_path = Path(file_path).resolve()
            
            # Ensure the file is within allowed directories
            if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in self.allowed_dirs):
                logger.error(f"Access denied: file outside allowed directories: {file_path}")
                return default
            
            if not file_path.exists():
                return default
                
            with open(file_path, 'r', encoding='utf-8') as f:
                # Use file locking for safety
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    content = f.read()
                    if is_json:
                        return json.loads(content) if content.strip() else default
                    return content
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return default
        except Exception as e:
            logger.error(f"Unexpected error reading file {file_path}: {e}")
            return default

    def safe_file_write(self, file_path, data, is_json=True):
        """Safely write data to a file with proper error handling and atomic operations"""
        try:
            # Validate file path to prevent path traversal
            file_path = Path(file_path).resolve()
            
            # Ensure the file is within allowed directories
            if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in self.allowed_dirs):
                logger.error(f"Access denied: file outside allowed directories: {file_path}")
                return False
            
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temporary file for atomic writes
            temp_file = Path(f"{file_path}.tmp")
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                # Use file locking for safety
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    if is_json:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(str(data))
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomic move
            temp_file.rename(file_path)
            
            # Set proper permissions
            os.chmod(file_path, 0o600)
            
            return True
            
        except (PermissionError, OSError) as e:
            logger.error(f"Error writing file {file_path}: {e}")
            # Clean up temp file if it exists
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error writing file {file_path}: {e}")
            # Clean up temp file if it exists
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False

    def create_unified_backup(self, settings_data, backup_reason="manual"):
        """Create a unified backup containing both settings and certificates"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_id = f"backup_{timestamp}_{backup_reason}"
            backup_filename = f"{backup_id}.zip"
            backup_path = self.backup_dir / "unified" / backup_filename
            
            # Ensure backup directory exists
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create unified backup metadata
            domains = []
            if self.cert_dir.exists():
                for domain_dir in self.cert_dir.iterdir():
                    if domain_dir.is_dir():
                        domains.append(domain_dir.name)
            
            metadata = {
                "backup_id": backup_id,
                "timestamp": datetime.now().isoformat(),
                "backup_reason": backup_reason,
                "version": "2.0.0",  # New unified format
                "type": "unified",
                "domains": domains,
                "settings_domains": [d.get('domain') if isinstance(d, dict) else d for d in settings_data.get('domains', [])],
                "total_domains": len(domains)
            }
            
            # Create ZIP file with both settings and certificates
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add settings data
                settings_backup = {
                    "metadata": metadata,
                    "settings": settings_data
                }
                zipf.writestr("settings.json", json.dumps(settings_backup, indent=2))
                
                # Add all certificate files
                if self.cert_dir.exists():
                    for domain_dir in self.cert_dir.iterdir():
                        if domain_dir.is_dir():
                            for cert_file in domain_dir.rglob("*"):
                                if cert_file.is_file():
                                    # Add file to zip with relative path under certificates/
                                    arc_path = f"certificates/{cert_file.relative_to(self.cert_dir)}"
                                    zipf.write(cert_file, arc_path)
                
                # Add unified metadata
                zipf.writestr("backup_metadata.json", json.dumps(metadata, indent=2))
            
            logger.info(f"Unified backup created: {backup_filename} (contains {len(domains)} domains)")
            return backup_filename
                
        except Exception as e:
            logger.error(f"Error creating unified backup: {e}")
            return None

    def create_settings_backup(self, settings_data, backup_reason="manual"):
        """Legacy method - creates unified backup for backward compatibility"""
        logger.warning("create_settings_backup is deprecated. Use create_unified_backup instead.")
        return self.create_unified_backup(settings_data, backup_reason)

    def create_certificates_backup(self, backup_reason="manual"):
        """Legacy method - redirect to unified backup creation"""
        logger.warning("create_certificates_backup is deprecated. Use create_unified_backup instead.")
        # We need settings to create a unified backup, so load current settings
        try:
            from modules.core.settings import SettingsManager
            settings_manager = SettingsManager(self.data_dir)
            settings_data = settings_manager.load_settings()
            return self.create_unified_backup(settings_data, backup_reason)
        except Exception as e:
            logger.error(f"Cannot create certificates backup without settings: {e}")
            return None

    def cleanup_old_settings_backups(self):
        """Remove old settings backups based on retention policy"""
        try:
            settings_backup_dir = self.backup_dir / "settings"
            if not settings_backup_dir.exists():
                return 0
                
            backup_files = []
            for backup_file in settings_backup_dir.glob("settings_*.json"):
                try:
                    stat = backup_file.stat()
                    backup_files.append((backup_file, datetime.fromtimestamp(stat.st_mtime)))
                except Exception as e:
                    logger.warning(f"Could not process backup file {backup_file}: {e}")
                    
            # Sort by modification time (oldest first)
            backup_files.sort(key=lambda x: x[1])
            
            # Remove files older than retention period
            cutoff_date = datetime.now() - timedelta(days=BACKUP_RETENTION_DAYS)
            removed_count = 0
            
            for backup_file, mod_time in backup_files:
                if mod_time < cutoff_date:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed old settings backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing old backup {backup_file}: {e}")
            
            # Also enforce maximum backup count
            if len(backup_files) > MAX_BACKUPS_PER_TYPE:
                excess_files = backup_files[:len(backup_files) - MAX_BACKUPS_PER_TYPE]
                for backup_file, _ in excess_files:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed excess settings backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing excess backup {backup_file}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleanup completed: {removed_count} old settings backups removed")
                
            return removed_count
            
        except Exception as e:
            logger.error(f"Error during settings backup cleanup: {e}")
            return 0

    def cleanup_old_certificate_backups(self):
        """Remove old certificate backups based on retention policy"""
        try:
            cert_backup_dir = self.backup_dir / "certificates"
            if not cert_backup_dir.exists():
                return 0
                
            backup_files = []
            for backup_file in cert_backup_dir.glob("certificates_*.zip"):
                try:
                    stat = backup_file.stat()
                    backup_files.append((backup_file, datetime.fromtimestamp(stat.st_mtime)))
                except Exception as e:
                    logger.warning(f"Could not process backup file {backup_file}: {e}")
                    
            # Sort by modification time (oldest first)
            backup_files.sort(key=lambda x: x[1])
            
            # Remove files older than retention period
            cutoff_date = datetime.now() - timedelta(days=BACKUP_RETENTION_DAYS)
            removed_count = 0
            
            for backup_file, mod_time in backup_files:
                if mod_time < cutoff_date:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed old certificate backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing old backup {backup_file}: {e}")
                        
            # Also enforce maximum backup count
            if len(backup_files) > MAX_BACKUPS_PER_TYPE:
                excess_files = backup_files[:len(backup_files) - MAX_BACKUPS_PER_TYPE]
                for backup_file, _ in excess_files:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed excess certificate backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing excess backup {backup_file}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleanup completed: {removed_count} old certificate backups removed")
                
            return removed_count
            
        except Exception as e:
            logger.error(f"Error during certificate backup cleanup: {e}")
            return 0

    def list_backups(self):
        """List all available backups with metadata (supports both legacy and unified formats)"""
        try:
            backups = {
                "unified": [],      # New unified backups
                "settings": [],     # Legacy settings backups
                "certificates": []  # Legacy certificate backups
            }
            
            # List unified backups (new format)
            unified_backup_dir = self.backup_dir / "unified"
            if unified_backup_dir.exists():
                for backup_file in unified_backup_dir.glob("backup_*.zip"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read unified backup metadata
                        try:
                            with zipfile.ZipFile(backup_file, 'r') as zipf:
                                if "backup_metadata.json" in zipf.namelist():
                                    metadata_content = zipf.read("backup_metadata.json")
                                    zip_metadata = json.loads(metadata_content.decode('utf-8'))
                                    metadata.update(zip_metadata)
                                    metadata["type"] = "unified"
                        except Exception:
                            pass  # Skip if can't read ZIP metadata
                            
                        backups["unified"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process unified backup {backup_file}: {e}")
            
            # List legacy settings backups (for backward compatibility)
            settings_backup_dir = self.backup_dir / "settings"
            if settings_backup_dir.exists():
                for backup_file in settings_backup_dir.glob("settings_*.json"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read backup metadata
                        backup_data = self.safe_file_read(backup_file, is_json=True)
                        if backup_data and "metadata" in backup_data:
                            metadata.update(backup_data["metadata"])
                            metadata["type"] = "legacy_settings"
                            
                        backups["settings"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process settings backup {backup_file}: {e}")
            
            # List legacy certificate backups (for backward compatibility)
            cert_backup_dir = self.backup_dir / "certificates"
            if cert_backup_dir.exists():
                for backup_file in cert_backup_dir.glob("certificates_*.zip"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read ZIP metadata
                        try:
                            with zipfile.ZipFile(backup_file, 'r') as zipf:
                                if "backup_metadata.json" in zipf.namelist():
                                    metadata_content = zipf.read("backup_metadata.json")
                                    zip_metadata = json.loads(metadata_content.decode('utf-8'))
                                    metadata.update(zip_metadata)
                                    metadata["type"] = "legacy_certificates"
                        except Exception:
                            pass  # Skip if can't read ZIP metadata
                            
                        backups["certificates"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process certificate backup {backup_file}: {e}")
            
            return backups
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return {"unified": [], "settings": [], "certificates": []}

    def restore_unified_backup(self, backup_file_path):
        """Restore from a unified backup file (both settings and certificates)"""
        try:
            logger.info(f"Starting unified backup restore from: {backup_file_path}")
            backup_path = Path(backup_file_path)
            
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Ensure directories exist
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            restored_domains = []
            settings_data = None
            
            # Extract unified backup
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # First, restore settings
                if "settings.json" in zipf.namelist():
                    settings_content = zipf.read("settings.json")
                    settings_backup = json.loads(settings_content.decode('utf-8'))
                    
                    if "settings" in settings_backup:
                        settings_data = settings_backup["settings"]
                        settings_file = self.data_dir / "settings.json"
                        if self.safe_file_write(settings_file, settings_data, is_json=True):
                            logger.info("Settings restored from unified backup")
                        else:
                            logger.error("Failed to restore settings from unified backup")
                            return False
                
                # Then, restore certificates
                for file_info in zipf.infolist():
                    if file_info.filename.startswith("certificates/") and file_info.filename != "certificates/":
                        logger.info(f"Extracting certificate file: {file_info.filename}")
                        
                        # Extract to certificates directory
                        # Remove "certificates/" prefix from the path
                        relative_path = file_info.filename[12:]  # len("certificates/") = 12
                        target_path = self.cert_dir / relative_path
                        
                        # Ensure target directory exists
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Extract file using proper handling
                        try:
                            with zipf.open(file_info) as source, open(target_path, 'wb') as target:
                                target.write(source.read())
                        except Exception as e:
                            logger.error(f"Error extracting {file_info.filename}: {e}")
                            continue
                        
                        # Set appropriate permissions
                        if target_path.name == 'privkey.pem':
                            os.chmod(target_path, 0o600)
                        else:
                            os.chmod(target_path, 0o644)
                        
                        # Track restored domains
                        if '/' in relative_path:
                            domain = relative_path.split('/')[0]
                            if domain and domain not in restored_domains:
                                logger.info(f"Found domain in unified backup: {domain}")
                                restored_domains.append(domain)
            
            logger.info(f"Unified backup restored successfully from: {backup_path.name}")
            if restored_domains:
                logger.info(f"Restored {len(restored_domains)} domains: {', '.join(restored_domains)}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring unified backup: {e}")
            return False

    def restore_settings_backup(self, backup_file_path):
        """Restore settings from a backup file (handles both legacy and unified formats)"""
        try:
            backup_path = Path(backup_file_path)
            
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Check if this is a unified backup
            if backup_path.name.startswith("backup_") and backup_path.suffix == ".zip":
                logger.info("Detected unified backup format, restoring both settings and certificates")
                return self.restore_unified_backup(backup_file_path)
            
            # Legacy settings backup (JSON file)
            logger.info("Restoring legacy settings backup")
            backup_data = self.safe_file_read(backup_path, is_json=True)
            if not backup_data:
                logger.error(f"Failed to read backup file: {backup_path}")
                return False
            
            # Extract settings from backup structure
            if "settings" in backup_data:
                settings_data = backup_data["settings"]
            else:
                # Direct settings file (legacy format)
                settings_data = backup_data
            
            # Write restored settings to main settings file
            settings_file = self.data_dir / "settings.json"
            if self.safe_file_write(settings_file, settings_data, is_json=True):
                logger.info(f"Settings restored successfully from: {backup_path.name}")
                return True
            else:
                logger.error(f"Failed to write restored settings to: {settings_file}")
                return False
                
        except Exception as e:
            logger.error(f"Error restoring settings backup: {e}")
            return False

    def restore_certificates_backup(self, backup_file_path):
        """Restore certificates from a backup file (handles both legacy and unified formats)"""
        try:
            logger.info(f"Starting certificate restore from: {backup_file_path}")
            backup_path = Path(backup_file_path)
            
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Check if this is a unified backup
            if backup_path.name.startswith("backup_") and backup_path.suffix == ".zip":
                logger.info("Detected unified backup format, restoring both settings and certificates")
                return self.restore_unified_backup(backup_file_path)
            
            # Legacy certificate backup (ZIP file)
            logger.info("Restoring legacy certificate backup")
            
            # Ensure certificates directory exists
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Track restored domains for settings update
            restored_domains = []
            
            # Extract ZIP file
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # Get list of files to extract (exclude metadata)
                files_to_extract = [f for f in zipf.namelist() if f != "backup_metadata.json"]
                
                # Extract all certificate files
                for file_info in zipf.infolist():
                    if file_info.filename != "backup_metadata.json":
                        logger.info(f"Extracting file: {file_info.filename}")
                        # Ensure target directory exists
                        target_path = self.cert_dir / file_info.filename
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Extract file
                        zipf.extract(file_info, self.cert_dir)
                        
                        # Track domains that have been restored
                        if '/' in file_info.filename:
                            domain = file_info.filename.split('/')[0]
                            if domain and domain not in restored_domains:
                                logger.info(f"Found domain in backup: {domain}")
                                restored_domains.append(domain)
            
            # Update settings with restored domains
            if restored_domains:
                logger.info(f"Found {len(restored_domains)} domains to potentially add to settings: {restored_domains}")
                self._update_settings_with_restored_domains(restored_domains)
            else:
                logger.info("No domains found in certificate backup to add to settings")
            
            logger.info(f"Certificates restored successfully from: {backup_path.name}")
            if restored_domains:
                logger.info(f"Added {len(restored_domains)} restored domains to settings: {', '.join(restored_domains)}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring certificates backup: {e}")
            return False

    def _update_settings_with_restored_domains(self, restored_domains):
        """Update settings file with restored certificate domains"""
        try:
            logger.info(f"Starting to update settings with restored domains: {restored_domains}")
            settings_file = self.data_dir / "settings.json"
            
            # Load current settings
            current_settings = self.safe_file_read(settings_file, is_json=True, default={})
            if not current_settings:
                current_settings = {}
            
            logger.info(f"Loaded current settings, found {len(current_settings.get('domains', []))} existing domains")
            
            # Ensure domains array exists
            if 'domains' not in current_settings:
                current_settings['domains'] = []
            
            # Get existing domains
            existing_domains = set()
            for domain_entry in current_settings['domains']:
                if isinstance(domain_entry, str):
                    existing_domains.add(domain_entry)
                elif isinstance(domain_entry, dict) and 'domain' in domain_entry:
                    existing_domains.add(domain_entry['domain'])
            
            # Add new domains that have valid certificates
            added_count = 0
            for domain in restored_domains:
                if domain in existing_domains:
                    continue
                
                # Check if the domain has valid certificate files
                domain_path = self.cert_dir / domain
                if (domain_path.exists() and 
                    (domain_path / "cert.pem").exists() and 
                    (domain_path / "privkey.pem").exists()):
                    
                    # Try to read DNS provider from metadata
                    metadata_file = domain_path / "metadata.json"
                    dns_provider = None
                    account_id = None
                    
                    if metadata_file.exists():
                        try:
                            metadata = self.safe_file_read(metadata_file, is_json=True, default={})
                            dns_provider = metadata.get('dns_provider')
                            account_id = metadata.get('account_id')
                        except Exception as e:
                            logger.warning(f"Could not read metadata for {domain}: {e}")
                    
                    # Create domain entry
                    if dns_provider and account_id:
                        # Use metadata information
                        domain_entry = {
                            "domain": domain,
                            "dns_provider": dns_provider,
                            "account_id": account_id
                        }
                    elif dns_provider:
                        # Use DNS provider but no account
                        domain_entry = {
                            "domain": domain,
                            "dns_provider": dns_provider
                        }
                    else:
                        # Fallback to default DNS provider from settings
                        default_dns_provider = current_settings.get('dns_provider', 'cloudflare')
                        domain_entry = {
                            "domain": domain,
                            "dns_provider": default_dns_provider
                        }
                    
                    current_settings['domains'].append(domain_entry)
                    added_count += 1
                    logger.info(f"Added restored domain to settings: {domain} (DNS: {domain_entry.get('dns_provider', 'unknown')})")
            
            # Save updated settings
            if added_count > 0:
                if self.safe_file_write(settings_file, current_settings, is_json=True):
                    logger.info(f"Settings updated with {added_count} restored certificate domains")
                else:
                    logger.error("Failed to save updated settings after certificate restore")
            else:
                logger.info("No new domains to add to settings (all restored domains already configured)")
                
        except Exception as e:
            logger.error(f"Error updating settings with restored domains: {e}")
